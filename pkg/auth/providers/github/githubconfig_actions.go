package github

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"
	"github.com/rancher/norman/httperror"
	"github.com/rancher/norman/types"
	"github.com/rancher/norman/types/convert"
	v32 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
)

func (g *Provider) formatter(apiContext *types.APIContext, resource *types.RawResource) {
	common.AddCommonActions(apiContext, resource)
	resource.AddAction(apiContext, "configureTest")
	resource.AddAction(apiContext, "testAndApply")
}

func (g *Provider) actionHandler(actionName string, action *types.Action, request *types.APIContext) error {
	// TODO: How to get the Name here?
	handled, err := common.HandleCommonAction(actionName, action, request, DefaultName, g.authConfigs)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}

	switch actionName {
	case "configureTest":
		return g.configureTest(request)
	case "testAndApply":
		return g.testAndApply(request)
	default:
		return httperror.NewAPIError(httperror.ActionNotAvailable, "")
	}
}

func (g *Provider) configureTest(request *types.APIContext) error {
	githubConfig := &v32.GithubConfig{}
	if err := json.NewDecoder(request.Request.Body).Decode(githubConfig); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}
	redirectURL := formGithubRedirectURL(githubConfig)

	data := map[string]any{
		"redirectUrl": redirectURL,
		"type":        "githubConfigTestOutput",
	}

	request.WriteResponse(http.StatusOK, data)
	return nil
}

func formGithubRedirectURL(githubConfig *v32.GithubConfig) string {
	return githubRedirectURL(githubConfig.Hostname, githubConfig.ClientID, githubConfig.TLS)
}

func formGithubRedirectURLFromMap(config map[string]any) string {
	hostname, _ := config[client.GithubConfigFieldHostname].(string)
	clientID, _ := config[client.GithubConfigFieldClientID].(string)
	tls, _ := config[client.GithubConfigFieldTLS].(bool)

	requestHostname := convert.ToString(config[".host"])
	clientIDs := convert.ToMapInterface(config["hostnameToClientId"])
	if otherID, ok := clientIDs[requestHostname]; ok {
		clientID = convert.ToString(otherID)
	}
	return githubRedirectURL(hostname, clientID, tls)
}

func githubRedirectURL(hostname, clientID string, tls bool) string {
	redirect := ""
	if hostname != "" {
		scheme := "http://"
		if tls {
			scheme = "https://"
		}
		redirect = scheme + hostname
	} else {
		redirect = githubDefaultHostName
	}
	redirect = redirect + "/login/oauth/authorize?client_id=" + clientID
	return redirect
}

// This describes what the front-end submits.
// GithubConfigApplyInput is not what we receive in the request.
type githubApplyInput struct {
	Config struct {
		Hostname     string `json:"hostname"`
		ID           string `json:"id"`
		Name         string `json:"name"`
		TLS          bool   `json:"tls"`
		ClientSecret string `json:"clientSecret"`
		ClientID     string `json:"clientId"`
	} `json:"githubConfig"`
	Code    string `json:"code,omitempty"`
	Enabled bool   `json:"enabled,omitempty"`
}

func inputToGitHubConfig(in githubApplyInput) v32.GithubConfig {
	return v32.GithubConfig{
		AuthConfig: v32.AuthConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name: in.Config.Name,
			},
		},
		TLS:          in.Config.TLS,
		ClientSecret: in.Config.ClientSecret,
		ClientID:     in.Config.ClientID,
	}
}

func (g *Provider) testAndApply(request *types.APIContext) error {
	// TODO: Why does the front-end not send the correct struct?
	githubConfigApplyInput := githubApplyInput{}
	if err := json.NewDecoder(request.Request.Body).Decode(&githubConfigApplyInput); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}

	githubLogin := &v32.GithubLogin{
		Code: githubConfigApplyInput.Code,
	}

	githubConfig := inputToGitHubConfig(githubConfigApplyInput)
	if githubConfig.ClientSecret != "" {
		value, err := common.ReadFromSecret(g.secrets, githubConfig.ClientSecret,
			strings.ToLower(client.GithubConfigFieldClientSecret))
		if err != nil {
			return err
		}
		githubConfig.ClientSecret = value
	}

	// Call provider to testLogin
	userPrincipal, groupPrincipals, providerInfo, err := g.LoginUser("", githubLogin, &githubConfig, true)
	if err != nil {
		if httperror.IsAPIError(err) {
			return err
		}
		return errors.Wrap(err, "server error while authenticating")
	}

	// if this works, save githubConfig CR adding enabled flag
	user, err := g.userMGR.SetPrincipalOnCurrentUser(request.Request, userPrincipal)
	if err != nil {
		return err
	}

	githubConfig.Enabled = githubConfigApplyInput.Enabled
	err = g.saveGithubConfig(&githubConfig)
	if err != nil {
		return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Failed to save github config: %v", err))
	}

	userExtraInfo := g.GetUserExtraAttributes(userPrincipal)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		return g.userMGR.UserAttributeCreateOrUpdate(user.Name, userPrincipal.Provider, groupPrincipals, userExtraInfo)
	}); err != nil {
		return httperror.NewAPIError(httperror.ServerError, fmt.Sprintf("Failed to create or update userAttribute: %v", err))
	}

	return g.tokenMGR.CreateTokenAndSetCookie(user.Name, userPrincipal, groupPrincipals, providerInfo, 0, "Token via Github Configuration", request)
}
