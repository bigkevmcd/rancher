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
	apiv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/auth/providers/common"
	client "github.com/rancher/rancher/pkg/client/generated/management/v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/util/retry"
)

func (g *Provider) formatter(apiContext *types.APIContext, resource *types.RawResource) {
	common.AddCommonActions(apiContext, resource)
	resource.AddAction(apiContext, "configureTest")
	resource.AddAction(apiContext, "testAndApply")
}

func (g *Provider) actionHandler(actionName string, action *types.Action, request *types.APIContext) error {
	handled, err := common.HandleCommonAction(actionName, action, request, Name, g.authConfigs)
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
	githubConfig := apiv3.GithubConfig{}
	if err := json.NewDecoder(request.Request.Body).Decode(&githubConfig); err != nil {
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

func (g *Provider) testAndApply(request *types.APIContext) error {
	githubConfigApplyInput := &apiv3.GithubConfigApplyInput{}

	if err := json.NewDecoder(request.Request.Body).Decode(githubConfigApplyInput); err != nil {
		return httperror.NewAPIError(httperror.InvalidBodyContent,
			fmt.Sprintf("Failed to parse body: %v", err))
	}

	// Create an AuthConfig from the input
	authConfig := &apiv3.AuthConfig{
		Spec: apiv3.AuthConfigSpec{
			Github: &apiv3.GithubConfig{
				Hostname: githubConfigApplyInput.GithubConfig.Hostname,
				// TODO: Investigate why this is not defaulting to true
				TLS:                 true,
				ClientID:            githubConfigApplyInput.GithubConfig.ClientID,
				AdditionalClientIDs: githubConfigApplyInput.GithubConfig.AdditionalClientIDs,
				HostnameToClientID:  githubConfigApplyInput.GithubConfig.HostnameToClientID,
			},
		},
		Enabled: githubConfigApplyInput.Enabled,
	}

	githubLogin := &apiv3.GithubLogin{
		Code: githubConfigApplyInput.Code,
	}

	// Call provider to testLogin
	userPrincipal, groupPrincipals, providerInfo, err := g.LoginUser(
		"", githubLogin, authConfig, true, githubConfigApplyInput.GithubConfig.ClientSecret)
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

	field := strings.ToLower(apiv3.GithubConfigFieldClientSecret)
	name, err := common.CreateOrUpdateSecrets(g.secrets, convert.ToString(githubConfigApplyInput.GithubConfig.ClientSecret), field, strings.ToLower(Name))
	if err != nil {
		// TODO: Improve this error
		return err
	}
	authConfig.Spec.Github.ClientSecretRef = secretRefFromName(name)
	authConfig.Enabled = githubConfigApplyInput.Enabled

	if err := g.saveGithubConfig(authConfig); err != nil {
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

func secretRefFromName(s string) *apiv3.SecretReference {
	parts := strings.SplitN(s, ":", 2)

	return &apiv3.SecretReference{
		Namespace: parts[0],
		Name:      parts[1],
	}
}

func formGithubRedirectURL(gc apiv3.GithubConfig) string {
	// Default tls to true because it's not being defaulted.
	return githubRedirectURL(gc.Hostname, gc.ClientID, true)
}

func formGithubRedirectURLFromMap(config map[string]any) string {
	hostname, _, _ := unstructured.NestedString(config, "spec", "github", client.GithubConfigFieldHostname)
	clientID, _, _ := unstructured.NestedString(config, "spec", "github", client.GithubConfigFieldClientID)
	tls, _, _ := unstructured.NestedBool(config, "spec", "github", client.GithubConfigFieldTLS)

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
