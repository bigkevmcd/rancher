package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	cattlev3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	"github.com/tomnomnom/linkheader"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// githubAppClient implements client for GitHub using a GitHub App.
type githubAppClient struct {
	httpClient *http.Client
}

func (g *githubAppClient) getOAuthAccessToken(code string, config *mgmtv3.GithubAppConfig) *oauth2.Config {
	endpoint := github.Endpoint
	if config.Hostname != "" {
		endpoint = oauth2.Endpoint{
			AuthURL:  "https://" + config.Hostname + "/login/oauth/authorize",
			TokenURL: "https://" + config.Hostname + "/login/oauth/access_token",
		}
	}

	return &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint:     endpoint,
	}
}

func (g *githubAppClient) getAccessToken(code string, config *mgmtv3.GithubAppConfig) (string, error) {
	form := url.Values{}
	form.Add("client_id", config.ClientID)
	form.Add("client_secret", config.ClientSecret)
	form.Add("code", code)

	url := getAPIURL("TOKEN", config)

	b, err := g.postToGithub(url, form)
	if err != nil {
		return "", fmt.Errorf("github getAccessToken: POST url %v received error from github, err: %v", url, err)
	}

	// Decode the response
	var respMap map[string]interface{}

	if err := json.Unmarshal(b, &respMap); err != nil {
		return "", fmt.Errorf("github getAccessToken: received error unmarshalling response body, err: %v", err)
	}

	if respMap["error"] != nil {
		desc := respMap["error_description"]
		return "", fmt.Errorf("github getAccessToken: received error from github %v, description from github %v", respMap["error"], desc)
	}

	acessToken, ok := respMap["access_token"].(string)
	if !ok {
		return "", fmt.Errorf("github getAccessToken: received error reading accessToken from response %v", respMap)
	}
	return acessToken, nil
}

func (g *githubAppClient) getUser(githubAccessToken string, config *mgmtv3.GithubAppConfig) (Account, error) {
	url := getAPIURL("USER_INFO", config)
	b, _, err := g.getFromGithub(githubAccessToken, url)
	if err != nil {
		logrus.Errorf("Github getGithubUser: GET url %v received error from github, err: %v", url, err)
		return Account{}, err
	}
	var githubAcct Account

	if err := json.Unmarshal(b, &githubAcct); err != nil {
		logrus.Errorf("Github getGithubUser: error unmarshalling response, err: %v", err)
		return Account{}, err
	}

	return githubAcct, nil
}

// TODO: These two need to use the cache.
func (g *githubAppClient) getOrgsForUser(username string, config *mgmtv3.GithubAppConfig) ([]Account, error) {
	appID, err := strconv.ParseInt(config.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing AppID: %w", err)
	}

	var installationID int64
	if config.InstallationID != "" {
		parsed, err := strconv.ParseInt(config.InstallationID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing InstallationID: %w", err)
		}
		installationID = parsed
	}

	data, err := getDataForApp(context.Background(), appID, []byte(config.PrivateKey), installationID, getAPIURL("", config))
	if err != nil {
		return nil, err
	}

	return data.listOrgsForUser(username), nil
}

func (g *githubAppClient) getTeamsForUser(username string, config *mgmtv3.GithubAppConfig) ([]Account, error) {
	appID, err := strconv.ParseInt(config.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing AppID: %w", err)
	}

	var installationID int64
	if config.InstallationID != "" {
		parsed, err := strconv.ParseInt(config.InstallationID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing InstallationID: %w", err)
		}
		installationID = parsed
	}

	data, err := getDataForApp(context.Background(), appID, []byte(config.PrivateKey), installationID, getAPIURL("", config))
	if err != nil {
		return nil, err
	}

	return data.listTeamsForUser(username), nil
}

func (g *githubAppClient) searchUsers(searchTerm, searchType string, config *cattlev3.GithubAppConfig) ([]Account, error) {
	appID, err := strconv.ParseInt(config.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing AppID: %w", err)
	}

	var installationID int64
	if config.InstallationID != "" {
		parsed, err := strconv.ParseInt(config.InstallationID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing InstallationID: %w", err)
		}
		installationID = parsed
	}

	data, err := getDataForApp(context.Background(), appID, []byte(config.PrivateKey), installationID, getAPIURL("", config))
	if err != nil {
		return nil, err
	}

	searchResult := data.searchOrgs(searchTerm)
	searchResult = append(searchResult, data.searchMembers(searchTerm)...)
	return searchResult, nil
}

func (g *githubAppClient) searchTeams(searchTerm string, config *cattlev3.GithubAppConfig) ([]Account, error) {
	appID, err := strconv.ParseInt(config.AppID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing AppID: %w", err)
	}

	var installationID int64
	if config.InstallationID != "" {
		parsed, err := strconv.ParseInt(config.InstallationID, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing InstallationID: %w", err)
		}
		installationID = parsed
	}

	data, err := getDataForApp(context.Background(), appID, []byte(config.PrivateKey), installationID, getAPIURL("", config))
	if err != nil {
		return nil, err
	}

	return data.searchTeams(searchTerm), nil
}

func (g *githubAppClient) getTeamByID(id string, config *mgmtv3.GithubAppConfig) (Account, error) {
	return Account{}, errors.New("fail")
}

func (g *githubAppClient) getUserOrgByID(id string, config *mgmtv3.GithubAppConfig) (Account, error) {
	return Account{}, errors.New("fail")
}

func (g *githubAppClient) postToGithub(url string, form url.Values) ([]byte, error) {
	req, err := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	if err != nil {
		logrus.Error(err)
	}
	req.PostForm = form
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Accept", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("Received error from github: %v", err)
		return nil, err
	}

	defer resp.Body.Close()
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return nil, fmt.Errorf("request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}
	return io.ReadAll(resp.Body)
}

func (g *githubAppClient) getFromGithub(githubAccessToken string, url string) ([]byte, string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Add("Authorization", "token "+githubAccessToken)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-agent", "rancher/github-app-client")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		logrus.Errorf("Received error from github: %v", err)
		return nil, "", err
	}
	defer resp.Body.Close()
	// Check the status code
	switch resp.StatusCode {
	case 200:
	case 201:
	default:
		var body bytes.Buffer
		io.Copy(&body, resp.Body)
		return nil, "", fmt.Errorf("request failed, got status code: %d. Response: %s",
			resp.StatusCode, body.Bytes())
	}

	nextURL := g.nextGithubPage(resp)
	b, err := io.ReadAll(resp.Body)
	return b, nextURL, err
}

func getAPIURL(endpoint string, config *mgmtv3.GithubAppConfig) string {
	var hostName, apiEndpoint, toReturn string

	if config.Hostname != "" {
		scheme := "http://"
		if config.TLS {
			scheme = "https://"
		}
		hostName = scheme + config.Hostname
		if hostName == githubDefaultHostName {
			apiEndpoint = githubAPI
		} else {
			apiEndpoint = scheme + config.Hostname + gheAPI
		}
	} else {
		hostName = githubDefaultHostName
		apiEndpoint = githubAPI
	}

	switch endpoint {
	case "API":
		toReturn = apiEndpoint
	case "TOKEN":
		toReturn = hostName + "/login/oauth/access_token"
	case "USERS":
		toReturn = apiEndpoint + "/users/"
	case "ORGS":
		toReturn = apiEndpoint + "/orgs/"
	case "USER_INFO":
		toReturn = apiEndpoint + "/user"
	case "ORG_INFO":
		toReturn = apiEndpoint + "/user/orgs?per_page=1"
	case "USER_PICTURE":
		toReturn = "https://avatars.githubusercontent.com/u/" + endpoint + "?v=3&s=72"
	case "USER_SEARCH":
		toReturn = apiEndpoint + "/search/users?q="
	case "TEAM":
		toReturn = apiEndpoint + "/teams/"
	case "TEAMS":
		toReturn = apiEndpoint + "/user/teams?per_page=100"
	case "TEAM_PROFILE":
		toReturn = hostName + "/orgs/%s/teams/%s"
	case "ORG_TEAMS":
		toReturn = apiEndpoint + "/orgs/%s/teams?per_page=100"
	default:
		toReturn = apiEndpoint
	}

	return toReturn
}

func (g *githubAppClient) paginateGithub(githubAccessToken string, url string) ([][]byte, error) {
	var responses [][]byte
	var err error
	var response []byte
	nextURL := url
	for nextURL != "" {
		response, nextURL, err = g.getFromGithub(githubAccessToken, nextURL)
		if err != nil {
			return nil, err
		}
		responses = append(responses, response)
	}

	return responses, nil
}

func (g *githubAppClient) nextGithubPage(response *http.Response) string {
	header := response.Header.Get("link")

	if header != "" {
		links := linkheader.Parse(header)
		for _, link := range links {
			if link.Rel == "next" {
				return link.URL
			}
		}
	}

	return ""
}
