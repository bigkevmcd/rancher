package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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

	url := g.getURL("TOKEN", config)

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
	url := g.getURL("USER_INFO", config)
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

func (g *githubAppClient) getOrgs(config *mgmtv3.GithubAppConfig) ([]Account, error) {
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

	data, err := teamDataFromApp(context.Background(), appID, []byte(config.PrivateKey), installationID, g.getURL("", config))
	if err != nil {
		return nil, err
	}

	return data.ListOrgs(), nil
}

func (g *githubAppClient) getTeams(config *mgmtv3.GithubAppConfig) ([]Account, error) {
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

	data, err := teamDataFromApp(context.Background(), appID, []byte(config.PrivateKey), installationID, g.getURL("", config))
	if err != nil {
		return nil, err
	}

	return data.listTeams(), nil
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
	req.Header.Add("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36)")
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

func (g *githubAppClient) getURL(endpoint string, config *mgmtv3.GithubAppConfig) string {
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

// func (g *githubAppClient) getTeamInfo(b []byte, config *mgmtv3.GithubAppConfig) ([]Account, error) {
// 	var teams []Account
// 	var teamObjs []Team
// 	if err := json.Unmarshal(b, &teamObjs); err != nil {
// 		logrus.Errorf("Github getTeamInfo: received error unmarshalling team array, err: %v", err)
// 		return teams, err
// 	}

// 	url := g.getURL("TEAM_PROFILE", config)
// 	for _, team := range teamObjs {
// 		teamAcct := Account{}
// 		team.toGithubAccount(url, &teamAcct)
// 		teams = append(teams, teamAcct)
// 	}

// 	return teams, nil
// }

// func (g *githubAppClient) getTeamByID(id string, githubAccessToken string, config *mgmtv3.GithubAppConfig) (Account, error) {
// 	var teamAcct Account

// 	url := g.getURL("TEAM", config) + id
// 	b, _, err := g.getFromGithub(githubAccessToken, url)
// 	if err != nil {
// 		logrus.Errorf("Github getTeamByID: GET url %v received error from github, err: %v", url, err)
// 		return teamAcct, err
// 	}
// 	var teamObj Team
// 	if err := json.Unmarshal(b, &teamObj); err != nil {
// 		logrus.Errorf("Github getTeamByID: received error unmarshalling team array, err: %v", err)
// 		return teamAcct, err
// 	}
// 	url = g.getURL("TEAM_PROFILE", config)
// 	teamObj.toGithubAccount(url, &teamAcct)

// 	return teamAcct, nil
// }

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
