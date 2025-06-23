package githubapp

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v72/github"
	"golang.org/x/oauth2"
)

// GitHubObject represents the basic values that all GitHub resources have.
type GitHubObject struct {
	Name      string
	Login     string
	AvatarURL string
	ID        int
}

// Org represents an Organization.
type Org struct {
	GitHubObject

	// Teams is a mapping "slug" -> OrgTeam
	Teams map[string]OrgTeam
}

// OrgTeam represents a team within an Organization.
type OrgTeam struct {
	GitHubObject

	OrgLogin string
	HTMLURL  string
	Slug     string
	Members  []string
}

// Add a team to this Organization.
func (o *Org) AddTeam(id int, slug, htmlURL string) {
	_, ok := o.Teams[slug]
	if ok {
		return
	}
	o.Teams[slug] = OrgTeam{GitHubObject: GitHubObject{ID: id}, Members: []string{}, Slug: slug, HTMLURL: htmlURL}
}

// Add a member to a team within this Organization.
func (o *Org) AddTeamMember(teamName, name string) {
	team, ok := o.Teams[teamName]
	if !ok {
		return
	}
	team.Members = append(team.Members, name)
	o.Teams[teamName] = team
}

// Aggregates the data for members.
type GitHubAppData struct {
	// Orgs is a mapping "name" -> *Org
	Orgs map[string]*Org
	// Members is a mapping "membername" -> org -> teams (slice of strings)
	Members map[string]map[string][]string
}

// OrgsForUser returns a set of Accounts derived from the Organizations the
// provided username is a member of.
func (g *GitHubAppData) OrgsForUser(username string) []Account {
	var accounts []Account

	for orgName := range g.Members[username] {
		org := g.Orgs[orgName]
		accounts = append(accounts, Account{Name: org.Name, Login: org.Login, AvatarURL: org.AvatarURL, ID: org.ID})
	}

	return accounts
}

// ListOrgs returns a set of Accounts derived from all Organizations queried
// with the GitHub App credentials.
func (g *GitHubAppData) ListOrgs() []Account {
	var accounts []Account

	for _, org := range g.Orgs {
		accounts = append(accounts, Account{Name: org.Name, Login: org.Login, AvatarURL: org.AvatarURL, ID: org.ID})
	}

	return accounts
}

// TeamsForUser returns a set of Accounts derived from the Teams the provided
// username is a member of.
func (g *GitHubAppData) TeamsForUser(username string) []Account {
	var accounts []Account

	for orgName := range g.Members[username] {
		org := g.Orgs[orgName]
		for teamName, team := range org.Teams {
			accounts = append(accounts, Account{Name: teamName, Login: team.Slug, AvatarURL: org.AvatarURL, ID: team.ID, HTMLURL: team.HTMLURL})
		}
	}

	return accounts
}

// ListTeams returns a set of Accounts derived from all Organizations queried
// with the GitHub App credentials.
func (g *GitHubAppData) ListTeams() []Account {
	var accounts []Account
	for _, org := range g.Orgs {
		for teamName, team := range org.Teams {
			accounts = append(accounts, Account{Name: teamName, Login: team.Slug, AvatarURL: org.AvatarURL, ID: team.ID, HTMLURL: team.HTMLURL})
		}
	}

	return accounts
}

func (g *GitHubAppData) AddOrg(id int, login, name, avatarURL string) {
	if _, ok := g.Orgs[login]; ok {
		return
	}
	g.Orgs[login] = &Org{GitHubObject: GitHubObject{Login: login, ID: id, Name: name, AvatarURL: avatarURL}, Teams: map[string]OrgTeam{}}
}

func (g *GitHubAppData) AddTeamToOrg(org string, id int, slug, htmlURL string) {
	o, ok := g.Orgs[org]
	if !ok {
		return
	}

	o.AddTeam(id, slug, htmlURL)
}

func (g *GitHubAppData) AddMemberToTeamInOrg(org, team, member string) {
	o, ok := g.Orgs[org]
	if !ok {
		return
	}
	o.AddTeamMember(team, member)

	m, ok := g.Members[member]
	if !ok {
		m = map[string][]string{}
	}

	orgTeams, ok := m[org]
	if !ok {
		orgTeams = []string{}
	}
	orgTeams = append(orgTeams, team)
	m[org] = orgTeams

	g.Members[member] = m
}

func newGitHubAppData() *GitHubAppData {
	return &GitHubAppData{
		Orgs:    map[string]*Org{},
		Members: map[string]map[string][]string{},
	}
}

func newGitHubClient(c *http.Client, endpoint string) (*github.Client, error) {
	client := github.NewClient(c)
	if endpoint != "" {
		c, err := client.WithEnterpriseURLs(endpoint, endpoint)
		if err != nil {
			// TODO: Improve error message
			return nil, err
		}
		client = c
	}

	return client, nil
}

// Create an installation specific token and return a client configured to use the
// token.
func newInstallationClient(ctx context.Context, client *github.Client, installationID int64, endpoint string) (*github.Client, error) {
	token, _, err := client.Apps.CreateInstallationToken(ctx, installationID, nil)
	if err != nil {
		return nil, fmt.Errorf("cannot create installation token: %w", err)
	}

	return newGitHubClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.GetToken()},
	)), endpoint)
}

func newClientForApp(ctx context.Context, appID int64, privateKey []byte, endpoint string) (*github.Client, error) {
	// Create the JWT token signed by the GitHub App, and a GitHub client using it.
	jwtToken := createJWT(appID, privateKey)

	return newGitHubClient(oauth2.NewClient(ctx, oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: jwtToken},
	)), endpoint)
}

func createJWT(appID int64, privateKey []byte) string {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
	}

	iss := time.Now().Add(-30 * time.Second).Truncate(time.Second)
	claims := &jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(iss),
		ExpiresAt: jwt.NewNumericDate(iss.Add(2 * time.Minute)),
		Issuer:    fmt.Sprintf("%v", appID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	ss, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("failed to sign JWT: %v", err)
	}

	return ss
}

func gatherDataForInstallation(ctx context.Context, data *GitHubAppData, installationClient *github.Client, organization int64) error {
	org, _, err := installationClient.Organizations.GetByID(ctx, organization)
	if err != nil {
		return fmt.Errorf("getting GitHub organization %v: %w", organization, err)
	}
	optionalString := func(s *string) string {
		if s == nil {
			return ""
		}

		return *s
	}

	data.AddOrg(int(*org.ID), *org.Login, optionalString(org.Name), *org.AvatarURL)

	opts := &github.ListOptions{PerPage: 100}
	var allTeams []*github.Team
	for {
		teams, resp, err := installationClient.Teams.ListTeams(ctx, *org.Login, opts)
		if err != nil {
			return fmt.Errorf("listing teams in GitHub organization %v: %w", *org.Login, err)
		}
		allTeams = append(allTeams, teams...)
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	for _, team := range allTeams {
		data.AddTeamToOrg(*org.Login, int(*team.ID), *team.Slug, *team.HTMLURL)

		membersOpts := &github.TeamListTeamMembersOptions{ListOptions: github.ListOptions{PerPage: 100}}
		var allMembers []*github.User
		for {
			members, resp, err := installationClient.Teams.ListTeamMembersByID(ctx, *org.ID, *team.ID, membersOpts)
			if err != nil {
				return fmt.Errorf("listing team members: %w", err)
			}
			allMembers = append(allMembers, members...)
			if resp.NextPage == 0 {
				break
			}
			membersOpts.Page = resp.NextPage
		}

		for _, member := range allMembers {
			data.AddMemberToTeamInOrg(*org.Login, *team.Slug, *member.Login)
		}
	}

	return nil
}

// Extract the team memberships of organisations that the App has been installed
// into.
//
// If the installationID is zero (0) all installations for the app will be
// queried.
func teamDataFromApp(ctx context.Context, appID int64, privateKey []byte, installationID int64, endpoint string) (*GitHubAppData, error) {
	data := newGitHubAppData()
	itr, err := ghinstallation.NewAppsTransport(http.DefaultTransport, appID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating transport to access GitHub: %w", err)
	}

	client := github.NewClient(
		&http.Client{
			Transport: itr,
			Timeout:   time.Second * 30,
		},
	)

	if endpoint != "" {
		c, err := client.WithEnterpriseURLs(endpoint, endpoint)
		if err != nil {
			return nil, fmt.Errorf("creating a github client: %w", err)
		}
		client = c
	}

	appClient, err := newClientForApp(ctx, appID, privateKey, endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating a client for app %v: %w", appID, err)
	}

	if installationID > 0 {
		installation, _, err := client.Apps.GetInstallation(ctx, installationID)
		if err != nil {
			log.Fatalf("failed to get installation %v: %s", installationID, err)
		}
		installationClient, err := newInstallationClient(ctx, appClient, installationID, endpoint)
		if err != nil {
			return nil, err
		}
		if err := gatherDataForInstallation(ctx, data, installationClient, *installation.TargetID); err != nil {
			return nil, err
		}
	} else {
		installations, _, err := client.Apps.ListInstallations(ctx, &github.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("listing app installations: %w", err)
		}

		for _, i := range installations {
			installationClient, err := newInstallationClient(ctx, appClient, *i.ID, endpoint)
			if err != nil {
				return nil, err
			}
			if err := gatherDataForInstallation(ctx, data, installationClient, *i.TargetID); err != nil {
				return nil, err
			}
		}
	}

	return data, nil
}
