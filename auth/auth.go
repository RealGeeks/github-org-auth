// Package auth allow go web apps to authenticate users using github and ensure
// they belong to a specific Team inside an Organization
package auth

import (
	"encoding/json"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// Config describes the required Github Organization and Team users are required
// to belong to in order to authenticate. And also has some required OAuth2 stuff.
type Config struct {
	Organization string // Organization name
	Team         string // Team inside Organization
	ClientID     string // OAuth2 application client id
	ClientSecret string // OAuth2 application client secret
	cfg          *oauth2.Config
}

// User returned by CheckPermission()
type User struct {
	Login  string `json:"login"`      // github login
	Name   string `json:"name"`       // github full name
	Avatar string `json:"avatar_url"` // github profile image
}

// AuthCodeURL returns the URL to redirect to so users can go to github
// enter their credentials and allow access
//
// They will return to the callback url. You need to create a callback url
// and call CheckPermission()
func (c *Config) AuthCodeURL(state string) string {
	if c.cfg == nil {
		c.cfg = &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       []string{"user:email", "read:org"},
			Endpoint:     github.Endpoint,
		}
	}

	return c.cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)
}

// team holds all information we need from each team a user belongs
// to in order to verify if they belong to the Team/Organization we
// want
type team struct {
	Name         string `json:"name"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

// CheckPermission must be called by your callback url with the OAuth2 authorization
// code given as GET parameter
//
// On success ok will be true and User will have some basic user details
//
// If the user doesn't belong to the desired Orgazation/Team, return false, user
// will still be a valid object and err will be nil
//
// If an error happens and we can't verify, ok will be false, user will be nil
// and err will be set
func (c *Config) CheckPermission(code string) (ok bool, user *User, err error) {
	if c.cfg == nil {
		c.cfg = &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       []string{"user:email", "read:org"},
			Endpoint:     github.Endpoint,
		}
	}

	// exchange oauth2 authorization code (retrieved from the callback url)
	// by an access token

	token, err := c.cfg.Exchange(oauth2.NoContext, code)
	if err != nil {
		return false, nil, err
	}

	// create a http client authorized to make requests to github api
	// using an access token

	client := c.cfg.Client(oauth2.NoContext, token)

	// get a list of all teams the current user belongs to

	var teams []team
	resp, err := client.Get("https://api.github.com/user/teams")
	if err != nil {
		return false, nil, err
	}
	if err := json.NewDecoder(resp.Body).Decode(&teams); err != nil {
		return false, nil, err
	}
	resp.Body.Close()

	// get user details

	user = new(User)
	resp, err = client.Get("https://api.github.com/user")
	if err != nil {
		return false, nil, err
	}
	if err := json.NewDecoder(resp.Body).Decode(user); err != nil {
		return false, nil, err
	}
	resp.Body.Close()

	// check if user belongs to team

	for _, t := range teams {
		if t.Name == c.Team && t.Organization.Login == c.Organization {
			return true, user, nil
		}
	}

	return false, user, nil

}
