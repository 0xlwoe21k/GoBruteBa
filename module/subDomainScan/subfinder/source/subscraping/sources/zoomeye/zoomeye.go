// Package zoomeye logic
package zoomeye

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// zoomAuth holds the ZoomEye credentials
type zoomAuth struct {
	User string `json:"username"`
	Pass string `json:"password"`
}

type loginResp struct {
	JWT string `json:"access_token"`
}

// search results
type zoomeyeResults struct {
	Matches []struct {
		Site    string   `json:"site"`
		Domains []string `json:"domains"`
	} `json:"matches"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.ZoomEyeUsername == "" || session.Keys.ZoomEyePassword == "" {
			return
		}

		jwt, err := doLogin(ctx, session)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			return
		}
		// check if jwt is null
		if jwt == "" {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: errors.New("could not log into zoomeye")}
			return
		}

		headers := map[string]string{
			"Authorization": fmt.Sprintf("JWT %s", jwt),
			"Accept":        "application/json",
			"Content-Type":  "application/json",
		}
		for currentPage := 0; currentPage <= 100; currentPage++ {
			api := fmt.Sprintf("https://api.zoomeye.org/web/search?query=hostname:%s&page=%d", domain, currentPage)
			resp, err := session.Get(ctx, api, "", headers)
			isForbidden := resp != nil && resp.StatusCode == http.StatusForbidden
			if err != nil {
				if !isForbidden && currentPage == 0 {
					results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
					session.DiscardHTTPResponse(resp)
				}
				return
			}

			var res zoomeyeResults
			err = json.NewDecoder(resp.Body).Decode(&res)
			if err != nil {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
				resp.Body.Close()
				return
			}
			resp.Body.Close()

			for _, r := range res.Matches {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: r.Site}
				for _, domain := range r.Domains {
					results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: domain}
				}
			}
			currentPage++
		}
	}()

	return results
}

// doLogin performs authentication on the ZoomEye API
func doLogin(ctx context.Context, session *subscraping2.Session) (string, error) {
	creds := &zoomAuth{
		User: session.Keys.ZoomEyeUsername,
		Pass: session.Keys.ZoomEyePassword,
	}
	body, err := json.Marshal(&creds)
	if err != nil {
		return "", err
	}
	resp, err := session.SimplePost(ctx, "https://api.zoomeye.org/user/login", "application/json", bytes.NewBuffer(body))
	if err != nil {
		session.DiscardHTTPResponse(resp)
		return "", err
	}

	defer resp.Body.Close()

	var login loginResp
	err = json.NewDecoder(resp.Body).Decode(&login)
	if err != nil {
		return "", err
	}
	return login.JWT, nil
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "zoomeye"
}
