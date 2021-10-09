// Package securitytrails logic
package securitytrails

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

type response struct {
	Subdomains []string `json:"subdomains"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.Securitytrails == "" {
			return
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain), "", map[string]string{"APIKEY": session.Keys.Securitytrails})
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var securityTrailsResponse response
		err = jsoniter.NewDecoder(resp.Body).Decode(&securityTrailsResponse)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, subdomain := range securityTrailsResponse.Subdomains {
			if strings.HasSuffix(subdomain, ".") {
				subdomain += domain
			} else {
				subdomain = subdomain + "." + domain
			}

			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: subdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "securitytrails"
}
