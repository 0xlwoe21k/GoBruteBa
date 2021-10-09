// Package passivetotal logic
package passivetotal

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"bytes"
	"context"
	"regexp"

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

		if session.Keys.PassiveTotalUsername == "" || session.Keys.PassiveTotalPassword == "" {
			return
		}

		// Create JSON Get body
		var request = []byte(`{"query":"` + domain + `"}`)

		resp, err := session.HTTPRequest(
			ctx,
			"GET",
			"https://api.passivetotal.org/v2/enrichment/subdomains",
			"",
			map[string]string{"Content-Type": "application/json"},
			bytes.NewBuffer(request),
			subscraping2.BasicAuth{Username: session.Keys.PassiveTotalUsername, Password: session.Keys.PassiveTotalPassword},
		)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var data response
		err = jsoniter.NewDecoder(resp.Body).Decode(&data)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		for _, subdomain := range data.Subdomains {
			// skip entries like xxx.xxx.xxx.xxx\032domain.tld
			if passiveTotalFilterRegex.MatchString(subdomain) {
				continue
			}
			finalSubdomain := subdomain + "." + domain
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: finalSubdomain}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "passivetotal"
}

var passiveTotalFilterRegex *regexp.Regexp = regexp.MustCompile(`^(?:\d{1,3}\.){3}\d{1,3}\\032`)
