// Package shodan logic
package shodan

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
)

// Source is the passive scraping agent
type Source struct{}

type dnsdbLookupResponse struct {
	Domain     string   `json:"domain"`
	Subdomains []string `json:"subdomains"`
	Result     int      `json:"result"`
	Error      string   `json:"error"`
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.Shodan == "" {
			return
		}

		searchURL := fmt.Sprintf("https://api.shodan.io/dns/domain/%s?key=%s", domain, session.Keys.Shodan)
		resp, err := session.SimpleGet(ctx, searchURL)
		if err != nil {
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		var response dnsdbLookupResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			return
		}

		if response.Error != "" {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: fmt.Errorf("%v", response.Error)}
			return
		}

		for _, data := range response.Subdomains {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: fmt.Sprintf("%s.%s", data, domain)}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "shodan"
}
