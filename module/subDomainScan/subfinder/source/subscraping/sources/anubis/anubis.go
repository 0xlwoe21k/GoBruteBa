// Package anubis logic
package anubis

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"

	jsoniter "github.com/json-iterator/go"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain))
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var subdomains []string
		err = jsoniter.NewDecoder(resp.Body).Decode(&subdomains)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			resp.Body.Close()
			return
		}

		resp.Body.Close()

		for _, record := range subdomains {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: record}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "anubis"
}
