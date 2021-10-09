// Package chaos logic
package chaos

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"

	"github.com/projectdiscovery/chaos-client/pkg/chaos"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.Chaos == "" {
			return
		}

		chaosClient := chaos.New(session.Keys.Chaos)
		for result := range chaosClient.GetSubdomains(&chaos.SubdomainsRequest{
			Domain: domain,
		}) {
			if result.Error != nil {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: result.Error}
				break
			}
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: fmt.Sprintf("%s.%s", result.Subdomain, domain)}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "chaos"
}
