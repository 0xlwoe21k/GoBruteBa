// Package alienvault logic
package alienvault

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"encoding/json"
	"fmt"
)

type alienvaultResponse struct {
	Detail     string `json:"detail"`
	Error      string `json:"error"`
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain))
		if err != nil && resp == nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response alienvaultResponse
		// Get the response body and decode
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.Error != "" {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: fmt.Errorf("%s, %s", response.Detail, response.Error)}
			return
		}

		for _, record := range response.PassiveDNS {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: record.Hostname}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "alienvault"
}
