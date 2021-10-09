// Package riddler logic
package riddler

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"bufio"
	"context"
	"fmt"
)

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://riddler.io/search?q=pld:%s&view_type=data_table", domain))
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			subdomain := session.Extractor.FindString(line)
			if subdomain != "" {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: subdomain}
			}
		}
		resp.Body.Close()
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "riddler"
}
