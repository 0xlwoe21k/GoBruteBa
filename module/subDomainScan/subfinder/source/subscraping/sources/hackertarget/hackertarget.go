// Package hackertarget logic
package hackertarget

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

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("http://api.hackertarget.com/hostsearch/?q=%s", domain))
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			match := session.Extractor.FindAllString(line, -1)
			for _, subdomain := range match {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}
