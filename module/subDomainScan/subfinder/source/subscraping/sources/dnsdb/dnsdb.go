// Package dnsdb logic
package dnsdb

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"

	jsoniter "github.com/json-iterator/go"
)

type dnsdbResponse struct {
	Name string `json:"rrname"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.DNSDB == "" {
			return
		}

		headers := map[string]string{
			"X-API-KEY":    session.Keys.DNSDB,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		resp, err := session.Get(ctx, fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s?limit=1000000000000", domain), "", headers)
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
			var response dnsdbResponse
			err = jsoniter.NewDecoder(bytes.NewBufferString(line)).Decode(&response)
			if err != nil {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
				return
			}
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: strings.TrimSuffix(response.Name, ".")}
		}
		resp.Body.Close()
	}()
	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "DNSDB"
}
