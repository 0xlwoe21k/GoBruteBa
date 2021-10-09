// Package threatbook logic
package threatbook

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"
	"strconv"

	jsoniter "github.com/json-iterator/go"
)

type threatBookResponse struct {
	ResponseCode int64  `json:"response_code"`
	VerboseMsg   string `json:"verbose_msg"`
	Data         struct {
		Domain     string `json:"domain"`
		SubDomains struct {
			Total string   `json:"total"`
			Data  []string `json:"data"`
		} `json:"sub_domains"`
	} `json:"data"`
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		defer close(results)

		if session.Keys.ThreatBook == "" {
			return
		}

		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://api.threatbook.cn/v3/domain/sub_domains?apikey=%s&resource=%s", session.Keys.ThreatBook, domain))
		if err != nil && resp == nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			session.DiscardHTTPResponse(resp)
			return
		}

		var response threatBookResponse
		err = jsoniter.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			resp.Body.Close()
			return
		}
		resp.Body.Close()

		if response.ResponseCode != 0 {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: fmt.Errorf("code %d, %s", response.ResponseCode, response.VerboseMsg)}
			return
		}

		total, err := strconv.ParseInt(response.Data.SubDomains.Total, 10, 64)
		if err != nil {
			results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Error, Error: err}
			return
		}

		if total > 0 {
			for _, subdomain := range response.Data.SubDomains.Data {
				results <- subscraping2.Result{Source: s.Name(), Type: subscraping2.Subdomain, Value: subdomain}
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "threatbook"
}
