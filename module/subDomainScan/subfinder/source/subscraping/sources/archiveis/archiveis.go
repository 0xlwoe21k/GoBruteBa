// Package archiveis is a Archiveis Scraping Engine in Golang
package archiveis

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"
	"io/ioutil"
	"regexp"
)

type agent struct {
	Results chan subscraping2.Result
	Session *subscraping2.Session
}

var reNext = regexp.MustCompile("<a id=\"next\" style=\".*\" href=\"(.*)\">&rarr;</a>")

func (a *agent) enumerate(ctx context.Context, baseURL string) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := a.Session.SimpleGet(ctx, baseURL)
	if err != nil {
		a.Results <- subscraping2.Result{Source: "archiveis", Type: subscraping2.Error, Error: err}
		a.Session.DiscardHTTPResponse(resp)
		return
	}

	// Get the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		a.Results <- subscraping2.Result{Source: "archiveis", Type: subscraping2.Error, Error: err}
		resp.Body.Close()
		return
	}

	resp.Body.Close()

	src := string(body)
	for _, subdomain := range a.Session.Extractor.FindAllString(src, -1) {
		a.Results <- subscraping2.Result{Source: "archiveis", Type: subscraping2.Subdomain, Value: subdomain}
	}

	match1 := reNext.FindStringSubmatch(src)
	if len(match1) > 0 {
		a.enumerate(ctx, match1[1])
	}
}

// Source is the passive scraping agent
type Source struct{}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping2.Session) <-chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	a := agent{
		Session: session,
		Results: results,
	}

	go func() {
		a.enumerate(ctx, fmt.Sprintf("http://archive.is/*.%s", domain))
		close(a.Results)
	}()

	return a.Results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "archiveis"
}
