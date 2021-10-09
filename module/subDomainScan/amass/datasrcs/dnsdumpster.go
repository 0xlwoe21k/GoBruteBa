// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	amasshttp "github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
)

// DNSDumpster is the Service that handles access to the DNSDumpster data source.
type DNSDumpster struct {
	service.BaseService

	SourceType string
	sys        systems.System
}

// NewDNSDumpster returns he object initialized, but not yet started.
func NewDNSDumpster(sys systems.System) *DNSDumpster {
	d := &DNSDumpster{
		SourceType: requests.SCRAPE,
		sys:        sys,
	}

	d.BaseService = *service.NewBaseService(d, "DNSDumpster")
	return d
}

// Description implements the Service interface.
func (d *DNSDumpster) Description() string {
	return d.SourceType
}

// OnStart implements the Service interface.
func (d *DNSDumpster) OnStart() error {
	d.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (d *DNSDumpster) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		d.dnsRequest(ctx, req)
		d.CheckRateLimit()
	}
}

func (d *DNSDumpster) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", d.String(), req.Domain))

	u := "https://dnsdumpster.com/"
	page, err := amasshttp.RequestWebPage(ctx, u, nil, nil, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", d.String(), u, err))
		return
	}

	token := d.getCSRFToken(page)
	if token == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to obtain the CSRF token", d.String(), u))
		return
	}

	d.CheckRateLimit()
	page, err = d.postForm(ctx, token, req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", d.String(), u, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		genNewNameEvent(ctx, d.sys, d, amasshttp.CleanName(sd))
	}
}

func (d *DNSDumpster) getCSRFToken(page string) string {
	re := regexp.MustCompile(`<input type="hidden" name="csrfmiddlewaretoken" value="([a-zA-Z0-9]*)">`)

	if subs := re.FindStringSubmatch(page); len(subs) == 2 {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

func (d *DNSDumpster) postForm(ctx context.Context, token, domain string) (string, error) {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return "", fmt.Errorf("%s failed to obtain the EventBus from Context", d.String())
	}

	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://dnsdumpster.com/", strings.NewReader(params.Encode()))
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: Failed to setup the POST request: %v", d.String(), err))
		return "", err
	}
	// The CSRF token needs to be sent as a cookie
	cookie := &http.Cookie{
		Name:   "csrftoken",
		Domain: "dnsdumpster.com",
		Value:  token,
	}
	req.AddCookie(cookie)

	req.Header.Set("User-Agent", amasshttp.UserAgent)
	req.Header.Set("Accept", amasshttp.Accept)
	req.Header.Set("Accept-Language", amasshttp.AcceptLang)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://dnsdumpster.com")
	req.Header.Set("X-CSRF-Token", token)

	resp, err := amasshttp.DefaultClient.Do(req)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: The POST request failed: %v", d.String(), err))
		return "", err
	}
	defer resp.Body.Close()

	// Now, grab the entire page
	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("Failed to read response body: %v", err))
		return "", err
	}
	return string(in), nil
}
