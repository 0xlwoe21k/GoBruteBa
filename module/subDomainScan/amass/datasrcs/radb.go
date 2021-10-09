// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/resolve"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
	"github.com/miekg/dns"
)

const (
	// radbWhoisURL is the URL for the RADb whois server.
	radbWhoisURL = "whois.radb.net"
)

// RADb is the Service that handles access to the RADb data source.
type RADb struct {
	service.BaseService

	SourceType string
	sys        systems.System
	addr       string
}

// NewRADb returns he object initialized, but not yet started.
func NewRADb(sys systems.System) *RADb {
	r := &RADb{
		SourceType: requests.API,
		sys:        sys,
	}

	r.BaseService = *service.NewBaseService(r, "RADb")
	return r
}

// Description implements the Service interface.
func (r *RADb) Description() string {
	return r.SourceType
}

// OnStart implements the Service interface.
func (r *RADb) OnStart() error {
	msg := resolve.QueryMsg(radbWhoisURL, dns.TypeA)
	if resp, err := r.sys.Pool().Query(context.TODO(),
		msg, resolve.PriorityCritical, resolve.RetryPolicy); err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			ip := ans[0].Data
			if ip != "" {
				r.addr = ip
			}
		}
	}

	r.SetRateLimit(1)
	return nil
}

func (r *RADb) registryRADbURL(registry string) string {
	var url string

	switch registry {
	case "arin":
		url = "https://rdap.arin.net/registry/"
	case "ripencc":
		url = "https://rdap.db.ripe.net/"
	case "apnic":
		url = "https://rdap.apnic.net/"
	case "lacnic":
		url = "https://rdap.lacnic.net/rdap/"
	case "afrinic":
		url = "https://rdap.afrinic.net/rdap/"
	}
	return url
}

// OnRequest implements the Service interface.
func (r *RADb) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.ASNRequest); ok {
		r.asnRequest(ctx, req)
		r.CheckRateLimit()
	}
}

func (r *RADb) asnRequest(ctx context.Context, req *requests.ASNRequest) {
	if req.Address == "" && req.ASN == 0 {
		return
	}

	r.CheckRateLimit()
	if req.Address != "" {
		r.executeASNAddrQuery(ctx, req.Address)
		return
	}

	r.executeASNQuery(ctx, req.ASN, "", "")
}

func (r *RADb) executeASNAddrQuery(ctx context.Context, addr string) {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	url := r.getIPURL("arin", addr)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(ctx, url, nil, headers, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	var m struct {
		Version   string `json:"ipVersion"`
		ClassName string `json:"objectClassName"` // should be 'ip network'
		CIDRs     []struct {
			V4Prefix string `json:"v4prefix"`
			V6Prefix string `json:"v6prefix"`
			Length   int    `json:"length"`
		} `json:"cidr0_cidrs"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	} else if m.ClassName != "ip network" || len(m.CIDRs) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The request returned zero results", r.String(), url),
		)
		return
	}

	var prefix string
	switch m.Version {
	case "v4":
		prefix = m.CIDRs[0].V4Prefix
	case "v6":
		prefix = m.CIDRs[0].V6Prefix
	}
	if prefix == "" {
		return
	}

	cidr := prefix + "/" + strconv.Itoa(m.CIDRs[0].Length)
	if asn := r.ipToASN(ctx, cidr); asn != 0 {
		r.executeASNQuery(ctx, asn, addr, cidr)
	}
}

func (r *RADb) getIPURL(registry, addr string) string {
	format := r.registryRADbURL(registry) + "ip/%s"

	return fmt.Sprintf(format, addr)
}

func (r *RADb) executeASNQuery(ctx context.Context, asn int, addr, prefix string) {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if asn == 0 {
		return
	}

	numRateLimitChecks(r, 2)
	url := r.getASNURL("arin", strconv.Itoa(asn))
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(ctx, url, nil, headers, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	var m struct {
		ClassName   string `json:"objectClassName"` // interested in "autnum"
		Description string `json:"name"`
		Dates       []struct {
			Action string `json:"eventAction"` // interested in "registration"
			Date   string `json:"eventDate"`
		}
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	} else if m.ClassName != "autnum" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The query returned incorrect results", r.String(), url),
		)
		return
	}

	var registration string
	for _, event := range m.Dates {
		if event.Action == "registration" {
			registration = event.Date
			break
		}
	}

	var at time.Time
	if registration != "" {
		d, err := time.Parse(time.RFC3339, registration)
		if err == nil {
			at = d
		}
	}

	numRateLimitChecks(r, 2)
	blocks := stringset.New()
	if prefix != "" {
		blocks.Insert(prefix)
	}
	blocks.Union(r.netblocks(ctx, asn))

	if len(blocks) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The query returned zero netblocks", r.String(), url),
		)
		return
	}

	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, &requests.ASNRequest{
		Address:        addr,
		ASN:            asn,
		Prefix:         prefix,
		AllocationDate: at,
		Description:    m.Description,
		Netblocks:      blocks,
		Tag:            r.SourceType,
		Source:         r.String(),
	})
}

func (r *RADb) getASNURL(registry, asn string) string {
	format := r.registryRADbURL(registry) + "autnum/%s"

	return fmt.Sprintf(format, asn)
}

func (r *RADb) netblocks(ctx context.Context, asn int) stringset.Set {
	netblocks := stringset.New()

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return netblocks
	}

	numRateLimitChecks(r, 2)
	url := r.getNetblocksURL(strconv.Itoa(asn))
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(ctx, url, nil, headers, nil)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return netblocks
	}

	var m struct {
		Results []struct {
			Version   string `json:"ipVersion"`
			ClassName string `json:"objectClassName"` // should be 'ip network'
			CIDRs     []struct {
				V4Prefix string `json:"v4prefix"`
				V6Prefix string `json:"v6prefix"`
				Length   int    `json:"length"`
			} `json:"cidr0_cidrs"`
		} `json:"arin_originas0_networkSearchResults"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return netblocks
	}

	for _, block := range m.Results {
		if block.ClassName != "ip network" {
			continue
		}

		for _, cidr := range block.CIDRs {
			var prefix string

			switch block.Version {
			case "v4":
				prefix = cidr.V4Prefix
			case "v6":
				prefix = cidr.V6Prefix
			}

			if prefix != "" {
				l := strconv.Itoa(cidr.Length)

				netblocks.Insert(prefix + "/" + l)
			}
		}
	}

	if len(netblocks) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", r.String(), asn),
		)
	}
	return netblocks
}

func (r *RADb) getNetblocksURL(asn string) string {
	format := "https://rdap.arin.net/registry/arin_originas0_networksbyoriginas/%s"

	return fmt.Sprintf(format, asn)
}

func (r *RADb) ipToASN(ctx context.Context, cidr string) int {
	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return 0
	}

	numRateLimitChecks(r, 2)
	if r.addr == "" {
		msg := resolve.QueryMsg(radbWhoisURL, dns.TypeA)
		resp, err := r.sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.RetryPolicy)
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
				fmt.Sprintf("%s: %s: %v", r.String(), radbWhoisURL, err))
			return 0
		}

		ans := resolve.ExtractAnswers(resp)
		if len(ans) == 0 {
			return 0
		}

		ip := ans[0].Data
		if ip == "" {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
				fmt.Sprintf("%s: Failed to resolve %s", r.String(), radbWhoisURL))
			return 0
		}
		r.addr = ip
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := amassnet.DialContext(ctx, "tcp", r.addr+":43")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", r.String(), err))
		return 0
	}
	defer conn.Close()

	fmt.Fprintf(conn, "!r%s,o\n", cidr)

	var asn int
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err != nil {
			continue
		}

		if !strings.HasPrefix(line, "AS") {
			continue
		}

		line2 := strings.ReplaceAll(line, "AS", "")
		nums := strings.Split(strings.TrimSpace(line2), " ")
		n := strings.TrimSpace(nums[len(nums)-1])
		if n == "" {
			continue
		}
		asn, err = strconv.Atoi(n)
		if err != nil {
			asn = 0
		}
	}
	return asn
}
