// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package intel

import (
	"context"
	"net"
	"strings"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"golang.org/x/net/publicsuffix"
)

// activeTask is the task that handles all requests related to active methods within the pipeline.
type activeTask struct {
	c         *Collection
	queue     queue.Queue
	tokenPool chan struct{}
}

type taskArgs struct {
	Ctx    context.Context
	Data   pipeline.Data
	Params pipeline.TaskParams
}

// newActiveTask returns a activeTask specific to the provided Collection.
func newActiveTask(c *Collection, max int) *activeTask {
	if max <= 0 {
		return nil
	}

	tokenPool := make(chan struct{}, max)
	for i := 0; i < max; i++ {
		tokenPool <- struct{}{}
	}

	a := &activeTask{
		c:         c,
		queue:     queue.NewQueue(),
		tokenPool: tokenPool,
	}

	go a.processQueue()
	return a
}

// Process implements the pipeline Task interface.
func (a *activeTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	var ok bool
	switch data.(type) {
	case *requests.AddrRequest:
		ok = true
	}

	if ok {
		a.queue.Append(&taskArgs{
			Ctx:    ctx,
			Data:   data.Clone(),
			Params: tp,
		})
	}

	return data, nil
}

func (a *activeTask) processQueue() {
	for {
		select {
		case <-a.c.done:
			return
		case <-a.queue.Signal():
			a.processTask()
		}
	}
}

func (a *activeTask) processTask() {
	select {
	case <-a.c.done:
		return
	case <-a.tokenPool:
		element, ok := a.queue.Next()
		if !ok {
			a.tokenPool <- struct{}{}
			return
		}

		args := element.(*taskArgs)
		switch v := args.Data.(type) {
		case *requests.AddrRequest:
			go a.certEnumeration(args.Ctx, v, args.Params)
		}
	}
}

func (a *activeTask) certEnumeration(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	defer func() { a.tokenPool <- struct{}{} }()

	if req == nil || !req.Valid() {
		return
	}

	ip := net.ParseIP(req.Address)
	if ip == nil {
		return
	}

	c := a.c
	addrinfo := requests.AddressInfo{Address: ip}
	for _, name := range http.PullCertificateNames(ctx, req.Address, c.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			domain, err := publicsuffix.EffectiveTLDPlusOne(n)
			if err != nil {
				continue
			}

			if domain != "" {
				go pipeline.SendData(ctx, "filter", &requests.Output{
					Name:      domain,
					Domain:    domain,
					Addresses: []requests.AddressInfo{addrinfo},
					Tag:       requests.CERT,
					Sources:   []string{"Active Cert"},
				}, tp)
			}
		}
	}
}
