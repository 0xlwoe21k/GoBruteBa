// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package scripting

import (
	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/service"
	lua "github.com/yuin/gopher-lua"
)

// Wrapper so that scripts can obtain the configuration for the current enumeration.
func (s *Script) config(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	r := L.NewTable()
	if cfg.Active {
		r.RawSetString("mode", lua.LString("active"))
	} else if cfg.Passive {
		r.RawSetString("mode", lua.LString("passive"))
	} else {
		r.RawSetString("mode", lua.LString("normal"))
	}

	r.RawSetString("event_id", lua.LString(cfg.UUID.String()))
	r.RawSetString("max_dns_queries", lua.LNumber(cfg.MaxDNSQueries))

	scope := L.NewTable()
	tb := L.NewTable()
	for _, domain := range cfg.Domains() {
		tb.Append(lua.LString(domain))
	}
	scope.RawSetString("domains", tb)

	tb = L.NewTable()
	for _, sub := range cfg.Blacklist {
		tb.Append(lua.LString(sub))
	}
	scope.RawSetString("blacklist", tb)

	tb = L.NewTable()
	for _, rt := range cfg.RecordTypes {
		tb.Append(lua.LString(rt))
	}
	r.RawSetString("dns_record_types", tb)

	tb = L.NewTable()
	for _, resolver := range cfg.Resolvers {
		tb.Append(lua.LString(resolver))
	}
	r.RawSetString("resolvers", tb)

	tb = L.NewTable()
	for _, name := range cfg.ProvidedNames {
		tb.Append(lua.LString(name))
	}
	r.RawSetString("provided_names", tb)

	tb = L.NewTable()
	for _, addr := range cfg.Addresses {
		tb.Append(lua.LString(addr.String()))
	}
	scope.RawSetString("addresses", tb)

	tb = L.NewTable()
	for _, cidr := range cfg.CIDRs {
		tb.Append(lua.LString(cidr.String()))
	}
	scope.RawSetString("cidrs", tb)

	tb = L.NewTable()
	for _, asn := range cfg.ASNs {
		tb.Append(lua.LNumber(asn))
	}
	scope.RawSetString("asns", tb)

	tb = L.NewTable()
	for _, port := range cfg.Ports {
		tb.Append(lua.LNumber(port))
	}
	scope.RawSetString("ports", tb)
	r.RawSetString("scope", scope)

	tb = L.NewTable()
	tb.RawSetString("active", lua.LBool(cfg.BruteForcing))
	tb.RawSetString("recursive", lua.LBool(cfg.Recursive))
	tb.RawSetString("min_for_recursive", lua.LNumber(cfg.MinForRecursive))
	r.RawSetString("brute_forcing", tb)

	tb = L.NewTable()
	tb.RawSetString("active", lua.LBool(cfg.Alterations))
	tb.RawSetString("flip_words", lua.LBool(cfg.FlipWords))
	tb.RawSetString("flip_numbers", lua.LBool(cfg.FlipNumbers))
	tb.RawSetString("add_words", lua.LBool(cfg.AddWords))
	tb.RawSetString("add_numbers", lua.LBool(cfg.AddNumbers))
	tb.RawSetString("edit_distance", lua.LNumber(cfg.EditDistance))
	r.RawSetString("alterations", tb)

	L.Push(r)
	return 1
}

func (s *Script) dataSourceConfig(L *lua.LState) int {
	cfg := s.sys.Config().GetDataSourceConfig(s.String())
	if cfg == nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	tb.RawSetString("name", lua.LString(cfg.Name))
	if cfg.TTL != 0 {
		tb.RawSetString("ttl", lua.LNumber(cfg.TTL))
	}

	if creds := cfg.GetCredentials(); creds != nil {
		c := L.NewTable()

		c.RawSetString("name", lua.LString(creds.Name))
		if creds.Username != "" {
			c.RawSetString("username", lua.LString(creds.Username))
		}
		if creds.Password != "" {
			c.RawSetString("password", lua.LString(creds.Password))
		}
		if creds.Key != "" {
			c.RawSetString("key", lua.LString(creds.Key))
		}
		if creds.Secret != "" {
			c.RawSetString("secret", lua.LString(creds.Secret))
		}
		tb.RawSetString("credentials", c)
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can check if a subdomain name is in scope.
func (s *Script) inScope(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LFalse)
		return 1
	}

	lv := L.Get(2)
	if sub, ok := lv.(lua.LString); ok && cfg.IsDomainInScope(string(sub)) {
		L.Push(lua.LTrue)
		return 1
	}

	L.Push(lua.LFalse)
	return 1
}

// Wrapper so that scripts can obtain the brute force wordlist for the current enumeration.
func (s *Script) bruteWordlist(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, word := range cfg.Wordlist {
		tb.Append(lua.LString(word))
	}

	L.Push(tb)
	return 1
}

// Wrapper so that scripts can obtain the alteration wordlist for the current enumeration.
func (s *Script) altWordlist(L *lua.LState) int {
	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	tb := L.NewTable()
	for _, word := range cfg.AltWordlist {
		tb.Append(lua.LString(word))
	}

	L.Push(tb)
	return 1
}

// Wrapper so scripts can set the data source rate limit.
func (s *Script) setRateLimit(L *lua.LState) int {
	lv := L.Get(1)
	if lv == nil {
		return 0
	}

	if num, ok := lv.(lua.LNumber); ok {
		sec := int(num)

		s.seconds = sec
	}
	return 0
}

func numRateLimitChecks(srv service.Service, num int) {
	for i := 0; i < num; i++ {
		srv.CheckRateLimit()
	}
}

// Wrapper so scripts can block until past the data source rate limit.
func (s *Script) checkRateLimit(L *lua.LState) int {
	numRateLimitChecks(s, s.seconds)
	return 0
}

// Wrapper so that scripts can request the path to the Amass output directory.
func (s *Script) outputdir(L *lua.LState) int {
	var dir string

	ctx, err := extractContext(L.CheckUserData(1))
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	cfg, _, err := requests.ContextConfigBus(ctx)
	if err == nil {
		dir = config.OutputDirectory(cfg.Dir)
	}

	L.Push(lua.LString(dir))
	return 1
}
