-- Copyright 2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Anubis"
type = "api"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {url=buildurl(domain)})
end

function buildurl(domain)
    return "https://jldc.me/anubis/subdomains/" .. domain
end
