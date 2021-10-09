-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "ArchiveIt"
type = "archive"

function start()
    setratelimit(1)
end

function vertical(ctx, domain)
    scrape(ctx, {['url']=firsturl(domain)})

    local found = pages(ctx, domain)
    if not found then
        return
    end

    for i=1,50,1 do
        local ok = scrape(ctx, {['url']=secondurl(domain, i)})
        if not ok then
            break
        end

        checkratelimit()
    end
end

function firsturl(domain)
    return "https://wayback.archive-it.org/all/timemap/cdx?matchType=domain&fl=original&collapse=urlkey&url=" .. domain
end

function secondurl(domain, pagenum)
    return "https://archive-it.org/explore?show=Sites&q=" .. domain .. "&page=" .. pagenum
end

function pages(ctx, domain)
    local u = "https://archive-it.org/explore?show=Sites&q=" .. domain
    local resp, err = request(ctx, {['url']=u})
    if (err ~= nil and err ~= "") then
        return false
    end

    local match = find(resp, "No metadata results")
    if (match == nil or #match == 0) then
        return false
    end

    return true
end
