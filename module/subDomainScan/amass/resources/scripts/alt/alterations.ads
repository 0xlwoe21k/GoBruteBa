-- Copyright 2017-2021 Jeff Foley. All rights reserved.
-- Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

name = "Alterations"
type = "alt"

ldh_chars = "_abcdefghijklmnopqrstuvwxyz0123456789-"

function resolved(ctx, name, domain, records)
    local nparts = split(name, ".")
    local dparts = split(domain, ".")
    -- Do not process resolved root domain names
    if #nparts <= #dparts then
        return
    end

    local cfg = config(ctx)
    if (cfg.mode == "passive" or not cfg['alterations'].active) then
        return
    end

    makenames(ctx, cfg.alterations, name)
end

function makenames(ctx, cfg, name)
    local words = alt_wordlist(ctx)

    if cfg['flip_words'] then
        for i, n in pairs(flip_words(name, words)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
    end
    if cfg['flip_numbers'] then
        for i, n in pairs(flip_numbers(name)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
    end
    if cfg['add_numbers'] then
        for i, n in pairs(append_numbers(name)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
    end
    if cfg['add_words'] then
        for i, n in pairs(add_prefix_word(name, words)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
        for i, n in pairs(add_suffix_word(name, words)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
    end

    local distance = cfg['edit_distance']
    if distance > 0 then
        for i, n in pairs(fuzzy_label_searches(name, distance)) do
            local expired = sendnames(ctx, n)
            if expired then
                return
            end
        end
    end
end

function flip_words(name, words)
    local s = {}
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    parts = split(hostname, "-")
    if #parts < 2 then
        return s
    end

    local post = partial_join(parts, "-", 2, #parts)
    for i, word in pairs(words) do
        set_insert(s, word .. "-" .. post .. "." .. base)
    end

    local pre = partial_join(parts, "-", 1, #parts - 1)
    for i, word in pairs(words) do
        set_insert(s, pre .. "-" .. word .. "." .. base)
    end

    return set_elements(s)
end

function flip_numbers(name)
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    local s = {}
    local start = 1
    while true do
        local b, e = string.find(hostname, "%d+", start)
        if b == nil then
            break
        end
        start = e + 1

        local pre = string.sub(hostname, 1, b - 1)
        local post = string.sub(hostname, e + 1)

        -- Create an entry with the number removed
        set_insert(s, pre .. post .. "." .. base)
        local seq = numseq(tonumber(string.sub(hostname, b, e)))
        for i, sn in pairs(seq) do
            set_insert(s, pre .. sn .. post .. "." .. base)
        end
    end

    return set_elements(s)
end

function numseq(num)
    local s = {}

    local start = num - 50
    if start < 1 then
        start = 1
    end

    local max = num + 50
    for i=start,max do
        set_insert(s, tostring(i))
    end

    return set_elements(s)
end

function append_numbers(name)
    local s = {}
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    for i=0,9 do
        set_insert(s, hostname .. tostring(i) .. "." .. base)
        set_insert(s, hostname .. "-" .. tostring(i) .. "." .. base)
    end

    return set_elements(s)
end

function add_prefix_word(name, words)
    local s = {}
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    for i, w in pairs(words) do
        set_insert(s, w .. hostname .. "." .. base)
        set_insert(s, w .. "-" .. hostname .. "." .. base)
    end

    return set_elements(s)
end

function add_suffix_word(name, words)
    local s = {}
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    for i, w in pairs(words) do
        set_insert(s, hostname .. w .. "." .. base)
        set_insert(s, hostname .. "-" .. w .. "." .. base)
    end

    return set_elements(s)
end

function fuzzy_label_searches(name, distance)
    local parts = split(name, ".")
    local hostname = parts[1]
    local base = partial_join(parts, ".", 2, #parts)

    local s = {hostname}
    for i=1,distance do
        local tb = set_elements(s)

        set_insert_many(s, additions(tb))
        set_insert_many(s, deletions(tb))
        set_insert_many(s, substitutions(tb))
    end

    local results = {}
    for i, n in pairs(set_elements(s)) do
        set_insert(results, n .. "." .. base)
    end

    return set_elements(results)
end

function additions(set)
    local results = {}
    local l = string.len(ldh_chars)

    for x, name in pairs(set) do
        local nlen = string.len(name)

        for i=1,nlen do
            for j=1,l do
                local c = string.sub(ldh_chars, j, j)
                local post = string.sub(name, i)
                local pre = ""
                if i > 1 then
                    pre = string.sub(name, 1, i - 1)
                end

                set_insert(results, pre .. c .. post)
            end
        end
    end

    return set_elements(results)
end

function deletions(set)
    local results = {}

    for x, name in pairs(set) do
        local nlen = string.len(name)

        for i=1,nlen do
            local post = string.sub(name, i + 1)
            local pre = ""
            if i > 1 then
                pre = string.sub(name, 1, i - 1)
            end

            set_insert(results, pre .. post)
        end
    end

    return set_elements(results)
end

function substitutions(set)
    local results = {}
    local l = string.len(ldh_chars)

    for x, name in pairs(set) do
        local nlen = string.len(name)

        for i=1,nlen do
            for j=1,l do
                local c = string.sub(ldh_chars, j, j)
                local post = string.sub(name, i + 1)
                local pre = ""
                if i > 1 then
                    pre = string.sub(name, 1, i - 1)
                end

                set_insert(results, pre .. c .. post)
            end
        end
    end

    return set_elements(results)
end

function split(str, delim)
    local result = {}
    local pattern = "[^%" .. delim .. "]+"

    local matches = find(str, pattern)
    if (matches == nil or #matches == 0) then
        return result
    end

    for i, match in pairs(matches) do
        table.insert(result, match)
    end

    return result
end

function join(parts, sep)
    local result = ""

    for i, v in pairs(parts) do
        result = result .. sep .. v
    end

    return result
end

function partial_join(parts, sep, first, last)
    if (first < 1 or last > #parts) then
        return ""
    end

    local result = parts[first]
    first = first + 1

    for i=first,last do
        result = result .. sep .. parts[i]
    end

    return result
end

function set_insert(tb, name)
    if name ~= "" then
        tb[name] = true
    end

    return tb
end

function set_insert_many(tb, list)
    if list == nil then
        return tb
    end

    for i, v in pairs(list) do
        tb[v] = true
    end

    return tb
end

function set_elements(tb)
    local result = {}
    if tb == nil then
        return result
    end

    for k, v in pairs(tb) do
        table.insert(result, k)
    end

    return result
end

function sendnames(ctx, content)
    local names = find(content, subdomainre)
    if names == nil then
        return false
    end

    local found = {}
    for i, v in pairs(names) do
        if found[v] == nil then
            local expired = newname(ctx, v)
            if expired then
                return expired
            end
            found[v] = true
        end
    end

    return false
end
