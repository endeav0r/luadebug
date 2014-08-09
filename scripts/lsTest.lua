require ('ldebug')

function map (f, t)
    local result = {}
    for k,v in pairs(t) do
        result[k] = f(v)
    end
    return result
end

function stepPrint (d)
    d:step()

    pcString = string.format('%x', d:getpc())
    bytes = d:readmem(d:getpc(), 8)

    function formatByte (b)
        return string.format('%02x', b)
    end

    bytesString = table.concat(map(formatByte, bytes))


    print(string.format(pcString .. '\t' .. bytesString))
end

local d = ldebug.execv('/bin/ls', {'/'})

for i=1,10 do
    stepPrint(d)
end