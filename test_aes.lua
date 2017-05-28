local aes = require "resty.aes"

local function from_hex(hex)
    return string.gsub(hex, "%x%x", function(c) return string.char(tonumber(c, 16)) end)
end

local key = from_hex("933BE86463227AEEB040902D2A68B2899D2B36A24EE539A8EFA89C1240875F9E705CDA349A5025B678E0A4C3BF78409CD37A3A98487964EA4C675F9ADA00F88CF040EBD331A5264860720D6D8D26BF86D35509D714CF1FA640F62E32D801B29F6CE68638705F5F18B79299FAC0E566BA0E704483F9AC3DF6AA6F2F292F689CA3826A71A84698861EC8AE05C6A5DCD40E4F0ED01AB214413AAE23D3A34C56DA014BC9585574A92A11AF4201B79833C7C783BC5E7D713F5BA222FBDF6506FF1DCCBA736E06BDDA17C9A7631BABDBA1A92115B252B950998A623D5F2A1ADB324782D48FCC151CD0045219A75FAE8F18FA8ABF37977541C64CB00A6000F755106218")
key = string.sub(key, 1, 32)
local iv = from_hex("bfd3814678afe0036efa67ca8da44e2e")
local aes_256_cbc_with_iv = aes:new(key, nil, aes.cipher(256, "cbc"), {iv = iv})

-- AES 128 CBC with IV and no SALT
local encrypted = aes_256_cbc_with_iv:encrypt([[{"I":"username","q":1,"clt":{"p":"wxapp","v":10000}}]])
print(ngx.encode_base64(encrypted))
print(aes_256_cbc_with_iv:decrypt(encrypted))


encrypted = "AehgVsne741NRvGGRrrIcktjZtf52/0gFOAlWkSLLAoz8X2XpGhJ1Ccez0e4YA78ZsYHrflvUoRp6odSSgTmnpqVFvbQNqhzl9KJRw52FyQW84AEEUfMK3xIEZ16Lc5D"
encrypted = ngx.decode_base64(encrypted)
print("------------------")
print(aes_256_cbc_with_iv:decrypt(encrypted))

