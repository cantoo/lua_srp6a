local aes = require "resty.aes"

local function from_hex(hex)
    return string.gsub(hex, "%x%x", function(c) return string.char(tonumber(c, 16)) end)
end

local key = from_hex("2cf4e4bed6ab49b420badab434866bca8a5192f18782009690fda02369937f4f61e38a9947fc8dd2ced6b0671b13f07a2832aa75668e442bb1728619f7ac1cbdc251e5a6d6d24348397652de32ac7720de23993fc8c642d4e1a4d8f751e48a3a428d609b028405953ff7a7656d19dd61296fb0fcfbb0ad688ca0f6445ba57cab2a63943446cb24651c2c18bcf4f1c64c2608333ead024acb32fa16ff5a4fe207f1506e0189a17b57253d6f05445baa56c9a4730f863a49467a0836bd9f72b81d9e9934ab2ff1a267e6a369b822e677b32daeb53e4839654bfbf476828a0520d38763db1950abe6361ecbff55d77b00d0f7fc6bac899d64df047b3a5fb1613119")
key = string.sub(key, 1, 32)
local iv = from_hex("bfd3814678afe0036efa67ca8da44e2e")
local aes_256_cbc_with_iv = aes:new(key, nil, aes.cipher(256, "cbc"), {iv = iv})

-- AES 128 CBC with IV and no SALT
local encrypted = aes_256_cbc_with_iv:encrypt([[{"I":"username","q":1,"clt":{"p":"wxapp","v":10000}}]])
print(ngx.encode_base64(encrypted))
print(aes_256_cbc_with_iv:decrypt(encrypted))

