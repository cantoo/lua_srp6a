#SRP6a
[TOC]
##密码验证中哪里数据可能被窃取
- 代码
- 网络包
- 数据库

**终极目标:** 所有以上数据全部公开, 也不会导致密码泄露

##常用的密码验证方法
- 明文传输密码
- 传输hash(密码)
	- [彩虹表](https://zh.wikipedia.org/wiki/%E5%BD%A9%E8%99%B9%E8%A1%A8), hash(密码)是密码等价物
- 使用加密通道传输密码
>**问题:** 加密通道如何建立?

##Diffie-Hellman key exchange
```sequence
Title:Alice and Bob both know:\np = 23(a prime number)\ng = 11(a generator)
Note over Alice: Alice pick random a = 6
Alice->Bob: A = g^a mod p = 9
Note over Bob: Bob pick random b = 5
Bob->Alice: B = g^b mod p = 5
Note over Alice: K = B^a mod p = 8
Note over Bob: K = A^b mod p = 8
```
>[**wikipedia: **](https://zh.wikipedia.org/wiki/%E8%BF%AA%E8%8F%B2-%E8%B5%AB%E7%88%BE%E6%9B%BC%E5%AF%86%E9%91%B0%E4%BA%A4%E6%8F%9B)如果 p 是一个至少 300 位的质数，并且a和b至少有100位长， 那么即使使用全人类所有的计算资源和当今最好的算法也不可能从g, p和A 中计算出 a。这个问题就是著名的**离散对数问题**。

##中间人攻击
```sequence
Alice->Eve: A = g^a mod p
Eve->Bob: Z = g^z mod p
Bob->Eve: B = g^b mod p
Eve->Alice: Z = g^z mod p
Note over Alice: KA = Z^a mod p
Note over Eve: KA = A^z mod p\nKB=B^z mod p
Note over Bob: KB = Z^b mod p
```

##SSL
```sequence
Alice->Bob: Client random\n我支持的加密算法, 密钥交换算法, 哈希算法
Bob->Alice: \nServer random\n选定算法组合\n数据证书(包含Bob的公钥)\n^
Note over Alice: 确认证书有效
Alice->Bob: 公钥加密(Premaster secret)
Note over Bob: 使用私钥解出Premaster secret
Note over Alice,Bob: 使用Client random, Server random, Premaster secret生成会话密钥
```

**ssl为避免中间人攻击, 必须有一个可信任的第三方**
<!--中间人攻击一般使用域名劫持的方式, 那可信任的第三方的域名也有可能被劫持-->
<!--没有客户端服务器双方共同认知的密钥协商无法摆脱中间人攻击-->
<!--问题守恒, 如果一件事情本身是有问题的, 那用一些方法规避只会产生新的问题-->

##SRP6a算法简介

**官方设计文档:** [SRP Protocol Design](http://srp.stanford.edu/design.html) 
**相关标准:** [RFC2945](https://tools.ietf.org/html/rfc2945)

>[**wikipedia: **](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)The SRP protocol has a number of desirable properties: it allows a user to authenticate themselves to a server, it is resistant to **dictionary attacks** mounted by an eavesdropper, and it does not require a **trusted third party**. It effectively conveys a **zero-knowledge password proof** from the user to the server.

- 不传输密码等价物
- 不需要第三方参与
- 不惧怕中间人攻击
- 客户端也能验证服务器

**开源实现:** 
- [Javascript](https://github.com/symeapp/srp-client) 
- [Java](http://www.gnu.org/software/gnu-crypto/) 
- [C](https://github.com/cocagne/csrp)
- [Openssl](https://github.com/openssl/openssl/tree/master/crypto/srp)
- [C++](https://github.com/slechta/DragonSRP/)
- [Python](https://bitbucket.org/pbleyer/py3srp)
- [Lua](https://github.com/cantoo/lua_srp6a)

##注册 - 使用SRP6a
```sequence
Alice->Bob: I
Bob->Alice: N, g, s
Note over Alice: x = H(s | H ( I | ":" | p))
Alice->Bob: v = g^x mod N(password verifier) 
Note over Bob: Bob store I: v, s
```
其中:
N是一个至少1024位的大素数, 要求*N = 2q + 1 q*也是素数.
g是一个以N为模的生成元.
s是盐, I是用户名, p是密码

##验证 - 使用SRP6a
```sequence
Alice->Bob: I
Bob->Alice: N, g, s
Note over Alice: pick random a
Alice->Bob: A = g^a mod N
Note right of Bob: if(A mod N == 0) abort
Note over Bob: k = H(N, g)\npick random b
Bob->Alice: B = kv + g^b mod N
Note left of Alice: if(B mod N == 0) abort
Note over Alice,Bob: Both u = H(A, B)
Note over Alice: x = H(s | H ( I | ":" | p))\nS = (B - g^x)^(a + ux) mod N\nK = H(S)
Note over Bob: S = (Av^u)^b mod N\nK = H(S)
Note over Alice,Bob: M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)\nM2 = H(A | M1 | K)
Alice-->Bob: M1
Note over Bob: verify M1
Bob-->Alice: M2
Note over Alice: verify M2
```
**讨论: 登录态是什么?**
>[**wikipedia: **](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)Now the two parties have a shared, strong session key K. To complete authentication, they need to prove to each other that their keys match. 

>When using SRP to negotiate a shared key "K" which will be immediately used after the negotiation the verification steps of "M"1 and "M"2 may be skipped. The server will reject the very first request from the client which it cannot decrypt.

##SRP6a代码演示
```lua
local srp = require ("srp")

local username = "username"
local passwd = "passwd"
print("Client ============== > Server:\n"
	.. "username = " .. username .. "\n")

local g, N = srp.get_default_gN();
local s, v = srp.create_verifier(username, passwd, N, g)
print("Server ============== > Client:\n"
	.. "N = " .. N .. "\n"
	.. "g = " .. g .. "\n"
	.. "s = " .. s .. "\n")

local a = srp.RAND_pseudo_bytes(32)
--print("Client a: " .. a)
local A = srp.Calc_A(a, N, g)
print("Client ============== > Server:\n"
	.. "A = " .. A .. "\n")

print("Server verify A mod N: " .. srp.Verify_mod_N(A, N))
local b = srp.RAND_pseudo_bytes(32)
--print("b: " .. b)
local B = srp.Calc_B(b, N, g, v)
print("Server ============== > Client:\n"
	.. "B = " .. B .. "\n")
	
print("Client verify B mod N: " .. srp.Verify_mod_N(B, N))
local Kclient = srp.Calc_client_key(A, B, N, s, username, passwd, g, a)
--print("Kclient: " .. Kclient);
local M1 = srp.Calc_M1(N, g, username, s, A, B, Kclient);
print("Client ============== > Server:\n"
	.. "M1 = " .. M1 .. "\n")

print("Server verify M1 match")
local Kserver = srp.Calc_server_key(A, B, N, v, b);
--print("Kserver: " .. Kserver);
local M2 = srp.Calc_M2(A, M1, Kserver)
print("Server ============== > Client:\n"
	.. "M2 = " .. M2 .. "\n")

print("Client verify M2 match \n")
```





