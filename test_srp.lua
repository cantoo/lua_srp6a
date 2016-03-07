local srp = require ("srp")
local g, N = srp.get_default_gN();
print("g: " .. g);
print("N: " .. N);

local username = "username"
local passwd = "passwd"
local s, v = srp.create_verifier(username, passwd, N, g)
print("s: " .. s)
print("v: " .. v)

local b = srp.RAND_pseudo_bytes(32)
print("b: " .. b)
local B = srp.Calc_B(b, N, g, v)
print("B: " .. B)
print("B mod N: " .. srp.Verify_mod_N(B, N))

local a = srp.RAND_pseudo_bytes(32)
print("a: " .. a)
local A = srp.Calc_A(a, N, g)
print("A: " .. A)
print("A mod N: " .. srp.Verify_mod_N(A, N))

local Kclient = srp.Calc_client_key(A, B, N, s, username, passwd, g, a)
print("Kclient: " .. Kclient);

local Kserver = srp.Calc_server_key(A, B, N, v, b);
print("Kserver: " .. Kserver);

