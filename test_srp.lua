local srp = require ("srp")

local username = "username"
local password = "123456"
print("Client ============== > Server:\n"
	.. "username = " .. username .. "\n")

local g, N = srp.get_default_gN("2048");
local s = srp.RAND_pseudo_bytes(16)
local v = srp.create_verifier(username, password, s, N, g)
print("v = " .. v);
print("Server ============== > Client:\n"
	.. "N = " .. N .. "\n"
	.. "g = " .. g .. "\n"
	.. "s = " .. s .. "\n")

local a = srp.RAND_pseudo_bytes(32)
print("a = " .. a)
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
local Kclient = srp.Calc_client_key(A, B, N, s, username, password, g, a)
print("Kclient = " .. Kclient);
local M1 = srp.Calc_M1(N, g, username, s, A, B, Kclient);
print("Client ============== > Server:\n"
	.. "M1 = " .. M1 .. "\n")

print("Server verify M1 match")
local Kserver = srp.Calc_server_key(A, B, N, v, b);
print("Kserver = " .. Kserver);
local M2 = srp.Calc_M2(A, M1, Kserver)
print("Server ============== > Client:\n"
	.. "M2 = " .. M2 .. "\n")

print("Client verify M2 match \n")
