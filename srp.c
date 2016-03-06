// gcc -O3 -Wall -I/data/lib/include -I/data/app/nginx/luajit/include/luajit-2.0/ -c srp.c
// gcc -shared -fPIC srp.o /usr/local/lib/liblua.a /data/lib/lib/libcrypto.a -o srp.so

#include <stdlib.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <openssl/srp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/asn1.h>

static int srp_get_default_gN(lua_State* L)
{
    char N_num_bits[4] = "1024";
    if(lua_gettop(L) >= 1 && lua_isstring(L, 1))
    {
        memset(N_num_bits, 0, sizeof(N_num_bits));
        strncpy(N_num_bits, lua_tostring(L, 1), sizeof(N_num_bits));
    }

    SRP_gN *GN = SRP_get_default_gN(N_num_bits);
    if(GN == NULL)
    {
        return luaL_error(L, "get_default_gN failed");
    }

    char* strN = BN_bn2hex(GN->N);
    if(strN == NULL)
    {
        return luaL_error(L, "get_default_gN BN_bin2hex N failed");
    }

    lua_pushnumber(L, BN_get_word(GN->g));
    lua_pushstring(L, strN);
    OPENSSL_free(strN);
    return 2;
};

static int srp_RAND_pseudo_bytes(lua_State* L)
{
    unsigned char rand_tmp[4096] = {0};
    int32_t rand_size = 32;
    if(lua_gettop(L) >= 1 && lua_isnumber(L, 1))
    {
        rand_size = lua_tonumber(L, 1);
        rand_size = rand_size > sizeof(rand_tmp) ? sizeof(rand_tmp) : rand_size;
    }

    RAND_pseudo_bytes(rand_tmp, rand_size);
    BIGNUM* rd = BN_bin2bn(rand_tmp, rand_size, NULL);
    if(rd == NULL)
    {
        return luaL_error(L, "RAND_pseudo_bytes BN_bin2bn rd failed");
    }

    char* strrd = BN_bn2hex(rd);
    if(strrd == NULL)
    {
        BN_free(rd);
        return luaL_error(L, "RAND_pseudo_bytes BN_bin2hex rd failed");
    }

    lua_pushstring(L, strrd);
    OPENSSL_free(strrd);
    BN_free(rd);
    return 1;
};

static int srp_Calc_B(lua_State* L)
{
    if(lua_gettop(L) < 4)
    {
        return luaL_error(L, "Calc_B require b, N, g, v");
    }

    int ret = 1;
    BIGNUM* b = BN_new();
    BIGNUM* N = NULL;
    BIGNUM* g = NULL;
    BIGNUM* v = NULL;
    BIGNUM* B = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&b, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_B invalid b");
        goto err;
    }

    N = BN_new();
    if(!lua_isstring(L, 2) || !BN_hex2bn(&N, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_B invalid N");
        goto err;
    }

    g = BN_new();
    if(!lua_isnumber(L, 3) || !BN_set_word(g, lua_tonumber(L, 3)))
    {
        ret = luaL_error(L, "Calc_B invalid g");
        goto err;
    }

    v = BN_new();
    if(!lua_isstring(L, 4) || !BN_hex2bn(&v, lua_tostring(L, 4)))
    {
        ret = luaL_error(L, "Calc_B invalid v");
        goto err;
    }

    B = SRP_Calc_B(b, N, g, v);
    char* strB = BN_bn2hex(B);
    lua_pushstring(L, strB);
    OPENSSL_free(strB);

err:
    BN_free(b);
    BN_free(N);
    BN_free(g);
    BN_free(v);
    BN_free(B);
    return ret;
};

static const luaL_reg srp_lib[] = {
    { "get_default_gN", srp_get_default_gN },
    { "RAND_pseudo_bytes", srp_RAND_pseudo_bytes },
    { "Calc_B", srp_Calc_B },
    { NULL, NULL }
};

int luaopen_srp(lua_State *L)
{
    luaL_register(L, "srp", srp_lib);
    return 1;
};



