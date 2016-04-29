// gcc -O3 -Wall -I/data/lib/include -I/data/app/nginx/luajit/include/luajit-2.0/ -c srp.c
// gcc -shared -fPIC srp.o /usr/local/lib/liblua.a /data/lib/lib/libcrypto.a -o srp.so

#include <stdlib.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include <openssl/srp.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
# include <openssl/sha.h>

static int srp_get_default_gN(lua_State* L)
{
    char N_num_bits[] = "1024";
    if(lua_gettop(L) >= 1 && lua_isstring(L, 1))
    {
        memset(N_num_bits, 0, sizeof(N_num_bits));
        strncpy(N_num_bits, lua_tostring(L, 1), sizeof(N_num_bits) - 1);
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

static int srp_Verify_mod_N(lua_State* L)
{
    if(lua_gettop(L) < 2)
    {
        return luaL_error(L, "Verify_mod_N require the variable to verify and N");
    }

    int ret = 1;
    BIGNUM* B = NULL;
    BIGNUM* N = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&B, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Verify_mod_N invalid verify variable");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&N, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Verify_mod_N invalid N");
        goto err;
    }

    int result = SRP_Verify_B_mod_N(B, N);
    lua_pushnumber(L, result);

err:
    BN_free(B);
    BN_free(N);
    return ret;
};

static int srp_create_verifier(lua_State* L)
{
    if(lua_gettop(L) < 4)
    {
        return luaL_error(L, "create_verifier require username, passwd, N, g");
    }

    int ret = 2;
    char username[4096] = {0};
    char passwd[4096] = {0};
    BIGNUM* N = NULL;
    BIGNUM* g = BN_new();
    BIGNUM* s = NULL;
    BIGNUM* v = NULL;
    char* strs = NULL;
    char* strv = NULL;

    if(!lua_isstring(L, 1))
    {
        ret = luaL_error(L, "create_verifier invalid username");
        goto err;
    }

    strncpy(username, lua_tostring(L, 1), sizeof(username));

    if(!lua_isstring(L, 2))
    {
        ret = luaL_error(L, "create_verifier invalid passwd");
        goto err;
    }

    strncpy(passwd, lua_tostring(L, 2), sizeof(passwd));

    if(!lua_isstring(L, 3) || !BN_hex2bn(&N, lua_tostring(L, 3)))
    {
        ret = luaL_error(L, "create_verifier invalid N");
        goto err;
    }

    if(!lua_isnumber(L, 4) || !BN_set_word(g, lua_tonumber(L, 4)))
    {
        ret = luaL_error(L, "create_verifier invalid g");
        goto err;
    }

    if(!SRP_create_verifier_BN(username, passwd, &s, &v, N, g)) 
    {
        ret = luaL_error(L, "create_verifier failed");
        goto err;
    }

    strs = BN_bn2hex(s);
    if(strs == NULL)
    {
        ret = luaL_error(L, "create_verifier BN_bin2hex s failed");
        goto err;
    }

    strv = BN_bn2hex(v);
    if(strv == NULL)
    {
        ret = luaL_error(L, "create_verifier BN_bin2hex v failed");
        goto err;
    }

    lua_pushstring(L, strs);
    lua_pushstring(L, strv);

err:
    BN_free(N);
    BN_free(g);
    BN_free(s);
    BN_free(v);
    OPENSSL_free(strs);
    OPENSSL_free(strv);
    return ret;
};


static int srp_Calc_A(lua_State* L)
{
    if(lua_gettop(L) < 3)
    {
        return luaL_error(L, "Calc_A require a, N, g");
    }

    int ret = 1;
    BIGNUM* a = NULL;
    BIGNUM* N = NULL;
    BIGNUM* g = BN_new();
    BIGNUM* A = NULL;
    char* strA = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&a, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_A invalid a");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&N, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_A invalid N");
        goto err;
    }

    if(!lua_isnumber(L, 3) || !BN_set_word(g, lua_tonumber(L, 3)))
    {
        ret = luaL_error(L, "Calc_A invalid g");
        goto err;
    }

    A = SRP_Calc_A(a, N, g);
    if(A == NULL)
    {
        ret = luaL_error(L, "Calc_A SRP_Calc_A failed");
        goto err;
    }

    strA = BN_bn2hex(A);
    if(strA == NULL)
    {
        ret = luaL_error(L, "Calc_A BN_bin2hex A failed");
        goto err;
    }

    lua_pushstring(L, strA);

err:
    BN_free(a);
    BN_free(N);
    BN_free(g);
    BN_free(A);
    OPENSSL_free(strA);
    return ret;
}

static int srp_Calc_B(lua_State* L)
{
    if(lua_gettop(L) < 4)
    {
        return luaL_error(L, "Calc_B require b, N, g, v");
    }

    int ret = 1;
    BIGNUM* b = NULL;
    BIGNUM* N = NULL;
    BIGNUM* g = BN_new();
    BIGNUM* v = NULL;
    BIGNUM* B = NULL;
    char* strB = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&b, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_B invalid b");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&N, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_B invalid N");
        goto err;
    }

    if(!lua_isnumber(L, 3) || !BN_set_word(g, lua_tonumber(L, 3)))
    {
        ret = luaL_error(L, "Calc_B invalid g");
        goto err;
    }

    if(!lua_isstring(L, 4) || !BN_hex2bn(&v, lua_tostring(L, 4)))
    {
        ret = luaL_error(L, "Calc_B invalid v");
        goto err;
    }

    B = SRP_Calc_B(b, N, g, v);
    if(B == NULL)
    {
        ret = luaL_error(L, "Calc_B SRP_Calc_B failed");
        goto err;
    }

    strB = BN_bn2hex(B);
    if(strB == NULL)
    {
        ret = luaL_error(L, "Calc_B BN_bin2hex B failed");
        goto err;
    }

    lua_pushstring(L, strB);

err:
    BN_free(b);
    BN_free(N);
    BN_free(g);
    BN_free(v);
    BN_free(B);
    OPENSSL_free(strB);
    return ret;
};

static int srp_Calc_client_key(lua_State* L)
{
    if(lua_gettop(L) < 8)
    {
        return luaL_error(L, "Calc_client_key require A, B, N, s, username, passwd, g, a");
    }

    int ret = 1;
    BIGNUM* A = NULL;
    BIGNUM* B = NULL;
    BIGNUM* N = NULL;
    BIGNUM* s = NULL;
    BIGNUM* g = BN_new();
    BIGNUM* a = NULL;
    BIGNUM* u = NULL;
    BIGNUM* x = NULL;
    BIGNUM* K = NULL;
    char username[4096] = {0};
    char passwd[4096] = {0};
    char* strK = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&A, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_client_key invalid A");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&B, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_client_key invalid B");
        goto err;
    }

    if(!lua_isstring(L, 3) || !BN_hex2bn(&N, lua_tostring(L, 3)))
    {
        ret = luaL_error(L, "Calc_client_key invalid N");
        goto err;
    }

    if(!lua_isstring(L, 4) || !BN_hex2bn(&s, lua_tostring(L, 4)))
    {
        ret = luaL_error(L, "Calc_client_key invalid s");
        goto err;
    }

    if(!lua_isstring(L, 5))
    {
        ret = luaL_error(L, "Calc_client_key invalid username");
        goto err;
    }

    strncpy(username, lua_tostring(L, 5), sizeof(username));

    if(!lua_isstring(L, 6))
    {
        ret = luaL_error(L, "Calc_client_key invalid passwd");
        goto err;
    }

    strncpy(passwd, lua_tostring(L, 6), sizeof(passwd));

    if(!lua_isnumber(L, 7) || !BN_set_word(g, lua_tonumber(L, 7)))
    {
        ret = luaL_error(L, "Calc_client_key invalid g");
        goto err;
    }

    if(!lua_isstring(L, 8) || !BN_hex2bn(&a, lua_tostring(L, 8)))
    {
        ret = luaL_error(L, "Calc_client_key invalid a");
        goto err;
    }

    /* calculate u */
    u = SRP_Calc_u(A, B, N);
    if(u == NULL)
    {
        ret = luaL_error(L, "Calc_client_key SRP_Calc_u failed");
        goto err;
    }

    /* calculate x */
    x = SRP_Calc_x(s, username, passwd);
    if(x == NULL)
    {
        ret = luaL_error(L, "Calc_client_key SRP_Calc_x failed");
        goto err;
    }

    K = SRP_Calc_client_key(N, B, g, x, a, u);
    if(K == NULL)
    {
        ret = luaL_error(L, "Calc_client_key SRP_Calc_client_key failed");
        goto err;
    }

    strK = BN_bn2hex(K);
    if(strK == NULL)
    {
        ret = luaL_error(L, "Calc_client_key BN_bin2hex K failed");
        goto err;
    }

    lua_pushstring(L, strK);

err:
    BN_free(A);
    BN_free(B);
    BN_free(N);
    BN_free(s);
    BN_free(g);
    BN_free(a);
    BN_free(u);
    BN_free(x);
    BN_free(K);
    OPENSSL_free(strK);
    return ret;
};

static int srp_Calc_server_key(lua_State* L)
{
    if(lua_gettop(L) < 5)
    {
        return luaL_error(L, "Calc_server_key require A, B, N, v, b");
    }

    int ret = 1;
    BIGNUM* A = NULL;
    BIGNUM* B = NULL;
    BIGNUM* v = NULL;
    BIGNUM* b = NULL;
    BIGNUM* N = NULL;
    BIGNUM* u = NULL;
    BIGNUM* K = NULL;
    char* strK = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&A, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_server_key invalid A");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&B, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_server_key invalid B");
        goto err;
    }

    if(!lua_isstring(L, 3) || !BN_hex2bn(&N, lua_tostring(L, 3)))
    {
        ret = luaL_error(L, "Calc_server_key invalid N");
        goto err;
    }
	
    if(!lua_isstring(L, 4) || !BN_hex2bn(&v, lua_tostring(L, 4)))
    {
        ret = luaL_error(L, "Calc_server_key invalid v");
        goto err;
    }

    if(!lua_isstring(L, 5) || !BN_hex2bn(&b, lua_tostring(L, 5)))
    {
        ret = luaL_error(L, "Calc_server_key invalid b");
        goto err;
    }

    /* calculate u */
    u = SRP_Calc_u(A, B, N);
    if(u == NULL)
    {
        ret = luaL_error(L, "Calc_server_key SRP_Calc_u failed");
        goto err;
    }

    K = SRP_Calc_server_key(A, v, u, b, N);
    if(K == NULL)
    {
        ret = luaL_error(L, "Calc_server_key SRP_Calc_server_key failed");
        goto err;
    }

    strK = BN_bn2hex(K);
    if(strK == NULL)
    {
        ret = luaL_error(L, "Calc_server_key BN_bin2hex K failed");
        goto err;
    }

    lua_pushstring(L, strK);

err:
    BN_free(A);
    BN_free(B);
    BN_free(v);
    BN_free(b);
    BN_free(N);
    BN_free(u);
    BN_free(K);
    OPENSSL_free(strK);
    return ret;
};

BIGNUM* SRP_Calc_M1(BIGNUM* N, BIGNUM* g, const char* username, BIGNUM* s, BIGNUM* A, BIGNUM* B, BIGNUM* K)
{
    /* H[H(N) XOR H(g) | H(username) | s | A | B | K] */
    unsigned char* tmp = NULL;
    unsigned char dig[SHA_DIGEST_LENGTH];
    unsigned char digg[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;

    if((tmp = OPENSSL_malloc(BN_num_bytes(N))) == NULL)
    {
        return NULL;
    }

    // H(N)
    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    BN_bn2bin(N, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(N));
    EVP_DigestFinal_ex(&ctxt, dig, NULL);

    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    BN_bn2bin(g, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(g));
    EVP_DigestFinal_ex(&ctxt, digg, NULL);

    // H(N) ^ H(g)
    int i = 0;
    for(; i < SHA_DIGEST_LENGTH; ++i)
    {
        dig[i] ^= digg[i];
    }

    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctxt, dig, sizeof(dig));
    BN_bn2bin(s, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(s));
    BN_bn2bin(A, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(A));
    BN_bn2bin(B, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(B));
    BN_bn2bin(K, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(K));
    EVP_DigestFinal_ex(&ctxt, dig, NULL);
    EVP_MD_CTX_cleanup(&ctxt);

    OPENSSL_free(tmp);
    return BN_bin2bn(dig, sizeof(dig), NULL);
};

static int srp_Calc_M1(lua_State* L)
{
    /* BIGNUM* N, BIGNUM* g, const char* username, BIGNUM* s, BIGNUM* A, BIGNUM* B, BIGNUM* K */
    if(lua_gettop(L) < 7)
    {
        return luaL_error(L, "Calc_M1 require N, g, username, s, A, B, K");
    }

    int ret = 1;
    BIGNUM* M1 = NULL;
    BIGNUM* N = NULL;
    BIGNUM* g = BN_new();
    char username[4096] = {0};
    BIGNUM* s = NULL;
    BIGNUM* A = NULL;
    BIGNUM* B = NULL;
    BIGNUM* K = NULL;
    char* strM1 = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&N, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_M1 invalid N");
        goto err;
    }

    if(!lua_isnumber(L, 2) || !BN_set_word(g, lua_tonumber(L, 2)))
    {
        ret = luaL_error(L, "Calc_M1 invalid g");
        goto err;
    }

    if(!lua_isstring(L, 3))
    {
        ret = luaL_error(L, "Calc_M1 invalid username");
        goto err;
    }
    
    strncpy(username, lua_tostring(L, 3), sizeof(username));

    if(!lua_isstring(L, 4) || !BN_hex2bn(&s, lua_tostring(L, 4)))
    {
        ret = luaL_error(L, "Calc_M1 invalid s");
        goto err;
    }

    if(!lua_isstring(L, 5) || !BN_hex2bn(&A, lua_tostring(L, 5)))
    {
        ret = luaL_error(L, "Calc_M1 invalid A");
        goto err;
    }

    if(!lua_isstring(L, 6) || !BN_hex2bn(&B, lua_tostring(L, 6)))
    {
        ret = luaL_error(L, "Calc_M1 invalid B");
        goto err;
    }

    if(!lua_isstring(L, 7) || !BN_hex2bn(&K, lua_tostring(L, 7)))
    {
        ret = luaL_error(L, "Calc_M1 invalid K");
        goto err;
    }

    if((M1 = SRP_Calc_M1(N, g, username, s, A, B, K)) == NULL)
    {
        ret = luaL_error(L, "Calc_M1 SRP_Calc_M1 failed");
        goto err;
    }

    strM1 = BN_bn2hex(M1);
    if(strM1 == NULL)
    {
        ret = luaL_error(L, "Calc_M1 BN_bin2hex M1 failed");
        goto err;
    }

    lua_pushstring(L, strM1);

err:
    BN_free(M1);
    BN_free(N);
    BN_free(g);
    BN_free(s);
    BN_free(A);
    BN_free(B);
    BN_free(K);
    OPENSSL_free(strM1);
    return ret;
};

BIGNUM* SRP_Calc_M2(BIGNUM* A, BIGNUM* M1, BIGNUM* K)
{
    /* H(A | M1 | K) */
    unsigned char* tmp = NULL;
    unsigned char dig[SHA_DIGEST_LENGTH];
    EVP_MD_CTX ctxt;

    if((tmp = OPENSSL_malloc(BN_num_bytes(K))) == NULL)
    {
        return NULL;
    }

    EVP_MD_CTX_init(&ctxt);
    EVP_DigestInit_ex(&ctxt, EVP_sha1(), NULL);
    BN_bn2bin(A, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(A));
    BN_bn2bin(M1, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(M1));
    BN_bn2bin(K, tmp);
    EVP_DigestUpdate(&ctxt, tmp, BN_num_bytes(K));
    EVP_DigestFinal_ex(&ctxt, dig, NULL);
    EVP_MD_CTX_cleanup(&ctxt);

    OPENSSL_free(tmp);
    return BN_bin2bn(dig, sizeof(dig), NULL);
};

static int srp_Calc_M2(lua_State* L)
{
    /* BIGNUM* A, BIGNUM* M1, BIGNUM* K */
    if(lua_gettop(L) < 3)
    {
        return luaL_error(L, "Calc_M2 require A, M1, K");
    }

    int ret = 1;
    BIGNUM* M2 = NULL;
    BIGNUM* A = NULL;
    BIGNUM* M1 = NULL;
    BIGNUM* K = NULL;
    char* strM2 = NULL;

    if(!lua_isstring(L, 1) || !BN_hex2bn(&A, lua_tostring(L, 1)))
    {
        ret = luaL_error(L, "Calc_M2 invalid A");
        goto err;
    }

    if(!lua_isstring(L, 2) || !BN_hex2bn(&M1, lua_tostring(L, 2)))
    {
        ret = luaL_error(L, "Calc_M2 invalid M1");
        goto err;
    }

    if(!lua_isstring(L, 3) || !BN_hex2bn(&K, lua_tostring(L, 3)))
    {
        ret = luaL_error(L, "Calc_M2 invalid K");
        goto err;
    }

    if((M2 = SRP_Calc_M2(A, M1, K)) == NULL)
    {
        ret = luaL_error(L, "Calc_M2 SRP_Calc_M2 failed");
        goto err;
    }

    strM2 = BN_bn2hex(M2);
    if(strM2 == NULL)
    {
        ret = luaL_error(L, "Calc_M2 BN_bin2hex M2 failed");
        goto err;
    }

    lua_pushstring(L, strM2);

err:
    BN_free(M2);
    BN_free(A);
    BN_free(M1);
    BN_free(K);
    OPENSSL_free(strM2);
    return ret;
};

static const luaL_reg srp_lib[] = {
    { "get_default_gN", srp_get_default_gN },
    { "RAND_pseudo_bytes", srp_RAND_pseudo_bytes },
    { "Verify_mod_N", srp_Verify_mod_N },
    { "create_verifier", srp_create_verifier },
    { "Calc_A", srp_Calc_A },
    { "Calc_B", srp_Calc_B },
    { "Calc_client_key", srp_Calc_client_key },
    { "Calc_server_key", srp_Calc_server_key },
    { "Calc_M1", srp_Calc_M1 },
    { "Calc_M2", srp_Calc_M2 },
    { NULL, NULL }
};

int luaopen_srp(lua_State *L)
{
    luaL_register(L, "srp", srp_lib);
    return 1;
};




