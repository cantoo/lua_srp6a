# lua_srp6a
Provide a shared library for lua which contains the openssl srp6a implemention. And add the calculation of M1, M2 which openssl do not provide.

Please run test_srp.lua to see the password verification process between client and server.

[Openresty](https://github.com/openresty/lua-nginx-module) is strongly recommended working with lua_srp6a, you will see how easily make a web server with openresty and how easily make a secure password verification with lua_srp6a.

# Reference:

[SRP6a wiki](https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol)

[SRP Protocol Design](http://srp.stanford.edu/design.html)

[RFC 2945](http://www.ietf.org/rfc/rfc2945.txt)

[Openssl SRP](https://github.com/openssl/openssl/tree/OpenSSL_1_0_2-stable/crypto/srp)


