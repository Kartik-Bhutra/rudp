#ifndef MY_HEADER_H
#define MY_HEADER_H
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ec.h>

int initWin();

int createServer(SOCKET *pSocketListen, PCSTR pServiceName);

int createClient(SOCKET *pSocketPeer, PCSTR pNodeName, PCSTR pServiceName, struct addrinfo **ppPeerAddress);

int base64_decode(const char *b64_string, unsigned char **output, size_t *output_len);

EVP_PKEY *load_private_key_from_file(const char *filename);

int sign_data(EVP_PKEY *pkey, const unsigned char *data, size_t data_len, unsigned char **signature, size_t *sig_len);