#include "header.h"

int main()
{
    if (initWin())
        return 1;

    EVP_PKEY *server_pkey = load_private_key_from_file("private_key_ed25519.pem");
    if (!server_pkey)
    {
        fprintf(stderr, "Failed to load private key from file.\n");
        WSACleanup();
        return 1;
    }
    printf("Server private key loaded successfully from file.\n");

    EVP_PKEY_free(server_pkey);
    WSACleanup();
    return 0;
}