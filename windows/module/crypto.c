#include "header.h"

int base64_decode(const char *b64_string, unsigned char **output, size_t *output_len)
{
    size_t len = strlen(b64_string);
    *output = malloc(len);
    if (!*output)
        return 0;

    *output_len = EVP_DecodeBlock(*output, (const unsigned char *)b64_string, len);
    if (*output_len == -1)
    {
        free(*output);
        return 0;
    }
    return 1;
}

EVP_PKEY *load_private_key_from_file(const char *filename)
{
    EVP_PKEY *pkey = NULL;
    BIO *bio = NULL;

    bio = BIO_new_file(filename, "r");
    if (!bio)
    {
        fprintf(stderr, "Failed to open file for reading: %s\n", filename);
        return NULL;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (!pkey)
    {
        fprintf(stderr, "Failed to read private key from file: %s\n", filename);
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);

    return pkey;
}

int sign_data_robust(EVP_PKEY *pkey, const unsigned char *data, size_t data_len, unsigned char **signature, size_t *sig_len)
{

    *signature = NULL;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new failed.\n");
        return 0;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) != 1)
    {
        fprintf(stderr, "ERROR: EVP_DigestSignInit failed.\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (EVP_DigestSign(md_ctx, NULL, sig_len, data, data_len) != 1)
    {
        fprintf(stderr, "ERROR: Failed to determine signature size.\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    *signature = malloc(*sig_len);
    if (!*signature)
    {
        fprintf(stderr, "ERROR: malloc failed for signature buffer.\n");
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    if (EVP_DigestSign(md_ctx, *signature, sig_len, data, data_len) != 1)
    {
        fprintf(stderr, "ERROR: EVP_DigestSign failed.\n");
        ERR_print_errors_fp(stderr);
        free(*signature);
        *signature = NULL;
        EVP_MD_CTX_free(md_ctx);
        return 0;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1;
}