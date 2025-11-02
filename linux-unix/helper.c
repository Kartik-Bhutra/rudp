#include "header.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <netinet/in.h> 


int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                const unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/**
 * Encrypts a payload struct into an output buffer.
 * Output buffer format: [16-byte IV][Ciphertext]
 */
int encrypt_payload_to_buffer(const quic_packet_payload_plain *payload, unsigned char *output_buffer, const unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE]; // 16 bytes
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        perror("RAND_bytes failed");
        return -1;
    }

    // Copy IV to the start of the output buffer
    memcpy(output_buffer, iv, AES_BLOCK_SIZE);

    // Encrypt payload struct into output buffer, offset by IV size
    int ciphertext_len = aes_encrypt((const unsigned char*)payload, sizeof(quic_packet_payload_plain),
                                     key, iv, output_buffer + AES_BLOCK_SIZE);

    if (ciphertext_len < 0) {
        fprintf(stderr, "aes_encrypt failed\n");
        return -1;
    }

    return AES_BLOCK_SIZE + ciphertext_len;
}

/**
 * Decrypts data from an input buffer into a payload struct.
 * Input buffer format: [16-byte IV][Ciphertext]
 */
int decrypt_buffer_to_payload(const unsigned char *input_buffer, int input_len, quic_packet_payload_plain *payload, const unsigned char *key)
{
    if (input_len <= AES_BLOCK_SIZE) {
        fprintf(stderr, "Decrypt error: input too short (len: %d)\n", input_len);
        return -1;
    }

    const unsigned char *iv = input_buffer;
    const unsigned char *ciphertext = input_buffer + AES_BLOCK_SIZE;
    int ciphertext_len = input_len - AES_BLOCK_SIZE;

    // Temp buffer for decrypted data
    unsigned char decrypted_buffer[sizeof(quic_packet_payload_plain) + AES_BLOCK_SIZE]; 
    int decrypted_len = aes_decrypt(ciphertext, ciphertext_len, key, iv, decrypted_buffer);

    if (decrypted_len < 0) {
        fprintf(stderr, "aes_decrypt failed\n");
        return -1;
    }
    
    if (decrypted_len != sizeof(quic_packet_payload_plain)) {
         fprintf(stderr, "Decrypt error: wrong size (got %d, expected %zu)\n",
                 decrypted_len, sizeof(quic_packet_payload_plain));
         return -1;
    }

    // Copy decrypted data into the payload struct
    memcpy(payload, decrypted_buffer, sizeof(quic_packet_payload_plain));
    return 0;
}