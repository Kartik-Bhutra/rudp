#include "header.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <arpa/inet.h>

#define CA_PRIVKEY_FILE "ca_key.pem"
#define CA_NAME "Simple-CA"

static void openssl_init()
{
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

static void openssl_cleanup()
{
    EVP_cleanup();
    ERR_free_strings();
}

static int sign_data(EVP_PKEY *pkey, const unsigned char *data, size_t data_len,
                     unsigned char **sig, size_t *sig_len)
{
    int ret = -1;
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto done;

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) goto done;
    if (EVP_DigestSignUpdate(mdctx, data, data_len) <= 0) goto done;

    if (EVP_DigestSignFinal(mdctx, NULL, sig_len) <= 0) goto done;

    *sig = OPENSSL_malloc(*sig_len);
    if (!*sig) goto done;

    if (EVP_DigestSignFinal(mdctx, *sig, sig_len) <= 0) {
        OPENSSL_free(*sig);
        *sig = NULL;
        goto done;
    }
    ret = 0;

done:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return ret;
}

int run_certificate_server()
{
    openssl_init();
    printf("Certificate CA server starting (simple CA)...\n");

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo *bind_address;
    if (getaddrinfo(NULL, CERTIFICATE_SERVER_PORT, &hints, &bind_address) != 0) {
        perror("getaddrinfo failed");
        openssl_cleanup();
        return 1;
    }

    int socket_listen = socket(bind_address->ai_family,
                               bind_address->ai_socktype,
                               bind_address->ai_protocol);
    if (socket_listen < 0) {
        perror("socket failed");
        freeaddrinfo(bind_address);
        openssl_cleanup();
        return 1;
    }

    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen) != 0) {
        perror("bind failed");
        freeaddrinfo(bind_address);
        close(socket_listen);
        openssl_cleanup();
        return 1;
    }

    freeaddrinfo(bind_address);
    printf("CA socket bound. Listening for PUBKEY packets...\n\n");

    FILE *fp = fopen(CA_PRIVKEY_FILE, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open CA private key file '%s'\n", CA_PRIVKEY_FILE);
        close(socket_listen);
        openssl_cleanup();
        return 1;
    }
    EVP_PKEY *ca_pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!ca_pkey) {
        fprintf(stderr, "Failed to read CA private key from '%s'\n", CA_PRIVKEY_FILE);
        ERR_print_errors_fp(stderr);
        close(socket_listen);
        openssl_cleanup();
        return 1;
    }

    while (1) {
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        quic_packet received_packet;

        ssize_t bytes_received = recvfrom(socket_listen,
                                          &received_packet,
                                          sizeof(received_packet),
                                          0,
                                          (struct sockaddr *)&client_address,
                                          &client_len);

        if (bytes_received < 0) {
            perror("recvfrom failed");
            continue;
        }

        char address_buffer[100];
        char service_buffer[100];
        if (getnameinfo((struct sockaddr *)&client_address,
                        client_len,
                        address_buffer, sizeof(address_buffer),
                        service_buffer, sizeof(service_buffer),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {

            printf("Received %ld bytes from %s %s\n", bytes_received, address_buffer, service_buffer);
        }

        const char *prefix = "PUBKEY:";
        if (strncmp((char *)received_packet.payload_buffer, prefix, strlen(prefix)) != 0) {
            printf("Not a PUBKEY request -> ignoring\n");
            continue;
        }

        unsigned char *pubkey_pem = received_packet.payload_buffer + strlen(prefix);
        size_t pubkey_pem_len = strnlen((char *)pubkey_pem, CHUNK_SIZE - strlen(prefix));
        if (pubkey_pem_len == 0) {
            fprintf(stderr, "Empty public key payload\n");
            continue;
        }

        printf("CA: received server public key PEM (%zu bytes). Signing...\n", pubkey_pem_len);

        unsigned char *signature = NULL;
        size_t sig_len = 0;
        if (sign_data(ca_pkey, pubkey_pem, pubkey_pem_len, &signature, &sig_len) != 0) {
            fprintf(stderr, "Failed to sign public key\n");
            ERR_print_errors_fp(stderr);
            continue;
        }

        // Use a large buffer to build the cert
        unsigned char cert_buf[BUFFER_SIZE];
        memset(cert_buf, 0, sizeof(cert_buf));
        size_t offset = 0;

        strncpy((char *)(cert_buf + offset), SERVER_DOMAIN, MAX_SUBJECT_LEN-1);
        offset += MAX_SUBJECT_LEN;
        strncpy((char *)(cert_buf + offset), CA_NAME, MAX_ISSUER_LEN-1);
        offset += MAX_ISSUER_LEN;

        uint32_t n_pub_len = htonl((uint32_t)pubkey_pem_len);
        memcpy(cert_buf + offset, &n_pub_len, sizeof(n_pub_len));
        offset += sizeof(n_pub_len);

        uint32_t n_sig_len = htonl((uint32_t)sig_len);
        memcpy(cert_buf + offset, &n_sig_len, sizeof(n_sig_len));
        offset += sizeof(n_sig_len);

        quic_packet cert_packet; // Need this for sizeof
        if (offset + pubkey_pem_len + sig_len > sizeof(cert_packet.payload_buffer)) {
            fprintf(stderr, "Certificate would exceed packet payload size (%zu bytes needed)\n",
                    offset + pubkey_pem_len + sig_len);
            OPENSSL_free(signature);
            continue;
        }

        memcpy(cert_buf + offset, pubkey_pem, pubkey_pem_len);
        offset += pubkey_pem_len;
        memcpy(cert_buf + offset, signature, sig_len);
        offset += sig_len;

        OPENSSL_free(signature);
        
        memset(&cert_packet, 0, sizeof(cert_packet));
        cert_packet.header.packet_number = 1; // PUBKEY request was 0 (from client)
        cert_packet.header.connection_id_start = received_packet.header.connection_id_destination;
        cert_packet.header.connection_id_destination = received_packet.header.connection_id_start;
        cert_packet.header.length = offset;

        memcpy(cert_packet.payload_buffer, cert_buf, offset);

        printf("CA: sending signed certificate (%zu bytes) back to requester\n", offset);
        ssize_t s = sendto(socket_listen,
                           &cert_packet, sizeof(cert_packet),
                           0,
                           (struct sockaddr *)&client_address, client_len);
        if (s < 0) {
            perror("sendto failed");
        }
    }

    EVP_PKEY_free(ca_pkey);
    close(socket_listen);
    openssl_cleanup();
    return 0;
}