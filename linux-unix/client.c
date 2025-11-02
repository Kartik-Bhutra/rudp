#include "header.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

static unsigned char symmetric_key[32]; 
static int handshake_complete = 0;

static int client_hello(int socket_peer, struct addrinfo *peer_address);
static int send_packet_client(int socket_peer, struct addrinfo *peer_address, char *filename);
static int verify_signature(EVP_PKEY *ca_pub_key, 
                            const unsigned char *data, size_t data_len,
                            const unsigned char *signature, size_t sig_len);

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

int run_client()
{
    openssl_init();
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *peer_address;
    if (getaddrinfo(SERVER_IP, "8080", &hints, &peer_address) != 0)
    {
        perror("getaddrinfo() failed");
        openssl_cleanup();
        return 1;
    }

    char address_buffer[100], service_buffer[100];
    if (getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
                    address_buffer, sizeof(address_buffer),
                    service_buffer, sizeof(service_buffer),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        printf("Remote address: %s:%s\n", address_buffer, service_buffer);
    }

    printf("Creating socket...\n");
    int socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer < 0)
    {
        perror("socket() failed");
        freeaddrinfo(peer_address);
        openssl_cleanup();
        return 1;
    }


    struct timeval timeout = {TIMEOUT_SEC, 0};
    if (setsockopt(socket_peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt() failed");
        freeaddrinfo(peer_address);
        close(socket_peer);
        openssl_cleanup();
        return 1;
    }
    
    printf("Performing handshake...\n");
    if (client_hello(socket_peer, peer_address) == 0) {
        fprintf(stderr, "Handshake failed.\n");
        freeaddrinfo(peer_address);
        close(socket_peer);
        openssl_cleanup();
        return 1;
    }

    char *filename = FILENAME;
    int result = send_packet_client(socket_peer, peer_address, filename);

    freeaddrinfo(peer_address);
    close(socket_peer);
    openssl_cleanup();
    return result;
}

static int client_hello(int socket_peer, struct addrinfo *peer_address){
    
    // --- 0) Load CA Public Key ---
    FILE *fp_ca = fopen("ca_pub.pem", "rb");
    if (!fp_ca) {
        perror("Failed to open ca_pub.pem");
        fprintf(stderr, "Please generate ca_pub.pem first.\n");
        return 0;
    }
    EVP_PKEY *ca_pub_key = PEM_read_PUBKEY(fp_ca, NULL, NULL, NULL);
    fclose(fp_ca);
    if (!ca_pub_key) {
        fprintf(stderr, "Failed to read CA public key from ca_pub.pem.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    printf("CA public key loaded.\n");

    // --- 1) Send ClientHello ---
    quic_packet initial;
    memset(&initial, 0, sizeof(initial));
    initial.header.packet_number = 0;
    initial.header.connection_id_start = 100;
    initial.header.connection_id_destination = 200;
    strcpy((char *)initial.payload_buffer ,"hello_server");
    initial.header.length = strlen("hello_server"); 
    
    ssize_t bytes_sent = sendto(socket_peer, &initial, sizeof(initial), 0,
                                        peer_address->ai_addr, peer_address->ai_addrlen);
    if (bytes_sent < 0)
    {
        perror("sendto(client_hello) failed");
        EVP_PKEY_free(ca_pub_key);
        return 0; 
    }
    printf("Sent %ld bytes. Waiting for SERVER HELLO (Certificate) \n", bytes_sent);

    // --- 2) Receive certificate from server ---
    quic_packet cert_packet;
    ssize_t bytes_received = recvfrom(socket_peer, &cert_packet, sizeof(cert_packet),
                                      0, NULL, NULL);

    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) printf("Timeout waiting for certificate.\n");
        else perror("recvfrom(cert) failed");
        EVP_PKEY_free(ca_pub_key);
        return 0;
    }

    // Check for packet_number 1 (cert)
    if (cert_packet.header.packet_number != 1) {
        fprintf(stderr, "Received unexpected packet (num:%d) instead of certificate.\n", cert_packet.header.packet_number);
        EVP_PKEY_free(ca_pub_key);
        return 0;
    }

    printf("Received certificate packet (cert size: %ld bytes)...\n", cert_packet.header.length);

    // --- 3) Extract public key AND signature from custom certificate ---
    unsigned char *cert_data = cert_packet.payload_buffer;
    size_t offset = MAX_SUBJECT_LEN + MAX_ISSUER_LEN;

    uint32_t n_pub_len;
    memcpy(&n_pub_len, cert_data + offset, sizeof(n_pub_len));
    offset += sizeof(n_pub_len);
    uint32_t pub_len = ntohl(n_pub_len);

    uint32_t n_sig_len;
    memcpy(&n_sig_len, cert_data + offset, sizeof(n_sig_len));
    offset += sizeof(n_sig_len);
    uint32_t sig_len = ntohl(n_sig_len);

    unsigned char *pubkey_pem = cert_data + offset;
    offset += pub_len; 
    unsigned char *signature = cert_data + offset; 

    printf("Verifying certificate signature (pubkey_len: %u, sig_len: %u)...\n", pub_len, sig_len);
    if (verify_signature(ca_pub_key, pubkey_pem, pub_len, signature, sig_len) != 0) {
        fprintf(stderr, "\n!!! CERTIFICATE VERIFICATION FAILED. Aborting handshake. !!!\n");
        EVP_PKEY_free(ca_pub_key);
        return 0;
    }
    printf("Verify: Signature is VALID.\n\n");
    EVP_PKEY_free(ca_pub_key); 

    char *pubkey_pem_null_terminated = malloc(pub_len + 1);
    if (!pubkey_pem_null_terminated) { perror("malloc"); return 0; }
    memcpy(pubkey_pem_null_terminated, pubkey_pem, pub_len);
    pubkey_pem_null_terminated[pub_len] = '\0';


    BIO *bio = BIO_new_mem_buf(pubkey_pem_null_terminated, pub_len);
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pubkey_pem_null_terminated);

    if (!pkey) {
        fprintf(stderr, "Failed to parse public key from certificate.\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }
    printf("Successfully parsed server public key.\n");

    // --- 4) Generate symmetric key and encrypt it (ClientKeyExchange) ---
    if (RAND_bytes(symmetric_key, 32) != 1) {
        perror("Failed to generate symmetric key");
        EVP_PKEY_free(pkey);
        return 0;
    }
    printf("Generated 256-bit symmetric key.\n");

    unsigned char encrypted_key[1024]; 
    size_t encrypted_key_len = 0;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0) {
         fprintf(stderr, "EVP_PKEY_encrypt_init failed.\n");
         ERR_print_errors_fp(stderr);
         EVP_PKEY_free(pkey);
         if(ctx) EVP_PKEY_CTX_free(ctx);
         return 0;
    }
    
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
         fprintf(stderr, "EVP_PKEY_CTX_set_rsa_padding failed.\n");
    }
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_oaep_md failed.\n");
    }
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) {
        fprintf(stderr, "EVP_PKEY_CTX_set_rsa_mgf1_md failed.\n");
    }

    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_key_len, symmetric_key, 32) <= 0) {
         fprintf(stderr, "EVP_PKEY_encrypt (size check) failed.\n");
         ERR_print_errors_fp(stderr);
    }

    if (encrypted_key_len > sizeof(encrypted_key)) {
         fprintf(stderr, "Encrypted key too large!\n");
    } else {
         if (EVP_PKEY_encrypt(ctx, encrypted_key, &encrypted_key_len, symmetric_key, 32) <= 0) {
              fprintf(stderr, "EVP_PKEY_encrypt failed.\n");
              ERR_print_errors_fp(stderr);
              encrypted_key_len = 0; 
         } else {
             printf("Symmetric key encrypted (%zu bytes).\n", encrypted_key_len);
         }
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    if (encrypted_key_len == 0) return 0; 

    // --- 5) Send encrypted key to server ---
    quic_packet key_packet;
    memset(&key_packet, 0, sizeof(key_packet));
    key_packet.header.packet_number = 2; 
    key_packet.header.connection_id_start = initial.header.connection_id_start;
    key_packet.header.connection_id_destination = initial.header.connection_id_destination;
    key_packet.header.length = encrypted_key_len;
    
    memcpy(key_packet.payload_buffer, encrypted_key, encrypted_key_len);

    bytes_sent = sendto(socket_peer, &key_packet, sizeof(key_packet), 0,
                        peer_address->ai_addr, peer_address->ai_addrlen);

    if (bytes_sent < 0) {
        perror("sendto(key_packet) failed");
        return 0;
    }

    // --- 6) Wait for server's encrypted ACK ---
    printf("Waiting for server KEY-ACK...\n");
    quic_packet key_ack;
    bytes_received = recvfrom(socket_peer, &key_ack, sizeof(key_ack), 0, NULL, NULL);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) printf("Timeout waiting for KEY-ACK.\n");
        else perror("recvfrom(key_ack) failed");
        return 0;
    }
    
    quic_packet_payload_plain ack_payload;
    if (decrypt_buffer_to_payload(key_ack.payload_buffer, key_ack.header.length, &ack_payload, symmetric_key) != 0) {
        fprintf(stderr, "Failed to decrypt server's KEY-ACK.\n");
        return 0;
    }

    // Check for ACK flag and the "KEY_ACK_OK" string
    if (ack_payload.ack == 1 && strcmp((char*)ack_payload.data, "KEY_ACK_OK") == 0) {
        printf("Server ACKed symmetric key. Handshake complete!\n");
        handshake_complete = 1;
        return 1;
    } else {
        fprintf(stderr, "Received invalid ACK for key packet (id:%d, ack:%d).\n",
                ack_payload.id, ack_payload.ack);
        return 0;
    }
}

int send_packet_client(int socket_peer, struct addrinfo *peer_address, char *filename)
{
    if (!handshake_complete) {
        fprintf(stderr, "Cannot send file: handshake not complete.\n");
        return 1;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror("Failed to open file");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fclose(fp); 

    int total_packets = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;
    printf("File size: %ld bytes, Total packets: %d\n", file_size, total_packets);
    

    for (int packet_number = 1; packet_number <= total_packets; packet_number++)
    {
        int ack_received = 0;

        // --- 1. Build the *plaintext* payload ---
        quic_packet_payload_plain payload_plain;
        memset(&payload_plain, 0, sizeof(payload_plain));
        payload_plain.ack = 0;
        payload_plain.id = packet_number;
        payload_plain.total_packet = total_packets;
        
        FILE *fp_chunk = fopen(filename, "rb");
        if (!fp_chunk) { perror("File open failed"); return 1; }
        long offset = (packet_number - 1) * CHUNK_SIZE;
        fseek(fp_chunk, offset, SEEK_SET);
        size_t bytesRead = fread(payload_plain.data, 1, CHUNK_SIZE, fp_chunk);
        fclose(fp_chunk);
        if (bytesRead <= 0) {
            fprintf(stderr, "File read error for packet %d\n", packet_number);
            return 1;
        }

        // --- 2. Encrypt the payload ---
        unsigned char encrypted_buf[sizeof(quic_packet_payload_plain) + AES_BLOCK_SIZE * 2];
        int encrypted_len = encrypt_payload_to_buffer(&payload_plain, encrypted_buf, symmetric_key);

        quic_packet packet; // Need this to get sizeof
        if (encrypted_len < 0 || encrypted_len > sizeof(packet.payload_buffer)) {
            fprintf(stderr, "Failed to encrypt packet #%d or ciphertext too large (%d)\n",
                    packet_number, encrypted_len);
            return 1;
        }
        
        // --- 3. Build the final packet ---
        memset(&packet, 0, sizeof(packet));
        packet.header.packet_number = packet_number + 100; // Use a different range for data
        packet.header.connection_id_start = 100;
        packet.header.connection_id_destination = 200;
        packet.header.length = encrypted_len;
        
        memcpy(packet.payload_buffer, encrypted_buf, encrypted_len);


        for (int attempt = 0; attempt < MAX_RETRIES && !ack_received; attempt++)
        {
            printf("\n[Attempt %d] Sending packet #%d/%d... (encrypted, %d bytes)\n",
                   attempt + 1, packet_number, total_packets, encrypted_len);

            ssize_t bytes_sent = sendto(socket_peer, &packet, sizeof(packet), 0,
                                        peer_address->ai_addr, peer_address->ai_addrlen);

            if (bytes_sent < 0)
            {
                perror("sendto() failed");
                continue;
            }

            printf("Sent %ld bytes. Waiting for ACK...\n", bytes_sent);

            quic_packet ack_packet;
            ssize_t bytes_received = recvfrom(socket_peer, &ack_packet, sizeof(ack_packet),
                                              0, NULL, NULL);

            if (bytes_received < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    printf("Timeout waiting for ACK.\n");
                else
                    perror("recvfrom() failed");
            }
            else 
            {
                // --- 4. DECRYPT ACK ---
                quic_packet_payload_plain ack_payload;
                if (decrypt_buffer_to_payload(ack_packet.payload_buffer, ack_packet.header.length, &ack_payload, symmetric_key) != 0) {
                    fprintf(stderr, "Failed to decrypt ACK for packet #%d\n", packet_number);
                    continue; 
                }

                if (ack_payload.ack == 1 &&
                     ack_payload.id == packet_number)
                {
                    printf("ACK received for packet #%d \n", packet_number);
                    ack_received = 1;
                }
                else
                {
                    printf("Received wrong ACK (id:%d, ack:%d)\n", ack_payload.id, ack_payload.ack);
                }
            }
        }

        if (!ack_received)
        {
            fprintf(stderr, "Failed to receive ACK for packet #%d after %d attempts.\n",
                    packet_number, MAX_RETRIES);
            return 1;
        }
    }

    printf("\n File \"%s\" successfully sent!\n", filename);
    return 0;
}

static int verify_signature(EVP_PKEY *ca_pub_key, 
                            const unsigned char *data, size_t data_len,
                            const unsigned char *signature, size_t sig_len)
{
    int ret = -1; 
    EVP_MD_CTX *mdctx = NULL;

    mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto done;

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, ca_pub_key) <= 0) {
        fprintf(stderr, "Verify: EVP_DigestVerifyInit failed.\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    if (EVP_DigestVerifyUpdate(mdctx, data, data_len) <= 0) {
        fprintf(stderr, "Verify: EVP_DigestVerifyUpdate failed.\n");
        ERR_print_errors_fp(stderr);
        goto done;
    }

    ret = EVP_DigestVerifyFinal(mdctx, signature, sig_len);
    if (ret == 1) {
        // Signature is valid
    } else if (ret == 0) {
        fprintf(stderr, "Verify: Signature is INVALID.\n");
        ret = -1; 
    } else {
        fprintf(stderr, "Verify: EVP_DigestVerifyFinal failed (error < 0).\n");
        ERR_print_errors_fp(stderr);
        ret = -1; 
    }

done:
    if (mdctx) EVP_MD_CTX_free(mdctx);
    return (ret == 1) ? 0 : -1; // Return 0 on success, -1 on failure
}