#include "header.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

static unsigned char symmetric_key[32];
static int handshake_complete = 0;
static EVP_PKEY *server_pkey = NULL; 

static void openssl_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}
static void openssl_cleanup() {
    if (server_pkey) EVP_PKEY_free(server_pkey);
    EVP_cleanup();
    ERR_free_strings();
}


quic_packet build_ack_encrypted(quic_packet received_packet, quic_packet_payload_plain *decrypted_payload)
{
    // 1. Build the plaintext payload for the ACK
    quic_packet_payload_plain ack_payload_plain;
    memset(&ack_payload_plain, 0, sizeof(ack_payload_plain));
    ack_payload_plain.ack = 1;
    ack_payload_plain.id = decrypted_payload->id;
    ack_payload_plain.total_packet = decrypted_payload->total_packet;
    strcpy((char *)ack_payload_plain.data, "ACK");

    // 2. Encrypt the plaintext ACK payload
    unsigned char encrypted_buf[sizeof(quic_packet_payload_plain) + AES_BLOCK_SIZE * 2];
    int encrypted_len = encrypt_payload_to_buffer(&ack_payload_plain, encrypted_buf, symmetric_key);
    
    // 3. Build the final packet structure
    quic_packet ack_packet;
    memset(&ack_packet, 0, sizeof(ack_packet));
    ack_packet.header.packet_number = received_packet.header.packet_number;
    ack_packet.header.connection_id_start = received_packet.header.connection_id_destination;
    ack_packet.header.connection_id_destination = received_packet.header.connection_id_start;
    
    if (encrypted_len < 0 || encrypted_len > sizeof(ack_packet.payload_buffer)) {
        fprintf(stderr, "Failed to encrypt ACK payload or ciphertext too large (%d)\n", encrypted_len);
        ack_packet.header.length = 0;
    } else {
        ack_packet.header.length = encrypted_len;
        memcpy(ack_packet.payload_buffer, encrypted_buf, encrypted_len);
    }
    
    return ack_packet;
}


int run_server()
{
    openssl_init();

    printf("Configuring local address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    if (getaddrinfo(NULL, PORT, &hints, &bind_address) != 0)
    {
        perror("getaddrinfo() failed");
        openssl_cleanup();
        return 1;
    }

    printf("Creating socket...\n");
    int socket_listen = socket(bind_address->ai_family,
                               bind_address->ai_socktype, bind_address->ai_protocol);
    if (socket_listen < 0)
    {
        perror("socket() failed");
        freeaddrinfo(bind_address);
        openssl_cleanup();
        return 1;
    }

    printf("Binding socket to local address...\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen) != 0)
    {
        perror("bind() failed");
        freeaddrinfo(bind_address);
        close(socket_listen);
        openssl_cleanup();
        return 1;
    }
    freeaddrinfo(bind_address);

    FILE *fp_key = fopen("server_key.pem", "rb"); 
    if (!fp_key) {
        perror("Failed to open server_key.pem");
        fprintf(stderr, "Please generate server_key.pem first.\n");
        openssl_cleanup();
        return 1;
    }
    server_pkey = PEM_read_PrivateKey(fp_key, NULL, NULL, NULL);
    fclose(fp_key);
    if (!server_pkey) {
        fprintf(stderr, "Failed to read server private key from server_key.pem.\n");
        ERR_print_errors_fp(stderr);
        openssl_cleanup();
        return 1;
    }
    printf("Server private key loaded.\n");

    printf("Socket binded. Listening for packets...\n\n");

    while (1)
    {
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        quic_packet received_packet; // This is the new, larger struct

        ssize_t bytes_received = recvfrom(socket_listen,
                                          &received_packet,
                                          sizeof(received_packet),
                                          0,
                                          (struct sockaddr *)&client_address, &client_len);

        if (bytes_received < 0) {
            perror("recvfrom() failed");
            continue;
        }

        char address_buffer[100], service_buffer[100];
        if (getnameinfo((struct sockaddr *)&client_address, client_len,
                        address_buffer, sizeof(address_buffer),
                        service_buffer, sizeof(service_buffer),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            printf("Received %ld bytes from %s %s\n", bytes_received, address_buffer, service_buffer);
        }


        if (handshake_complete)
        {
            // --- CASE 1: Encrypted Data Packet ---
            quic_packet_payload_plain payload_plain;
            if (decrypt_buffer_to_payload(received_packet.payload_buffer, received_packet.header.length, &payload_plain, symmetric_key) != 0)
            {
                fprintf(stderr, "Failed to decrypt packet from %s\n", address_buffer);
                continue;
            }
            
            printf("Decrypted packet: ID: %d, ACK: %d, Total: %d\n",
                   payload_plain.id, payload_plain.ack, payload_plain.total_packet);

            quic_packet ack_packet = build_ack_encrypted(received_packet, &payload_plain);
            
            printf("<- Sending Encrypted ACK (for Packet: %d) back to client...\n\n",
                   payload_plain.id);

            ssize_t bytes_sent = sendto(socket_listen, &ack_packet, sizeof(ack_packet),
                                        0, (struct sockaddr *)&client_address, client_len);
            if (bytes_sent < 0) perror("sendto(enc_ack) failed");

        }
        else
        {
            // --- CASE 2: Handshake In Progress ---
            
            // Check for ClientHello
            if (strcmp((char*)received_packet.payload_buffer ,"hello_server") == 0)
            {
                printf("Handshake init: client said hello\n");

                FILE *fp = fopen("server_cert.pem", "rb");
                if(!fp){
                    perror("cannot open server_cert.pem");
                    fprintf(stderr, "Please generate server_cert.pem using the certificate_server first.\n");
                    continue;
                }
                fseek(fp,0,SEEK_END);
                long cert_size = ftell(fp);
                rewind(fp);

                quic_packet cert_packet; // Need this for sizeof
                if (cert_size > sizeof(cert_packet.payload_buffer)) {
                    fprintf(stderr, "Certificate is too large (%ld) for packet buffer (%zu).\n",
                            cert_size, sizeof(cert_packet.payload_buffer));
                    fclose(fp);
                    continue;
                }

                unsigned char *cert_buf = malloc(cert_size);
                if (!cert_buf) { perror("malloc cert_buf failed"); fclose(fp); continue; }
                fread(cert_buf,1,cert_size,fp);
                fclose(fp);
                
                memset(&cert_packet,0,sizeof(cert_packet));
                cert_packet.header.packet_number = 1; // Hello was 0
                cert_packet.header.connection_id_start = received_packet.header.connection_id_destination;
                cert_packet.header.connection_id_destination = received_packet.header.connection_id_start;
                cert_packet.header.length = cert_size;

                memcpy(cert_packet.payload_buffer, cert_buf, cert_size);
                free(cert_buf);

                printf("<- Sending certificate to client (%ld bytes)...\n", cert_size);
                ssize_t s = sendto(socket_listen,&cert_packet,sizeof(cert_packet),0,
                                   (struct sockaddr *)&client_address,client_len);
                if(s<0) perror("send cert failed");
                
                continue; 
            }
            
            // Check for ClientKeyExchange (packet_number 2)
            if (received_packet.header.packet_number == 2)
            {
                printf("Handshake: Received ClientKeyExchange (encrypted symmetric key)...\n");
                
                unsigned char *encrypted_key = received_packet.payload_buffer;
                int encrypted_key_len = received_packet.header.length;
                
                unsigned char decrypted_key[256]; 
                size_t decrypted_key_len = 0;
                
                EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_pkey, NULL);
                if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0) {
                     fprintf(stderr, "EVP_PKEY_decrypt_init failed.\n");
                     ERR_print_errors_fp(stderr);
                     if (ctx) EVP_PKEY_CTX_free(ctx);
                     continue;
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

                if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_key_len, encrypted_key, encrypted_key_len) <= 0) {
                     fprintf(stderr, "EVP_PKEY_decrypt (size check) failed.\n");
                     ERR_print_errors_fp(stderr);
                }
                
                if (decrypted_key_len > sizeof(decrypted_key)) {
                     fprintf(stderr, "Decrypted key too large!\n");
                } else {
                     if (EVP_PKEY_decrypt(ctx, decrypted_key, &decrypted_key_len, encrypted_key, encrypted_key_len) <= 0) {
                          fprintf(stderr, "EVP_PKEY_decrypt failed.\n");
                          ERR_print_errors_fp(stderr);
                          decrypted_key_len = 0;
                     }
                }
                EVP_PKEY_CTX_free(ctx);
                
                if (decrypted_key_len != 32) {
                    fprintf(stderr, "Decrypted key is not 32 bytes (got %zu). Handshake failed.\n", decrypted_key_len);
                    continue;
                }
                
                memcpy(symmetric_key, decrypted_key, 32);
                handshake_complete = 1;
                printf("Successfully decrypted symmetric key. Handshake complete!\n");
                
                // --- Send Encrypted ACK for KeyExchange ---
                quic_packet_payload_plain ack_payload;
                memset(&ack_payload, 0, sizeof(ack_payload));
                ack_payload.ack = 1;
                ack_payload.id = -2; // Special ID for key ACK
                ack_payload.total_packet = 1;
                strcpy((char*)ack_payload.data, "KEY_ACK_OK");

                quic_packet ack_packet;
                memset(&ack_packet, 0, sizeof(ack_packet));
                ack_packet.header.packet_number = received_packet.header.packet_number + 1;
                ack_packet.header.connection_id_start = received_packet.header.connection_id_destination;
                ack_packet.header.connection_id_destination = received_packet.header.connection_id_start;
                
                unsigned char enc_buf[sizeof(quic_packet_payload_plain) + AES_BLOCK_SIZE * 2];
                int enc_len = encrypt_payload_to_buffer(&ack_payload, enc_buf, symmetric_key);
                
                if (enc_len < 0 || enc_len > sizeof(ack_packet.payload_buffer)) {
                     fprintf(stderr, "Failed to encrypt KEY-ACK or ciphertext too large (%d)\n", enc_len);
                     continue;
                }
                
                ack_packet.header.length = enc_len;
                memcpy(ack_packet.payload_buffer, enc_buf, enc_len);

                printf("<- Sending Encrypted KEY-ACK...\n\n");
                ssize_t s = sendto(socket_listen, &ack_packet, sizeof(ack_packet), 0,
                                   (struct sockaddr *)&client_address, client_len);
                if (s < 0) perror("sendto(key-ack) failed");
            }
        } 
    } 

    close(socket_listen);
    openssl_cleanup();
    return 0;
}