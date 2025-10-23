# include "header.h"

quic_packet build_ack(quic_packet_payload_plain received_packet){
    quic_packet_payload_plain ack_packet;
    ack_packet.header.packet_number = received_packet.header.packet_number;
    ack_packet.header.connection_id_start = received_packet.header.connection_id_destination;
    ack_packet.header.connection_id_destination = received_packet.header.connection_id_start;
    ack_packet.header.length = sizeof(ack_packet.payload);
    ack_packet.payload.ack = 1;
    ack_packet.payload.id = received_packet.payload.id;
    ack_packet.payload.total_packet = received_packet.payload.total_packet;
    memset(ack_packet.payload.data, 0, CHUNK_SIZE);
    strcpy((char *)ack_packet.payload.data, "ACK");
    return ack_packet;
}

quic_packet build_packet_from_file(char *filename, int packet_number, int total_packets)
{
    quic_packet packet;
    packet.header.packet_number = packet_number;
    packet.header.connection_id_start = 100;
    packet.header.connection_id_destination = 200;
    packet.header.length = sizeof(packet.payload);
    packet.payload.ack = 0;
    packet.payload.id = packet_number;
    packet.payload.total_packet = total_packets;

    memset(packet.payload.data, 0, CHUNK_SIZE);

    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        perror("File open failed");
        return packet;
    }

    long offset = (packet_number - 1) * CHUNK_SIZE;
    fseek(fp, offset, SEEK_SET);

    size_t bytesRead = fread(packet.payload.data, 1, CHUNK_SIZE, fp);
    fclose(fp);

    //printf("Built packet #%d (%zu bytes)\n", packet_number, bytesRead);
    return packet;
}

int send_packet_client(int socket_peer, struct addrinfo *peer_address, char *filename)
{
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
    // make a handshake 
    // send server client hello and recieve the certificate and then use the use server public key to send the 
    // symmetric key and continue the transmission with all data encrypted via symmetric key
    

    for (int packet_number = 1; packet_number <= total_packets; packet_number++)
    {
        int ack_received = 0;

        for (int attempt = 0; attempt < MAX_RETRIES && !ack_received; attempt++)
        {
            quic_packet packet = build_packet_from_file(filename, packet_number, total_packets);

            printf("\n[Attempt %d] Sending packet #%d/%d...\n",
                   attempt + 1, packet_number, total_packets);

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
            else if (ack_packet.payload.ack == 1 &&
                     ack_packet.payload.id == packet_number)
            {
                printf("ACK received for packet #%d \n", packet_number);
                ack_received = 1;
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

int client_hello(int socket_peer, struct addrinfo *peer_address){
    quic_packet initial;
    initial.header.packet_number = 0;
    initial.header.connection_id_start = 100;
    initial.header.connection_id_destination = 200;
    initial.header.length = sizeof(initial.payload);
    strcpy(initial.payload.data ,"hello_server");
    initial.payload.id = -1;
    initial.payload.total_packet = 1;
    initial.payload.ack = 0; 
    ssize_t bytes_sent = sendto(socket_peer, &initial, sizeof(initial), 0,
                                        peer_address->ai_addr, peer_address->ai_addrlen);
    if (bytes_sent < 0)
        {
            perror("sendto() failed");
            return 0; 
        }
    printf("Sent %ld bytes. Waiting for SERVER HELLO \n", bytes_sent);
    // certificate to be recieved 
    return 1;
}


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


int encrypt_payload_to_buffer(const quic_packet_payload_plain *payload, unsigned char *output_buffer, const unsigned char *key)
{
    unsigned char iv[AES_BLOCK_SIZE]; // 16 bytes
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        perror("RAND_bytes failed");
        return -1;
    }
    memcpy(output_buffer, iv, AES_BLOCK_SIZE);
    int ciphertext_len = aes_encrypt((const unsigned char*)payload, sizeof(quic_packet_payload_plain),
                                     key, iv, output_buffer + AES_BLOCK_SIZE);

    if (ciphertext_len < 0) {
        fprintf(stderr, "aes_encrypt failed\n");
        return -1;
    }

    return AES_BLOCK_SIZE + ciphertext_len;
}
int decrypt_buffer_to_payload(const unsigned char *input_buffer, int input_len, quic_packet_payload_plain *payload, const unsigned char *key)
{
    if (input_len <= AES_BLOCK_SIZE) {
        fprintf(stderr, "Decrypt error: input too short (len: %d)\n", input_len);
        return -1;
    }
    const unsigned char *iv = input_buffer;
    const unsigned char *ciphertext = input_buffer + AES_BLOCK_SIZE;
    int ciphertext_len = input_len - AES_BLOCK_SIZE;

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
    memcpy(payload, decrypted_buffer, sizeof(quic_packet_payload_plain));
    return 0;
}