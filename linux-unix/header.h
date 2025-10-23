#ifndef HEADER_H
#define HEADER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <netdb.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <netinet/in.h>

#define CHUNK_SIZE 1024
#define PORT "8080"
#define SERVER_IP "127.0.0.1"
#define CERTIFICATE_SERVER_IP "127.0.0.1"
#define CERTIFICATE_SERVER_PORT "8081"
#define SERVER_DOMAIN "exampledomain.com"
#define BUFFER_SIZE 2048
#define FILENAME "test.txt"

#define MAX_RETRIES 5
#define TIMEOUT_SEC 2  // timeout in seconds


typedef struct {
    int packet_number;           // field to be encrypted 
    int connection_id_start;
    int connection_id_destination;
    long length;                 // field to be encrypted
} quic_packet_header;

typedef struct {
    int ack;
    int id;
    int total_packet; 
    unsigned char data[CHUNK_SIZE];  // raw data chunk
} quic_packet_payload_plain;

typedef struct {
    quic_packet_header header;
    // 16 (IV) + 1036 (struct) + 4 (padding) = 1056 bytes.
    unsigned char payload_buffer[1060];
} quic_packet;


// Function prototypes
extern void send_packet_server();
extern int send_packet_client(int socket_peer, struct addrinfo *peer_address, char *filename);
extern void recieve_packet_server();
extern void take_client_ip(); 
extern void recieve_packet_client();
extern void send_certificate();
extern void recieve_packet_certificate_server();
extern int run_server();
extern int run_client();
extern quic_packet build_ack(quic_packet recieve_packet_client);
extern quic_packet build_packet_from_file(char *filename, int packet_number, int total_packets);
extern int aes_encrypt(const unsigned char *plaintext, int plaintext_len, const unsigned char *key,
                       const unsigned char *iv, unsigned char *ciphertext);

extern int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key,
                       const unsigned char *iv, unsigned char *plaintext);

extern int encrypt_payload_to_buffer(const quic_packet_payload_plain *payload, unsigned char *output_buffer, const unsigned char *key);
extern int decrypt_buffer_to_payload(const unsigned char *input_buffer, int input_len, quic_packet_payload_plain *payload, const unsigned char *key);

#endif
