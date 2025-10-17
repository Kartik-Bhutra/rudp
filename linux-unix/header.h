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

#define CHUNK_SIZE 1024
#define PORT "8080"
#define SERVER_IP "127.0.0.1"
#define SERVER_DOMAIN "exampledomain.com"
#define BUFFER_SIZE 2048


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
} quic_packet_payload;

typedef struct {
    quic_packet_header header;
    quic_packet_payload payload;
} quic_packet;

// Function prototypes
extern void send_packet_server();
extern void send_packet_client();
extern void recieve_packet_server();
extern void take_client_ip(); 
extern void recieve_packet_client();
extern void send_certificate();
extern void recieve_packet_certificate_server();
extern int run_server();
extern int run_client();

#endif
