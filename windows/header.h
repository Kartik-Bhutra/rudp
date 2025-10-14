#ifndef MY_HEADER_H
#define MY_HEADER_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifndef MAX_UDP_MESSAGE_SIZE
#define MAX_UDP_MESSAGE_SIZE 1024
#endif

#ifndef TIMEOUT_MS
#define TIMEOUT_MS 2000
#endif

#ifndef MAX_RETRIES
#define MAX_RETRIES 3
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>

int run_server();
int run_client();

struct udp_packet
{
    char data[MAX_UDP_MESSAGE_SIZE];
    int sequence_no;
};

#endif