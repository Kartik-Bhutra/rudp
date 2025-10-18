#include "header.h"

int run_client()
{
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *peer_address;
    if (getaddrinfo(SERVER_IP, "8080", &hints, &peer_address) != 0)
    {
        perror("getaddrinfo() failed");
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
        return 1;
    }


    struct timeval timeout = {TIMEOUT_SEC, 0};
    if (setsockopt(socket_peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt() failed");
        freeaddrinfo(peer_address);
        close(socket_peer);
        return 1;
    }

    char *filename = FILENAME;

    int result = send_packet_client(socket_peer, peer_address, filename);

    freeaddrinfo(peer_address);
    close(socket_peer);
    return result;
}
