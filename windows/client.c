#include "header.h"

int run_client()
{
    printf("Configuring remote address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *peer_address;
    if (getaddrinfo("127.0.0.1", "8080", &hints, &peer_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", WSAGetLastError());
        return 1;
    }
    printf("Remote address configured.\n");

    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
                address_buffer, sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s %s\n", address_buffer, service_buffer);

    printf("Creating socket...\n");
    SOCKET socket_peer;
    socket_peer = socket(peer_address->ai_family,
                         peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer == INVALID_SOCKET)
    {
        fprintf(stderr, "socket() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(peer_address);
        return 1;
    }
    printf("Socket creation completed.\n");

    const char *message = "Hello from the client module!";
    printf("Sending message...: %s\n", message);
    int bytes_sent = sendto(socket_peer,
                            message, (int)strlen(message),
                            0,
                            peer_address->ai_addr, peer_address->ai_addrlen);
    printf("Sent %d bytes.\n", bytes_sent);

    freeaddrinfo(peer_address);
    closesocket(socket_peer);
    return 0;
}