#include "header.h"

int run_server()
{
    printf("Configuring local address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *bind_address;
    getaddrinfo(0, "8080", &hints, &bind_address);
    printf("Local address configured.\n");

    printf("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
                           bind_address->ai_socktype, bind_address->ai_protocol);
    if (socket_listen == INVALID_SOCKET)
    {
        fprintf(stderr, "socket() failed. (%d)\n", WSAGetLastError());
        return 1;
    }
    printf("Socket creation completed.\n");

    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
             bind_address->ai_addr, bind_address->ai_addrlen))
    {
        fprintf(stderr, "bind() failed. (%d)\n", WSAGetLastError());
        return 1;
    }
    freeaddrinfo(bind_address);
    printf("Socket binded to local address.\n");

    printf("Waiting for data from client...\n");
    struct sockaddr_storage client_address;
    socklen_t client_len = sizeof(client_address);
    char read[MAX_UDP_MESSAGE_SIZE];
    int bytes_received = recvfrom(socket_listen,
                                  read, MAX_UDP_MESSAGE_SIZE,
                                  0,
                                  (struct sockaddr *)&client_address, &client_len);
    printf("Received (%d bytes): %.*s\n",
           bytes_received, bytes_received, read);

    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    getnameinfo(((struct sockaddr *)&client_address),
                client_len,
                address_buffer, sizeof(address_buffer),
                service_buffer, sizeof(service_buffer),
                NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s %s\n", address_buffer, service_buffer);
    closesocket(socket_listen);

    return 0;
}