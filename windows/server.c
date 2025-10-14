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
    if (getaddrinfo(0, "8080", &hints, &bind_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", WSAGetLastError());
        return 1;
    }

    printf("Creating socket...\n");
    SOCKET socket_listen;
    socket_listen = socket(bind_address->ai_family,
                           bind_address->ai_socktype, bind_address->ai_protocol);
    if (socket_listen == INVALID_SOCKET)
    {
        fprintf(stderr, "socket() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(bind_address);
        return 1;
    }

    printf("Binding socket to local address...\n");
    if (bind(socket_listen,
             bind_address->ai_addr, bind_address->ai_addrlen))
    {
        fprintf(stderr, "bind() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(bind_address);
        closesocket(socket_listen);
        return 1;
    }
    freeaddrinfo(bind_address);
    printf("Socket binded. Listening for packets...\n\n");

    while (1)
    {
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        struct udp_packet received_packet;

        int bytes_received = recvfrom(socket_listen,
                                      (char *)&received_packet,
                                      sizeof(received_packet),
                                      0,
                                      (struct sockaddr *)&client_address, &client_len);

        if (bytes_received < 0)
        {
            fprintf(stderr, "recvfrom() failed. (%d)\n", WSAGetLastError());
            continue;
        }

        char address_buffer[100];
        char service_buffer[100];
        getnameinfo((struct sockaddr *)&client_address, client_len,
                    address_buffer, sizeof(address_buffer),
                    service_buffer, sizeof(service_buffer),
                    NI_NUMERICHOST | NI_NUMERICSERV);

        printf("Received %d bytes from %s %s\n", bytes_received, address_buffer, service_buffer);

        if (bytes_received != sizeof(received_packet))
        {
            fprintf(stderr, "Received a malformed packet of size: %d\n", bytes_received);
            continue;
        }

        printf("-> Packet Seq: %d, Msg: \"%s\"\n", received_packet.sequence_no, received_packet.data);

        struct udp_packet ack_packet;
        ack_packet.sequence_no = received_packet.sequence_no;
        strncpy(ack_packet.data, "ACK", sizeof(ack_packet.data) - 1);
        ack_packet.data[sizeof(ack_packet.data) - 1] = '\0';

        printf("<- Sending ACK (Seq: %d) back to client...\n\n", ack_packet.sequence_no);

        int bytes_sent = sendto(socket_listen,
                                (const char *)&ack_packet, sizeof(ack_packet),
                                0,
                                (struct sockaddr *)&client_address, client_len);

        if (bytes_sent == SOCKET_ERROR)
        {
            fprintf(stderr, "sendto() failed. (%d)\n", WSAGetLastError());
        }
    }

    closesocket(socket_listen);
    return 0;
}