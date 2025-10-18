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
    if (getaddrinfo(NULL, PORT, &hints, &bind_address) != 0)
    {
        perror("getaddrinfo() failed");
        return 1;
    }

    printf("Creating socket...\n");
    int socket_listen = socket(bind_address->ai_family,
                               bind_address->ai_socktype, bind_address->ai_protocol);
    if (socket_listen < 0)
    {
        perror("socket() failed");
        freeaddrinfo(bind_address);
        return 1;
    }

    printf("Binding socket to local address...\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen) != 0)
    {
        perror("bind() failed");
        freeaddrinfo(bind_address);
        close(socket_listen);
        return 1;
    }

    freeaddrinfo(bind_address);
    printf("Socket binded. Listening for packets...\n\n");

    while (1)
    {
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        quic_packet received_packet;

        ssize_t bytes_received = recvfrom(socket_listen,
                                          &received_packet,
                                          sizeof(received_packet),
                                          0,
                                          (struct sockaddr *)&client_address, &client_len);

        if (bytes_received < 0)
        {
            perror("recvfrom() failed");
            continue;
        }

        char address_buffer[100];
        char service_buffer[100];
        if (getnameinfo((struct sockaddr *)&client_address, client_len,
                        address_buffer, sizeof(address_buffer),
                        service_buffer, sizeof(service_buffer),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0)
        {
            printf("Received %ld bytes from %s %s\n", bytes_received, address_buffer, service_buffer);
        }

        if (bytes_received != sizeof(received_packet))
        {
            fprintf(stderr, "Received a malformed packet of size: %ld\n", bytes_received);
            continue;
        }

        // printf("-> Packet Number: %d | Connection ID Src: %d | Dest: %d | Length: %ld\n",
        //        received_packet.header.packet_number,
        //        received_packet.header.connection_id_start,
        //        received_packet.header.connection_id_destination,
        //        received_packet.header.length);

        // printf("-> Payload ACK: %d | ID: %d | Total: %d\n",
        //        received_packet.payload.ack,
        //        received_packet.payload.id,
        //        received_packet.payload.total_packet);

        // Build ACK packet
        quic_packet ack_packet = build_ack(received_packet);

        printf("<- Sending ACK (Packet: %d) back to client...\n\n",
               ack_packet.header.packet_number);

        ssize_t bytes_sent = sendto(socket_listen,
                                    &ack_packet, sizeof(ack_packet),
                                    0,
                                    (struct sockaddr *)&client_address, client_len);

        if (bytes_sent < 0)
        {
            perror("sendto() failed");
        }
    }

    close(socket_listen);
    return 0;
}
