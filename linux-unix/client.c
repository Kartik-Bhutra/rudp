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

    printf("Remote address is: ");
    char address_buffer[100];
    char service_buffer[100];
    if (getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen,
                    address_buffer, sizeof(address_buffer),
                    service_buffer, sizeof(service_buffer),
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0)
    {
        printf("%s %s\n", address_buffer, service_buffer);
    }

    printf("Creating socket...\n");
    int socket_peer = socket(peer_address->ai_family,
                             peer_address->ai_socktype, peer_address->ai_protocol);
    if (socket_peer < 0)
    {
        perror("socket() failed");
        freeaddrinfo(peer_address);
        return 1;
    }
    printf("Socket created.\n");

    // Set receive timeout
    struct timeval timeout;
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    if (setsockopt(socket_peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt() failed");
        freeaddrinfo(peer_address);
        close(socket_peer);
        return 1;
    }

    quic_packet initial_message;
    initial_message.header.packet_number = 1;
    initial_message.header.connection_id_start = 100;
    initial_message.header.connection_id_destination = 200;
    initial_message.header.length = sizeof(initial_message.payload);

    initial_message.payload.ack = 0;
    initial_message.payload.id = 1;
    initial_message.payload.total_packet = 1;
    memset(initial_message.payload.data, 0, CHUNK_SIZE);
    strcpy((char *)initial_message.payload.data, "Hello Server");

    int ack_received = 0;
    for (int i = 0; i < MAX_RETRIES; i++)
    {
        printf("\nAttempt %d: Sending packet (No: %d): \"%s\"...\n",
               i + 1, initial_message.header.packet_number, initial_message.payload.data);

        ssize_t bytes_sent = sendto(socket_peer,
                                    &initial_message, sizeof(initial_message),
                                    0,
                                    peer_address->ai_addr, peer_address->ai_addrlen);

        if (bytes_sent < 0)
        {
            perror("sendto() failed");
            continue;
        }

        printf("Sent %ld bytes. Waiting for ACK...\n", bytes_sent);

        quic_packet ack_packet;
        ssize_t bytes_received = recvfrom(socket_peer,
                                          &ack_packet, sizeof(ack_packet),
                                          0, NULL, NULL);

        if (bytes_received < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("Timeout. No ACK received.\n");
            }
            else
            {
                perror("recvfrom() failed");
                break;
            }
        }
        else
        {
            printf("ACK received! (Packet: %d, Data: \"%s\")\n",
                   ack_packet.header.packet_number, ack_packet.payload.data);
            ack_received = 1;
            break;
        }
    }

    if (!ack_received)
    {
        fprintf(stderr, "Failed to receive ACK from server after %d attempts.\n", MAX_RETRIES);
    }

    freeaddrinfo(peer_address);
    close(socket_peer);
    return ack_received ? 0 : 1;
}
