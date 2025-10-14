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
    printf("Socket created.\n");

    DWORD timeout = TIMEOUT_MS;
    if (setsockopt(socket_peer, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0)
    {
        fprintf(stderr, "setsockopt() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(peer_address);
        closesocket(socket_peer);
        return 1;
    }

    struct udp_packet initial_message;
    initial_message.sequence_no = 1;

    strncpy(initial_message.data, "Hello Server", sizeof(initial_message.data) - 1);
    initial_message.data[sizeof(initial_message.data) - 1] = '\0';

    int ack_received = 0;
    for (int i = 0; i < MAX_RETRIES; i++)
    {
        printf("\nAttempt %d: Sending packet (Seq: %d): \"%s\"...\n", i + 1, initial_message.sequence_no, initial_message.data);
        int bytes_sent = sendto(socket_peer,
                                (const char *)&initial_message, sizeof(initial_message),
                                0,
                                peer_address->ai_addr, peer_address->ai_addrlen);

        if (bytes_sent == SOCKET_ERROR)
        {
            fprintf(stderr, "sendto() failed. (%d)\n", WSAGetLastError());
            continue;
        }
        printf("Sent %d bytes. Waiting for ACK...\n", bytes_sent);

        struct udp_packet ack_packet;
        int bytes_received = recvfrom(socket_peer, (char *)&ack_packet, sizeof(ack_packet), 0, NULL, NULL);

        if (bytes_received < 0)
        {

            if (WSAGetLastError() == WSAETIMEDOUT)
            {
                printf("Timeout. No ACK received.\n");
            }
            else
            {
                fprintf(stderr, "recvfrom() failed. (%d)\n", WSAGetLastError());
                break;
            }
        }
        else
        {

            printf("ACK received! (Seq: %d, Data: \"%s\")\n", ack_packet.sequence_no, ack_packet.data);
            ack_received = 1;
            break;
        }
    }

    if (!ack_received)
    {
        fprintf(stderr, "Failed to receive ACK from server after %d attempts.\n", MAX_RETRIES);
    }

    freeaddrinfo(peer_address);
    closesocket(socket_peer);
    return ack_received ? 0 : 1;
}