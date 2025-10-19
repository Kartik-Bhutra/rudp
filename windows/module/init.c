#include "header.h"

int initWin()
{
    printf("Initializing Winsock...\n");
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d))
    {
        fprintf(stderr, "Failed to initialize Winsock.\n");
        return 1;
    }
    return 0;
}

int createServer(SOCKET *pSocketListen, PCSTR pServiceName)
{
    printf("Configuring local address...\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo *bind_address;
    if (getaddrinfo(0, pServiceName, &hints, &bind_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", WSAGetLastError());
        return 1;
    }

    printf("Creating socket...\n");

    *pSocketListen = socket(bind_address->ai_family,
                            bind_address->ai_socktype,
                            bind_address->ai_protocol);

    if (*pSocketListen == INVALID_SOCKET)
    {
        fprintf(stderr, "socket() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(bind_address);
        return 1;
    }

    printf("Binding socket to local address...\n");
    if (bind(*pSocketListen,
             bind_address->ai_addr, bind_address->ai_addrlen))
    {
        fprintf(stderr, "bind() failed. (%d)\n", WSAGetLastError());
        freeaddrinfo(bind_address);
        closesocket(*pSocketListen);
        return 1;
    }

    freeaddrinfo(bind_address);
    return 0;
}

int createClient(SOCKET *pSocketPeer, PCSTR pNodeName, PCSTR pServiceName, struct addrinfo **ppPeerAddress)
{
    printf("Configuring remote address for %s:%s...\n", pNodeName, pServiceName);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(pNodeName, pServiceName, &hints, ppPeerAddress))
    {
        fprintf(stderr, "getaddrinfo() failed. (%d)\n", WSAGetLastError());
        return 1;
    }

    printf("Creating socket...\n");

    *pSocketPeer = socket((*ppPeerAddress)->ai_family,
                          (*ppPeerAddress)->ai_socktype,
                          (*ppPeerAddress)->ai_protocol);

    if (*pSocketPeer == INVALID_SOCKET)
    {
        fprintf(stderr, "socket() failed. (%d)\n", WSAGetLastError());

        freeaddrinfo(*ppPeerAddress);
        *ppPeerAddress = NULL;
        return 1;
    }

    printf("Client socket created successfully.\n");
    return 0;
}