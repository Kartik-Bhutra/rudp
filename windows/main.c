#include "header.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: program.exe [server|client]\n");
        return 1;
    }

    printf("Initializing Winsock...\n");
    WSADATA d;
    if (WSAStartup(MAKEWORD(2, 2), &d))
    {
        fprintf(stderr, "Failed to initialize Winsock.\n");
        return 1;
    }
    printf("Socket API initialized");

    int result = 0;

    if (strcmp(argv[1], "server") == 0)
    {
        printf("\n--- Starting in Server Mode ---\n");
        result = run_server();
    }
    else if (strcmp(argv[1], "client") == 0)
    {
        printf("\n--- Starting in Client Mode ---\n");
        result = run_client();
    }
    else
    {
        fprintf(stderr, "Invalid mode. Use 'server' or 'client'.\n");
        result = 1;
    }

    WSACleanup();
    printf("Finished.\n");

    return result;
}