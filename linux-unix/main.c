#include "header.h"

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [server|client]\n", argv[0]);
        return 1;
    }

    printf("Initializing Socket API...\n");
   
    printf("Socket API initialized.\n");

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

    printf("Finished.\n");

    return result;
}
