#include "header.h"

int main(int argc, char *argv[])
{
    //Read server_pub.pem  
    FILE *fp = fopen("server_pub.pem", "rb");
    if (!fp)
    {
        perror("Failed to open server_pub.pem");
        fprintf(stderr, "Please generate server_pub.pem first.\n");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long pubkey_size = ftell(fp);
    rewind(fp);

    unsigned char *pubkey_buf = malloc(pubkey_size);
    if (!pubkey_buf) {
        perror("malloc for pubkey failed");
        fclose(fp);
        return 1;
    }

    if (fread(pubkey_buf, 1, pubkey_size, fp) != pubkey_size) {
        fprintf(stderr, "Failed to read full public key.\n");
        fclose(fp);
        free(pubkey_buf);
        return 1;
    }
    fclose(fp);
    printf("Read %ld bytes from server_pub.pem.\n", pubkey_size);

    // Build the request packet
    const char *prefix = "PUBKEY:";
    quic_packet request_packet;
    if (strlen(prefix) + pubkey_size >= sizeof(request_packet.payload_buffer))
    {
        fprintf(stderr, "Public key is too large for packet payload.\n");
        free(pubkey_buf);
        return 1;
    }
    
    memset(&request_packet, 0, sizeof(request_packet));

    // Header
    request_packet.header.packet_number = 0;
    request_packet.header.connection_id_start = 123; 
    request_packet.header.connection_id_destination = 456;
    
    // Payload data (the "PUBKEY:" request)
    memcpy(request_packet.payload_buffer, prefix, strlen(prefix));
    memcpy(request_packet.payload_buffer + strlen(prefix), pubkey_buf, pubkey_size);
    request_packet.header.length = strlen(prefix) + pubkey_size;
    
    free(pubkey_buf); 

    // Set up UDP socket
    printf("Configuring certificate server address (%s:%s)...\n",CERTIFICATE_SERVER_IP, CERTIFICATE_SERVER_PORT);
           
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo *ca_address;
    if (getaddrinfo(CERTIFICATE_SERVER_IP, CERTIFICATE_SERVER_PORT, &hints, &ca_address) != 0)
    {
        perror("getaddrinfo() for CA failed");
        return 1;
    }

    int sock = socket(ca_address->ai_family, ca_address->ai_socktype, ca_address->ai_protocol);
    if (sock < 0)
    {
        perror("socket() failed");
        freeaddrinfo(ca_address);
        return 1;
    }

    struct timeval timeout = {TIMEOUT_SEC, 0};
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
        perror("setsockopt() timeout failed");
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }
    
    //Send the request
    printf("Sending PUBKEY request to CA...\n");
    ssize_t bytes_sent = sendto(sock, &request_packet, sizeof(request_packet), 0,
                                ca_address->ai_addr, ca_address->ai_addrlen);
    if (bytes_sent < 0)
    {
        perror("sendto() failed");
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }

    // Receive the response
    printf("Waiting for certificate response...\n");
    quic_packet response_packet;
    ssize_t bytes_received = recvfrom(sock, &response_packet, sizeof(response_packet),
                                      0, NULL, NULL);

    if (bytes_received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            printf("Timeout: No response from certificate server.\n");
        else
            perror("recvfrom() failed");
            
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }
    
    printf("Received %ld bytes from CA.\n", bytes_received);

    //Extract certificate and save to file 
    long cert_len = response_packet.header.length;
    unsigned char *cert_data = response_packet.payload_buffer;

    if (cert_len <= 0 || cert_len > sizeof(response_packet.payload_buffer))
    {
        fprintf(stderr, "Received invalid certificate length: %ld\n", cert_len);
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }

    FILE *out_fp = fopen("server_cert.pem", "wb");
    if (!out_fp)
    {
        perror("Failed to open server_cert.pem for writing");
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }
    
    if (fwrite(cert_data, 1, cert_len, out_fp) != cert_len)
    {
        fprintf(stderr, "Failed to write full certificate to file.\n");
        fclose(out_fp);
        close(sock);
        freeaddrinfo(ca_address);
        return 1;
    }

    fclose(out_fp);
    close(sock);
    freeaddrinfo(ca_address);

    printf("\nSuccessfully saved custom certificate to server_cert.pem (%ld bytes).\n", cert_len);
    return 0;
}