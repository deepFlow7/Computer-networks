#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <assert.h>
#include <poll.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <byteswap.h>

#define WINDOW_SIZE 1200
#define WAITING_TIME 0.5
#define MAX_FILENAME_LENGTH 50
#define BUFFER_SIZE 20
#define MAX_REQUEST_SIZE 1000
#define PROGRESS_STEP 0.5 // co ile % wypisywać komunikat o postępie
#define MIN(a, b) ((a) < (b) ? (a) : (b))

struct WINDOW_CELL
{
    int written;
    time_t timeout;
    int length;
    char content[MAX_REQUEST_SIZE];
};

int recive_udp(int sockfd, char *IP, int port_nr, struct WINDOW_CELL *window[], int written)
{
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[BUFFER_SIZE + MAX_REQUEST_SIZE];

    ssize_t packet_len = recvfrom(
        sockfd,
        buffer,
        IP_MAXPACKET,
        0,
        (struct sockaddr *)&sender,
        &sender_len);

    if (packet_len < 0)
    {
        fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
        return -1;
    }

    if (sender.sin_family != AF_INET) // czy UDP
    {
        return 0;
    }

    // od kogo dostaliśmy wiadomość
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sender.sin_addr), sender_ip, INET_ADDRSTRLEN);
    uint16_t sender_port = ntohs(sender.sin_port);

    if (sender_port != port_nr || strcmp(sender_ip, IP) != 0)
    {
        return 0;
    }

    // dane datagramu
    int start, size;
    sscanf((char *)buffer, "DATA %d %d\n", &start, &size);
    int idx = start / MAX_REQUEST_SIZE;
    struct WINDOW_CELL *received = window[idx % WINDOW_SIZE];
    if (idx >= written && received->written == 0)
    {
        received->written = 1;
        char *ptr = strchr((char *)buffer, '\n') + 1;
        memcpy((char *)received->content, ptr, size);
        received->length = size;
        return idx + 1;
    }

    return 0;
}

int send_udp(int sockfd, char *recipient_IP, int port_nr, int start, int size)
{
    struct sockaddr_in recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    recipient.sin_port = htons(port_nr);
    if (inet_pton(AF_INET, recipient_IP, &recipient.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton error: %s\n", strerror(errno));
        return -1;
    }

    char message[BUFFER_SIZE];
    snprintf(message, BUFFER_SIZE, "GET %d %d\n", start, size);

    socklen_t recipient_len = sizeof(recipient);
    if (sendto(sockfd, message, sizeof(message), 0, (struct sockaddr *)&recipient, recipient_len) < 0)
    {
        fprintf(stderr, "sendto error: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

struct WINDOW_CELL *new_cell()
{
    struct WINDOW_CELL *c;
    c = malloc(sizeof(struct WINDOW_CELL));
    c->written = 0;
    c->timeout = time(NULL);
    return c;
}

int write_to_file(int *written, FILE *file, struct WINDOW_CELL *window[])
{
    int i;
    int window_idx = *written % WINDOW_SIZE;
    for (i = window_idx; i < window_idx + WINDOW_SIZE; i++)
    {
        int i2 = i % WINDOW_SIZE;
        if (window[i2]->written == 0)
            break;

        window[i2]->written = 0;

        size_t bytes_written = fwrite(window[i2]->content, sizeof(char), window[i2]->length, file);
        if ((int)bytes_written != window[i2]->length)
        {
            fprintf(stderr, "Error writing to file\n");
            return -1;
        }
    }

    int processed = i - window_idx;
    *written += processed;

    return 0;
}

int read_and_check_arguments(int argc, char *argv[], char *ip_address, int *port_nr, char *filename, int *file_size)
{
    if (argc != 5)
    {
        fprintf(stderr, "Incorrect number of arguments");
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) == 0)
    {
        fprintf(stderr, "incorrect IP address: %s\n", argv[1]);
        return -1;
    }
    strcpy(ip_address, argv[1]);

    *port_nr = atoi(argv[2]);
    if (strspn(argv[2], "0123456789") != strlen(argv[2]) || *port_nr < 0 || *port_nr > 49151)
    {
        fprintf(stderr, "incorrect port number: %s\n", argv[2]);
        return -1;
    }

    strcpy(filename, argv[3]);

    *file_size = atoi(argv[4]);
    if (strspn(argv[4], "0123456789") != strlen(argv[4]) || *file_size < 0)
    {
        fprintf(stderr, "incorrect size: %s\n", argv[4]);
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    char ip_address[16], filename[MAX_FILENAME_LENGTH];
    int port_nr, file_size;

    if (read_and_check_arguments(argc, argv, ip_address, &port_nr, filename, &file_size) < 0)
        return EXIT_FAILURE;

    FILE *file = fopen(filename, "wb");
    if (file == NULL)
    {
        perror("Failed to open file");
        return EXIT_FAILURE;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    struct pollfd ps;
    ps.fd = sockfd;
    ps.events = POLLIN;
    ps.revents = 0;

    struct WINDOW_CELL *window[WINDOW_SIZE];
    for (int i = 0; i < WINDOW_SIZE; i++)
        window[i] = new_cell();

    int written = 0;
    int readed = 0;
    int timeout = 15;
    double last_progress = 0, progress = 0;

    int n = file_size / MAX_REQUEST_SIZE + (file_size % MAX_REQUEST_SIZE != 0);

    while (written < n)
    {

        time_t current_time = time(NULL);
        for (int i = 0; i < WINDOW_SIZE; i++)
        {
            // okno przesuwne trzymam jako "listę" zawijaną
            int written_ = written - (written % WINDOW_SIZE);
            int window_idx = written % WINDOW_SIZE;
            int start = (written_ + i + (i < window_idx) * WINDOW_SIZE) * MAX_REQUEST_SIZE;

            if (window[i]->written == 0 && window[i]->timeout <= current_time)
            {
               
                int rest = file_size - start;
                int size = rest > MAX_REQUEST_SIZE ? MAX_REQUEST_SIZE : rest;
                send_udp(sockfd, ip_address, port_nr, start, size);
                window[i]->timeout += WAITING_TIME;
            }
        }

        int ready = poll(&ps, 1, timeout);
        if (ready > 0 && ps.revents & POLLIN)
        {
            int r = recive_udp(sockfd, ip_address, port_nr, window, written);

            if (r < 0)
                return EXIT_FAILURE;

            if (r > 0)
            {
                readed++;
                progress = 100.0 * readed / n;
                if (progress >= last_progress + PROGRESS_STEP)
                {
                    printf("%.3f%% done\n", progress);
                    last_progress = progress;
                }
                if (r - 1 == written)
                    if (write_to_file(&written, file, window) < 0)
                        return EXIT_FAILURE;
            }
        }
        else if (ready < 0)
        {
            fprintf(stderr, "poll error: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < WINDOW_SIZE; i++)
    {
        free(window[i]);
    }

    close(sockfd);
    fclose(file);

    return 0;
}
