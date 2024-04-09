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

#define MAX_TTL 30

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
    const u_int16_t *ptr = buff;
    u_int32_t sum = 0;
    assert(length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return (u_int16_t)(~(sum + (sum >> 16U)));
}

double timespec_difference_in_ms(struct timespec start, struct timespec end)
{
    long long sec = end.tv_sec - start.tv_sec;
    long long nsec = end.tv_nsec - start.tv_nsec;

    return sec * 1000.0 + nsec / 1000000.0;
}

int is_destination(char **responder_ip, char *destination)
{
    for (int i = 0; i < 3; i++)
        if (responder_ip[i] != NULL && strcmp(responder_ip[i], destination) == 0)
            return 1;
    return 0;
}

int is_in_prefix(int j, char **responder_ip)
{
    for (int i = 0; i < j; i++)
    {
        if (responder_ip[i] != NULL && strcmp(responder_ip[i], responder_ip[j]) == 0)
            return 1;
    }
    return 0;
}

void printing(int i, int *is_response, char **responder_ip, double *response_time)
{
    printf("%2d.  ", i);

    int response_count = is_response[0] + is_response[1] + is_response[2];

    if (response_count == 0)
    {
        printf("*\n");
        return;
    }

    for (int j = 0; j < 3; j++)
        if (is_response[j] && !is_in_prefix(j, responder_ip))
            printf("%-15s ", responder_ip[j]);

    if (response_count == 3)
        printf(" %0.3f ms\n", (response_time[0] + response_time[1] + response_time[2]) / 3.0);
    else
        printf(" ???\n");
}

int send_icmp(int sock_fd, char *ip_address, int ttl, int seq_nr, struct timespec *start_time)
{

    struct icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = getpid() & 0xFF;
    header.icmp_hun.ih_idseq.icd_seq = seq_nr;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum(
        (u_int16_t *)&header, sizeof(header));

    struct sockaddr_in recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip_address, &recipient.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton error: %s\n", strerror(errno));
        return -1;
    }

    // ustawienie ttl
    if (setsockopt(sock_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) == -1)
    {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        return -1;
    }

    // wystartowanie mierzenia czasu
    clock_gettime(CLOCK_MONOTONIC, &start_time[seq_nr % 3]);

    ssize_t bytes_sent = sendto(
        sock_fd,
        &header,
        sizeof(header),
        0,
        (struct sockaddr *)&recipient,
        sizeof(recipient));

    if (bytes_sent < 0)
    {
        fprintf(stderr, "sendto error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void process_icmp_packet(int idx, const char *sender_ip_str, struct timespec *start_time, struct timespec end_time,
                         char **responder_ip, double *response_time, int *is_response)
{
    double diff_ms = timespec_difference_in_ms(start_time[idx], end_time);
    responder_ip[idx] = strdup(sender_ip_str);
    response_time[idx] = diff_ms;
    is_response[idx] = 1;
}

int receive(int sock_fd, int ttl, char **responder_ip, struct timespec *start_time, double *response_time, int *is_response)
{

    int received_packets_count = 0;
    struct timespec end_time;

    struct pollfd ps;
    ps.fd = sock_fd;
    ps.events = POLLIN;
    ps.revents = 0;

    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[IP_MAXPACKET];

    int seq_nr, id;
    int is_icmp_packet_to_process = 0;
    int timeout = 1000;

    while (received_packets_count < 3)
    {
        int ready = poll(&ps, 1, timeout);

        if (ready > 0 && ps.revents & POLLIN)
        {
            ssize_t packet_len = recvfrom(sock_fd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
            clock_gettime(CLOCK_MONOTONIC, &end_time);

            if (packet_len < 0)
            {
                fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
                return -1;
            }

            char sender_ip_str[20];
            const char *result = inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
            if (result == NULL)
            {
                perror("inet_ntop error");
                return -1;
            }

            struct ip *ip_header = (struct ip *)buffer;
            ssize_t ip_header_len = 4 * (ssize_t)(ip_header->ip_hl);

            if (ip_header->ip_p == IPPROTO_ICMP)
            {
                struct icmp *icmp_packet = (struct icmp *)(buffer + ip_header_len);

                if (icmp_packet->icmp_type == ICMP_ECHOREPLY)
                {
                    seq_nr = icmp_packet->icmp_seq;
                    id = icmp_packet->icmp_id;
                    is_icmp_packet_to_process = 1;
                }
                else if (icmp_packet->icmp_type == ICMP_TIME_EXCEEDED)
                {
                    struct iphdr *ip_header = (struct iphdr *)buffer;
                    struct icmphdr *icmp_header = (struct icmphdr *)icmp_packet;
                    icmp_header = (void *)icmp_header + 8 + 4 * ip_header->ihl;

                    seq_nr = icmp_header->un.echo.sequence;
                    id = icmp_header->un.echo.id;
                    is_icmp_packet_to_process = 1;
                }
                if (is_icmp_packet_to_process && id == (getpid() & 0xFF) && seq_nr - seq_nr % 3 == ttl * 3)
                {
                    int idx = seq_nr % 3;
                    process_icmp_packet(idx, sender_ip_str, start_time, end_time, responder_ip, response_time, is_response);
                    timeout -= response_time[idx];
                    received_packets_count++;
                }

                is_icmp_packet_to_process = 0;
            };
        }
        else if (ready == 0)
        {
            return received_packets_count;
        }
        else
        {
            perror("poll error");
            return -1;
        }
    }
    return received_packets_count;
}

int main(int argc, char *argv[])
{
    // sprawdzenie poprawności argumentów wywołań
    if (argc != 2)
    {
        fprintf(stderr, "Incorrect number of arguments: %d != 2\n", argc);
        return EXIT_FAILURE;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, argv[1], &addr) == 0)
    {
        fprintf(stderr, "incorrect IP address: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    // tworzenie gniazda
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_fd < 0)
    {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    // wysyłanie i odbieranie pakietów
    for (int i = 1; i <= MAX_TTL; i++)
    {

        char *responder_ip[3] = {NULL};
        double response_time[3] = {0};
        int is_response[3] = {0};
        struct timespec start_time[3];

        for (int j = 0; j < 3; j++)
            if (send_icmp(sock_fd, argv[1], i, 3 * i + j, start_time) < 0)
                return EXIT_FAILURE;

        if (receive(sock_fd, i, responder_ip, start_time, response_time, is_response) < 0)
            return EXIT_FAILURE;

        printing(i, is_response, responder_ip, response_time);

        if (is_destination(responder_ip, argv[1]))
            return 0;
    }
    return 0;
}
