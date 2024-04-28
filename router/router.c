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

#define MAX_DISTANCE 16
#define ROUND 15
#define PRINT_INTERVAL 5
#define ROUND_CYCLE 5

struct table_entry
{
    char *IP;
    int subnet_mask;
    char *next_hop; // Null -> connected directly
    int distance;
    int last_message_round;
};

struct neighbour_entry{
    struct table_entry entry;
    int old_distance; // zapamiętana bezpośrednia odległość
};

char *broadcast_or_network_IP(char *IP, int subnet_mask, int is_broadcast)
{
    uint32_t ip_address = inet_addr(IP);
    ip_address = __bswap_32(ip_address);
    uint32_t subnet_mask_int = (0xFFFFFFFF << (32 - subnet_mask));
    uint32_t broadcast_or_network_addr;
    if (is_broadcast)
        broadcast_or_network_addr = ip_address | ~subnet_mask_int;
    else
        broadcast_or_network_addr = ip_address & subnet_mask_int;
    char *broadcast_ip_str = (char *)malloc(16 * sizeof(char));
    sprintf(broadcast_ip_str, "%d.%d.%d.%d",
            (broadcast_or_network_addr >> 24) & 0xFF, (broadcast_or_network_addr >> 16) & 0xFF,
            (broadcast_or_network_addr >> 8) & 0xFF, broadcast_or_network_addr & 0xFF);
    return broadcast_ip_str;
}

char *broadcast_IP(char *IP, int subnet_mask)
{
    return broadcast_or_network_IP(IP, subnet_mask, 1);
}

char *network_IP(char *IP, int subnet_mask)
{
    return broadcast_or_network_IP(IP, subnet_mask, 0);
}

void printing(int n, struct table_entry route_table[])
{
    printf("\n");
    for (int i = 0; i < n; i++)
    {
        struct table_entry entry = route_table[i];

        char connect_str[25];
        if (entry.next_hop == NULL)
        {
            strcpy(connect_str, "connected directly");
        }
        else
            sprintf(connect_str, "via %s", entry.next_hop);
        char distance_str[16];
        if (entry.distance == MAX_DISTANCE)
            strcpy(distance_str, "unreachable");
        else
            sprintf(distance_str, "distance %d", entry.distance);
        printf("%s/%d %s %s\n", entry.IP, entry.subnet_mask, distance_str, connect_str);

    }
    printf("\n");
}

int IP_addr_idx_in_table(char *sender_ip, int n, struct neighbour_entry neighbours[])
{
    for (int i = 0; i < n; i++)
    {
        struct table_entry* entry = &neighbours[i].entry;
        if (strcmp(network_IP(sender_ip, entry->subnet_mask), entry->IP) == 0)
            return i;
    }
    return -1;
}

int network_addr_idx_in_table(char *IP, int IP_mask, struct table_entry route_table[], int n)
{
    for (int i = 0; i < n; i++)
        if (strcmp(network_IP(IP, IP_mask), route_table[i].IP) == 0)
            return i;
    return -1;
}

int min(int a, int b)
{
    return a < b ? a : b;
}

int is_my_IP(char *IP, int my_IPs_nr, char *my_IPs[])
{
    for (int i = 0; i < my_IPs_nr; i++)
        if (strcmp(IP, my_IPs[i]) == 0)
            return 1;
    return 0;
}

void add_entry(char *IP, int subnet_mask, char *next_hop, int distance, int round_nr, int *n, struct table_entry route_table[]){
    char *new_IP = (char *)malloc(16 * sizeof(char));
    strcpy(new_IP, IP);
    char *new_next_hop = NULL;
    if(next_hop != NULL){
        new_next_hop = (char *)malloc(16 * sizeof(char));
        strcpy(new_next_hop, next_hop);
    };

    struct table_entry new_entry = {new_IP, subnet_mask, new_next_hop, distance, round_nr};
    route_table[*n] = new_entry;
    *n += 1;
}

void process_udp(int *n, struct table_entry route_table[], int round_nr, char *sender_ip, char *destination_IP, 
    int destination_subnet_mask, int destination_distance, int neighbours_nr, struct neighbour_entry neighbours[])
{
    int sender_idx_in_table = IP_addr_idx_in_table(sender_ip, neighbours_nr, neighbours);
    int destination_idx_in_table = network_addr_idx_in_table(destination_IP, destination_subnet_mask, route_table, *n);

    // nie jest w tabeli jako bezpośrednio połączony
    if (sender_idx_in_table == -1)
    {
        return;
    }
    struct table_entry *sender_entry = &neighbours[sender_idx_in_table].entry;
    sender_entry->last_message_round = round_nr;

    if (sender_entry->distance == MAX_DISTANCE)
    {
        if (strcmp(network_IP(sender_ip, destination_subnet_mask), destination_IP) == 0){
            sender_entry->distance = destination_distance;
            neighbours[sender_idx_in_table].old_distance = destination_distance;
            route_table[destination_idx_in_table].distance = destination_distance;
            route_table[destination_idx_in_table].last_message_round = round_nr;
        }
        return;
    }

    int new_distance = destination_distance + sender_entry->distance;

    if (destination_idx_in_table >= 0)
    { // jest w tablicy
        struct table_entry *destination_entry = &route_table[destination_idx_in_table];

        if (destination_entry->next_hop != NULL && strcmp(destination_entry->next_hop, sender_ip) == 0){
            if (destination_distance < MAX_DISTANCE)
                destination_entry->last_message_round = round_nr;

            destination_entry->distance = min(new_distance, MAX_DISTANCE);
        }

        if (destination_entry->distance > new_distance)
        {
                destination_entry->distance = new_distance;
                if(destination_entry->next_hop == NULL)
                    destination_entry->next_hop = (char *)malloc(16 * sizeof(char));
                strcpy(destination_entry->next_hop, sender_ip);
        }
    }
    else
    {
        if (new_distance < MAX_DISTANCE)
            add_entry(destination_IP, destination_subnet_mask, sender_ip, new_distance, round_nr, n, route_table);
    }
}

int recive_udp(int sockfd, int *n, struct table_entry route_table[], int round_nr, int my_IPs_nr, char *my_IPs[], struct neighbour_entry neighbours[])
{
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    u_int8_t buffer[10];

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

    if (sender.sin_family != AF_INET || packet_len != 9) // czy UDP dobrego rozmiaru
    {
        return 0;
    }

    // od kogo dostaliśmy wiadomość
    char sender_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(sender.sin_addr), sender_ip, INET_ADDRSTRLEN);
    uint16_t sender_port = ntohs(sender.sin_port);

    if (sender_port != 54321 || is_my_IP(sender_ip, my_IPs_nr, my_IPs))
    {
        return 0;
    }

    // dane datagramu
    uint32_t IP_from_udp;
    uint8_t subnet_mask_from_udp;
    uint32_t distance_from_udp;

    memcpy(&IP_from_udp, buffer, sizeof(uint32_t));
    subnet_mask_from_udp = buffer[4];
    memcpy(&distance_from_udp, buffer + 5, sizeof(uint32_t));
    IP_from_udp = ntohl(IP_from_udp);
    distance_from_udp = ntohl(distance_from_udp);

    char IP_from_udp_str[16];
    sprintf(IP_from_udp_str, "%d.%d.%d.%d", (IP_from_udp >> 24) & 0xFF, (IP_from_udp >> 16) & 0xFF, (IP_from_udp >> 8) & 0xFF, IP_from_udp & 0xFF);

    process_udp(n, route_table, round_nr, sender_ip, IP_from_udp_str, subnet_mask_from_udp, distance_from_udp, my_IPs_nr, neighbours);

    return 0;
}

int send_udp(int sockfd, char *recipient_IP, char *IP, int subnet_mask, int distance)
{
    struct sockaddr_in recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    recipient.sin_port = htons(54321);
    if (inet_pton(AF_INET, recipient_IP, &recipient.sin_addr) <= 0)
    {
        fprintf(stderr, "inet_pton error: %s\n", strerror(errno));
        return -1;
    }

    uint8_t buffer[9];
    uint32_t IP_addr = inet_addr(IP);
    memcpy(buffer, &IP_addr, sizeof(uint32_t));
    buffer[4] = subnet_mask;
    uint32_t distance_htonl = htonl(distance);
    memcpy(buffer + 5, &distance_htonl, sizeof(uint32_t));

    socklen_t recipient_len = sizeof(recipient);
    if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&recipient, recipient_len) < 0)
    {
        //fprintf(stderr, "sendto error: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

void mark_unreachable(int i, int n, struct table_entry route_table[], struct neighbour_entry neighbours[], int round_nr)
{
    neighbours[i].entry.distance = MAX_DISTANCE;
    neighbours[i].entry.last_message_round = round_nr;

    char *unreachable_network_addr = neighbours[i].entry.IP;
    int subnet_mask = neighbours[i].entry.subnet_mask;

    for (int j = 0; j < n; j++)
    {
        if ((route_table[j].next_hop != NULL &&
            strcmp(unreachable_network_addr, network_IP(route_table[j].next_hop, subnet_mask)) == 0)
            || (route_table[j].next_hop == NULL && strcmp(unreachable_network_addr, route_table[j].IP) == 0)
            )
        {
            route_table[j].distance = MAX_DISTANCE;
            route_table[j].last_message_round = round_nr;
        }
    }
}

void direct_connection_fixed(struct neighbour_entry neighbour, int *n, struct table_entry route_table[], int round_nr){
    int idx_in_table = network_addr_idx_in_table(neighbour.entry.IP,neighbour.entry.subnet_mask, route_table, *n);
    if (idx_in_table < 0){
        add_entry(neighbour.entry.IP, neighbour.entry.subnet_mask, NULL, neighbour.entry.distance, round_nr, n, route_table);
    }
    else
        if(route_table[idx_in_table].distance >= neighbour.entry.distance){
            free(route_table[idx_in_table].next_hop);
            route_table[idx_in_table].next_hop = NULL;
            route_table[idx_in_table].distance = neighbour.entry.distance;
            neighbour.entry.last_message_round = round_nr;
        }
}

void send_all(int sockfd, int n, struct table_entry route_table[], int neighbours_nr, struct neighbour_entry neighbours[], int round_nr)
{
    for (int i = 0; i < neighbours_nr; i++)
    {
            char recipient_IP[16];
            strcpy(recipient_IP, broadcast_IP(neighbours[i].entry.IP, neighbours[i].entry.subnet_mask));
            for (int j = 0; j < n; j++)
            {
                if (route_table[j].last_message_round < ROUND_CYCLE || neighbours[i].entry.distance == MAX_DISTANCE)
                {
                    if (send_udp(sockfd, recipient_IP,
                                 route_table[j].IP, route_table[j].subnet_mask, route_table[j].distance) < 0)
                    {
                        if (neighbours[i].entry.distance < MAX_DISTANCE)
                            mark_unreachable(i, n, route_table, neighbours, round_nr);
                        break;
                    }
                    else
                    {

                        if (neighbours[i].entry.distance > neighbours[i].old_distance)
                        {

                            neighbours[i].entry.distance = neighbours[i].old_distance;
                            neighbours[i].entry.last_message_round = round_nr;

                            // dodaj wpis lub popraw route_table jesli trzeba
                            direct_connection_fixed(neighbours[i], &n, route_table, round_nr);
                        }
                    }
                }
            }
    }
}

void delete_entry(int i, int *n, struct table_entry route_table[])
{

    free(route_table[i].IP);
    free(route_table[i].next_hop);

    for (int j = i; j < *n - 1; j++)
        route_table[j] = route_table[j + 1];

    *n -= 1;
}

void read_configuration(int n, struct table_entry route_table[], char *my_IPs[], struct neighbour_entry neighbours[])
{
    for (int i = 0; i < n; i++)
    {
        int W, X, Y, Z;
        scanf("%d.%d.%d.%d/%d distance %d", &W, &X, &Y, &Z, &route_table[i].subnet_mask, &route_table[i].distance);
        route_table[i].IP = (char *)malloc(16 * sizeof(char));
        my_IPs[i] = (char *)malloc(16 * sizeof(char));
        char *IP_copy = (char *)malloc(16 * sizeof(char));

        sprintf(my_IPs[i], "%d.%d.%d.%d", W, X, Y, Z);
        strcpy(route_table[i].IP, network_IP(my_IPs[i], route_table[i].subnet_mask));
        strcpy(IP_copy, route_table[i].IP);

        route_table[i].next_hop = NULL;
        route_table[i].last_message_round = 0;

        struct table_entry new_entry =  {IP_copy, route_table[i].subnet_mask, NULL, route_table[i].distance, 0};
        neighbours[i].entry = new_entry;
        neighbours[i].old_distance = route_table[i].distance;
    }
}

int create_socket_and_bind()
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "socket error: %s\n", strerror(errno));
        return -1;
    }

    int broadcastPermission = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST,
                   (void *)&broadcastPermission,
                   sizeof(broadcastPermission)) < 0)
    {
        fprintf(stderr, "setsocketopt error: %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(54321);
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(
            sockfd,
            (struct sockaddr *)&server_address,
            sizeof(server_address)) < 0)
    {
        fprintf(stderr, "bind error: %s\n", strerror(errno));
        return -1;
    }
    return sockfd;
}

void check_and_update_reachability(struct table_entry route_table[], int *n, int round_nr)
{
    for (int i = 0; i < *n; i++)
    {
        struct table_entry *entry = &route_table[i];
        // przez cały cykl brak wiadomości
        if (entry->last_message_round == (round_nr + 1) % ROUND_CYCLE)
        {
            if (entry->next_hop == NULL)
            {
                if(entry->distance == MAX_DISTANCE){
                    entry->last_message_round = ROUND_CYCLE;
                }
            }
            else
            {
                if (entry->distance == MAX_DISTANCE)
                    delete_entry(i, n, route_table);
                else
                {
                    entry->distance = MAX_DISTANCE;
                    entry->last_message_round = round_nr;
                }
            }
        }
    }
}

int main()
{
    int max_table_length = 25;
    int n;
    scanf("%d", &n);
    struct table_entry route_table[max_table_length];
    struct neighbour_entry neighbours[n];
    int my_IPs_nr = n;
    char *my_IPs[n];

    read_configuration(n, route_table, my_IPs, neighbours);

    int sockfd = create_socket_and_bind();
    if (sockfd < 0)
        return EXIT_FAILURE;

    struct pollfd ps;
    ps.fd = sockfd;
    ps.events = POLLIN;
    ps.revents = 0;
    int timeout = 1000;

    time_t start_time = time(NULL);
    time_t next_round = start_time;
    time_t next_printing = start_time;

    int round_nr = 0;

    while (1)
    {
        time_t current_time = time(NULL);

        if (current_time >= next_round)
        {
            next_round += ROUND;
            send_all(sockfd, n, route_table, my_IPs_nr, neighbours, round_nr);
            check_and_update_reachability(route_table, &n, round_nr);
            round_nr = (round_nr + 1) % ROUND_CYCLE;
        }

        if (current_time >= next_printing)
        {
            printing(n, route_table);
            next_printing += PRINT_INTERVAL;
        }

        int ready = poll(&ps, 1, timeout);
        if (ready > 0 && ps.revents & POLLIN)
        {
            if (recive_udp(sockfd, &n, route_table, round_nr, my_IPs_nr, my_IPs, neighbours) < 0)
                return EXIT_FAILURE;
        }
        else if (ready < 0)
        {
            fprintf(stderr, "poll error: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < n; i++)
    {
        free(route_table[i].IP);
        free(route_table[i].next_hop);
    }

    for (int i = 0; i < my_IPs_nr; i++)
    {
        free(my_IPs[i]);
        free(neighbours[i].entry.IP);
    }

    close(sockfd);

    return 0;
}