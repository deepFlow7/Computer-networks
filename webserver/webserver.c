#include <arpa/inet.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_DIRECTORY_NAME_LENGTH 50
#define CONNECTION_TIME 1
#define SEND_BUFFER_SIZE 1000000
#define RECV_BUFFER_SIZE 1000

void send_response(int sockfd, char *response_code, char *content,
                   char *content_type, size_t content_length) {

  printf("%s, Cotent type: %s\n\n", response_code, content_type);

  if (content_length == 0)
    content_length = strlen(content);

  char buffer[SEND_BUFFER_SIZE + 1];

 

  if(strcmp(response_code, "301 Moved Permanently") == 0)
    snprintf(buffer, SEND_BUFFER_SIZE,
           "HTTP/1.1 %s\r\n"
           "Location: index.html\r\n"
            "Content-Type: %s\r\n"
          "Content-Length: %zu\r\n"
          "\r\n",
           response_code, content_type, content_length);
  else snprintf(buffer, SEND_BUFFER_SIZE,
           "HTTP/1.1 %s\r\n"
            "Content-Type: %s\r\n"
          "Content-Length: %zu\r\n"
          "\r\n",
           response_code, content_type, content_length);
   


  ssize_t bytes_sent = send(sockfd, buffer, strlen(buffer), 0);
  if (bytes_sent < 0)
    fprintf(stderr, "send error");
  bytes_sent = send(sockfd, content, content_length, 0);
  if (bytes_sent < 0)
    fprintf(stderr, "send error");
}

char *read_file(char *path, size_t *fsize) {
  FILE *f = fopen(path, "rb");

  fseek(f, 0, SEEK_END);
  *fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  char *content = malloc(*fsize + 1);
  fread(content, *fsize, 1, f);
  fclose(f);

  content[*fsize] = 0;
  return content;
}

char *type(char *path) {
  const char *ext = strrchr(path, '.');
  if (!ext)
    return "application/octet-stream; charset=utf-8";
  if (strcmp(ext, ".html") == 0)
    return "text/html; charset=utf-8";
  if (strcmp(ext, ".txt") == 0)
    return "text/plain; charset=utf-8";
  if (strcmp(ext, ".pdf") == 0)
    return "application/pdf; charset=utf-8";
  if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0)
    return "image/jpeg";
  if (strcmp(ext, ".png") == 0)
    return "image/png";
  if (strcmp(ext, ".css") == 0)
    return "text/css; charset=utf-8";
  return "application/octet-stream; charset=utf-8";
}

void process_request(int sockfd, char *directory, char *path, char *method,
                     char *host) {

  if (strcmp(method, "GET") != 0 || !host) {
    send_response(sockfd, "501 Not Implemented",
                  "<div>The request is not understood by the server.</div>",
                  "text/html; charset=utf-8", 0);
    return;
  }

  char *colon_position = strchr(host, ':');
  size_t domain_len = (colon_position != NULL) ? (size_t)(colon_position - host) : strlen(host);
  char domain[domain_len + 1];
  strncpy(domain, host, domain_len);
  domain[domain_len] = '\0';

  char full_path[MAX_DIRECTORY_NAME_LENGTH + 256];
  snprintf(full_path, sizeof(full_path), "%s/%s%s", directory, domain, path);

  printf("%s %s\n", method, full_path);

  if (strstr(path, "..")) {
    send_response(
        sockfd, "403 Forbidden",
        "<div>The file is located outside the domain directory.</div>",
        "text/html; charset=utf-8", 0);
    return;
  }

  struct stat file_info;
  
  if (stat(full_path, &file_info) != 0) {
    send_response(sockfd, "404 Not Found", "<div>File doesn't exist.</div>",
                  "text/html; charset=utf-8", 0);
    return;
  }

  if (S_ISDIR(file_info.st_mode)) {
    char index_html[] = "index.html";
    strcat(full_path, index_html);
    send_response(sockfd, "301 Moved Permanently", "<div>Redirect to index.html.</div>",
                  "text/html; charset=utf-8", 0);
    return;
  }

  size_t file_size;
  char *file_content = read_file(full_path, &file_size);
  if (file_content == NULL) {
    fprintf(stderr, "Failed to read file: %s\n", full_path);
    return;
  }

  send_response(sockfd, "200 OK",
                file_content, type(full_path), file_size);
  free(file_content);
}

int recive_and_process_request(int connected_sock_fd, char *directory) {
  u_int8_t buffer[RECV_BUFFER_SIZE + 1];
  ssize_t bytes_read = recv(connected_sock_fd, buffer, RECV_BUFFER_SIZE, 0);
  if (bytes_read < 0) {
    fprintf(stderr, "recvfrom error: %s\n", strerror(errno));
    return 0;
  }

  char method[16], path[256];
  sscanf((const char *)buffer, "%s %s", method, path);

  char *host_start = strstr((const char *)buffer, "Host:");
  char host[256] = {0};
  if (host_start)
    sscanf(host_start, "Host: %255s", host);

  char *connection_start = strstr((const char *)buffer, "Connection:");
  char connection[256] = {0};
  if (connection_start)
    sscanf(connection_start, "Connection: %255s", connection);

  process_request(connected_sock_fd, directory, path, method, host);
  return strcmp(connection, "close") == 0;
}

int read_and_check_arguments(int argc, char *argv[], int *port_nr,
                             char *directory) {
  if (argc != 3) {
    fprintf(stderr, "Incorrect number of arguments");
    return -1;
  }

  *port_nr = atoi(argv[1]);
  if (strspn(argv[1], "0123456789") != strlen(argv[1]) || *port_nr < 0 ||
      *port_nr > 49151) {
    fprintf(stderr, "incorrect port number: %s\n", argv[1]);
    return -1;
  }

  strcpy(directory, argv[2]);
  struct stat info;
  if (stat(directory, &info) != 0 || !S_ISDIR(info.st_mode)) {
    fprintf(stderr, "incorrect directory name: %s\n", argv[2]);
    return -1;
  }

  return 0;
}

int create_and_bind_socket(int port_nr) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    fprintf(stderr, "socket error: %s\n", strerror(errno));
    return -1;
  }

  int optval = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
    fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
    close(sockfd);
    return -1;
  }

  struct sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));

  server_address.sin_family = AF_INET;
  server_address.sin_port = htons(port_nr);
  server_address.sin_addr.s_addr = htonl(INADDR_ANY);

  if (bind(sockfd, (struct sockaddr *)&server_address,
           sizeof(server_address)) == -1) {
    fprintf(stderr, "bind error: %s\n", strerror(errno));
    close(sockfd);
    return -1;
  }
  if (listen(sockfd, 10) < 0) {
    fprintf(stderr, "listen error: %s\n", strerror(errno));
    close(sockfd);
    return -1;
  }
  return sockfd;
}

int handle_client(int sockfd, char *directory) {
  struct pollfd ps;
  ps.fd = sockfd;
  ps.events = POLLIN;
  ps.revents = 0;

  int timeout = 15;
  int time_to_exit = time(NULL) + CONNECTION_TIME;

  while (time_to_exit > time(NULL)) {

    
    int ready = poll(&ps, 1, timeout);
    if (ready > 0 && ps.revents & POLLIN) {
      if (recive_and_process_request(sockfd, directory) == 0)
        time_to_exit = time(NULL) + CONNECTION_TIME;
    } else if (ready < 0) {
      fprintf(stderr, "poll error: %s\n", strerror(errno));
      return -1;
    }

  }
  return 0;
}

int main(int argc, char *argv[]) {
  char directory[MAX_DIRECTORY_NAME_LENGTH];
  int port_nr;

  if (read_and_check_arguments(argc, argv, &port_nr, directory) < 0)
    return EXIT_FAILURE;

  int sockfd = create_and_bind_socket(port_nr);
  if (sockfd < 0)
    return EXIT_FAILURE;

  for (;;) {
    int connected_sock_fd = accept(sockfd, NULL, NULL);
    if (connected_sock_fd < 0) {
      close(sockfd);
      fprintf(stderr, "accept error: %s\n", strerror(errno));
      return EXIT_FAILURE;
    }

    handle_client(connected_sock_fd, directory);
    close(connected_sock_fd);
  }

  close(sockfd);

  return 0;
}
