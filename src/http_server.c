#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netinet/tcp.h>

#include "config.h"
#include "log.h"
#include "tunnel.h"

int process_request(int new_socket, char *id) {
    log_info("Processing HTTP SAML request\n");

    int flag = 1;
    setsockopt(new_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    const char *reply = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "SAML Login...\r\n\0";

    ssize_t write_result = write(new_socket, reply, strlen(reply));
    (void)write_result;

    // Read the request
    char request[1024];
    ssize_t read_result = read(new_socket, request, sizeof(request));

    // Check for '=id' in the response
    // If the recevied request from the server is larger than the buffer, the result will not be null-terminated.
    // Causing strlen to behave wrong.
    if (read_result < 0 || read_result == sizeof(request) || strlen(request) < 10 || strncmp(request, "GET /?id=", 9) != 0) {
        log_error("Bad request\n");
        return -1;
    }

    // Extract the id
    const int id_start = 9;
    char *id_end = memchr(&request[id_start], ' ', sizeof(request) - id_start);

    if (id_end == NULL) {
        log_error("Bad request format\n");
        return -1;
    }

    int id_length = id_end - &request[id_start];

    if(id_length == 0 || id_length > MAX_SAML_SESSION_ID_LENGTH) {
        log_error("Bad request id\n");
        return -1;
    }

    strncpy(id, &request[id_start], id_length);

    for (int i = 0; i < id_length; i++) {
        if (isalnum(id[i]) || id[i] == '-') continue;
        log_error("Invalid id format\n");
        return -1;
    }
    close(new_socket);
    log_info("Extracted id: %s\n", id);
    return 0;
}

/**
 * run a http server to listen for saml login requests
*/
void* start_http_server(void *void_config) {
    struct vpn_config *config = (struct vpn_config *)void_config;

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    long saml_port = config->saml_port;

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_error("Failed to create socket\n");
        return NULL;
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        close(server_fd);
        log_error("Failed to set socket options\n");
        return NULL;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(saml_port);

    // Forcefully attaching socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(server_fd);
        log_error("Failed to bind socket to port %d \n",saml_port);
        return NULL;
    }

    if (listen(server_fd, 3) < 0) {
        close(server_fd);
        log_error("Failed to listen on socket\n");
        return NULL;
    }
    log_info("Listening for saml login on port: %d\n", saml_port);

    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            log_error("Failed to accept connection\n");
            continue;
        }

        int result = process_request(new_socket, config->saml_session_id);
        close(new_socket);
        if(result != 0) {
            log_error("Failed to process request\n");
            continue;
        }
        break;
    }

    close(server_fd);
    return NULL;
}

