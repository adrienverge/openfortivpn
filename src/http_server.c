#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include "tunnel.h"



void* process_request(int new_socket) {
    log_info("Processing request\n");
    

    return NULL;
}

void* start_http_server(long saml_port) {
    

    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        log_error("Failed to create socket\n");
        return NULL;
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        log_error("Failed to set socket options\n");
        return NULL;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(saml_port);

    // Forcefully attaching socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_error("Failed to bind socket to port %d \n",saml_port);
        return NULL;
    }

    if (listen(server_fd, 3) < 0) {
        log_error("Failed to listen on socket\n");
        return NULL;
    }
    log_info("Listening for saml login on port: %d\n", saml_port);
    int running = 1;
    while(running) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            log_error("Failed to accept connection\n");
            continue;
        }
        process_request(new_socket);
    }

    return NULL;
}