#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include <pthread.h>
#include "tunnel.h"



int process_request(int new_socket, char *id) {
    log_info("Processing request\n");
    
    char *response = "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nContent-Type: text/plain\r\n\r\nHello, world!";
    ssize_t write_result = write(new_socket, response, strlen(response));
    (void)write_result;

    // Read the request
    char request[1024];
    ssize_t read_result = read(new_socket, request, sizeof(request));

    // Check for '=id' in the response
    if (read_result < 0 || strlen(request) < 10 || strncmp(request, "GET /?id=", 9) != 0) {
        log_error("Bad request\n");
        return -1;
    }

    // Extract the id
    const int id_start = 9;
    char *id_end = memchr(&request[id_start], ' ', 1000);

    if (id_end == NULL) {
        log_error("Bad request format\n");
        return -1;
    }

    int id_length = id_end - &request[id_start];

    if(id_length == 0 || id_length > 1000) {
        log_error("Bad request id\n");
        return -1;
    }

    strncpy(id, &request[id_start], id_length);

    for (int i = 0; i < id_length; i++) {
        if (isalnum(id[i]) || id[i] == '-') continue;
        log_error("Invalid id format\n");
        return -1;
    }

    log_info("Extracted id: %s\n", id);
    close(new_socket);
    return 0;
}

/**
 * run a http server to listen for saml login requests 
*/
void* start_http_server(struct vpn_config *config) {
    
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
    char *id[1024];
    config->saml_session_id = id;



    pthread_t vpn_thread = NULL;


    while(running) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            log_error("Failed to accept connection\n");
            continue;
        }

        int result = process_request(new_socket, config->saml_session_id);
        if(result != 0) {
            log_error("Failed to process request\n");
            continue;
        }


        // Kill previous thread if it exists
        if (vpn_thread != NULL) {
            log_error("Stop existing tunnel\n");
            pthread_cancel(vpn_thread);
            pthread_join(vpn_thread, NULL);
        }
        
        int thread_create_result = pthread_create(&vpn_thread, NULL, run_tunnel, &config);
        // if (thread_create_result != 0) {
        //     log_error("Failed to create VPN thread\n");
        //     continue;
        // }

    
        // pthread_detach(vpn_thread);

        result = 0;
    }

    return NULL;
}

