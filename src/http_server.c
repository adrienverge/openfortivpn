#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "log.h"
#include <pthread.h>
#include "tunnel.h"
#include <ctype.h>
#include <signal.h>
#include <netinet/tcp.h>



int process_request(int new_socket, char *id) {
    log_info("Processing request\n");
    
    int flag = 1;
    setsockopt(new_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    const int buffer_size = 2048;
    char *response[buffer_size];
    memset(response,' ',buffer_size);
    response[buffer_size - 1] = '\0';
    char *reply = "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Connection: close\r\n\r\n"
            "SAML Login...\r\n\0";
    memcpy(response,reply,strlen(reply));

    // Read the request
    ssize_t write_result = write(new_socket, response, buffer_size);
    (void)write_result;

    // dup2(new_socket, STDOUT_FILENO);
    // dup2(new_socket, STDERR_FILENO);



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
    // close(new_socket);
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

    pthread_t vpn_thread = 0;


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
        if (vpn_thread != 0) {
            log_error("Stop existing tunnel\n");
            pthread_kill(vpn_thread,SIGTERM);
            pthread_join(vpn_thread, NULL);
        }
        
        int thread_create_result = pthread_create(&vpn_thread, NULL, run_tunnel_wrapper, (void *)config);
        if (thread_create_result != 0) {
            log_error("Failed to create VPN thread\n");
            continue;
        }

    
        // pthread_detach(vpn_thread);

        result = 0;
    }

    return NULL;
}

