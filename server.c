#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>

#define PORT 8080
#define BUFFER_SIZE 1024
#define DEFAULT_FILE "index.html"
#define DEBUG true

SSL_CTX *init_server_ctx() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void load_certificates(SSL_CTX *ctx, const char *cert_file, const char *key_file) {
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}

void handle_request(SSL *ssl, int client_socket) {
    char buffer[BUFFER_SIZE];
    ssize_t bytesRead;

    if (ssl) {
        bytesRead = SSL_read(ssl, buffer, sizeof(buffer));
    } else {
        bytesRead = recv(client_socket, buffer, sizeof(buffer), 0);
    }

    // Extract the requested file from the HTTP request
    char requested_file[256];
    sscanf(buffer, "GET %s", requested_file);
    
    if(DEBUG){
        printf("Requested File: %s\n", requested_file);
    }

    // Default to serving index.html if the requested file is a directory
    if (requested_file[strlen(requested_file) - 1] == '/') {
        strcat(requested_file, DEFAULT_FILE);
    }
    // Remove the leading slash, defaulting to serving index.html if the requested file is a directory
    if (requested_file[0] == '/') {
        memmove(requested_file, requested_file + 1, strlen(requested_file));
    }

    if(DEBUG){
        printf("Resolved File: %s\n", requested_file);
    }
    // Avoid directory traversal by checking for "..", "./" and "/"
    if (strstr(requested_file, "..") != NULL || strstr(requested_file, "./") != NULL || strstr(requested_file, "/") != NULL) {
        if(DEBUG){
            printf("Access Denied on File: %s\n", requested_file);
        }
        // Send an access denied response
        char response[] = "HTTP/1.1 403 Forbidden\r\n\r\nAccess Denied";
        if (ssl) {
            SSL_write(ssl, response, sizeof(response) - 1);
        } else {
            send(client_socket, response, sizeof(response) - 1, 0);
        }
    } else {
        // Open and send the requested file
        FILE *file = fopen(requested_file, "rb");
        if (file == NULL) {

            printf("File not found: %s\n", requested_file);

            char response[] = "HTTP/1.1 404 Not Found\r\n\r\nFile Not Found";
            if (ssl) {
                SSL_write(ssl, response, sizeof(response) - 1);
            } else {
                send(client_socket, response, sizeof(response) - 1, 0);
            }
        } else {
            // Read and send the file contents
            if(DEBUG){
                printf("Serving File: %s\n", requested_file);
            }

            char response[BUFFER_SIZE];
            sprintf(response, "HTTP/1.1 200 OK\r\n\r\n");

            if (ssl) {
                SSL_write(ssl, response, strlen(response));
            } else {
                send(client_socket, response, strlen(response), 0);
            }

            size_t bytesRead;
            while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
                if (ssl) {
                    SSL_write(ssl, buffer, bytesRead);
                } else {
                    send(client_socket, buffer, bytesRead, 0);
                }
            }

            fclose(file);
        }
    }

    // Cleanup SSL structures
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(client_socket);
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    SSL_CTX *ssl_ctx;

    // Check for the presence of SSL certificates in the command line arguments
    const char *cert_file = (argc > 1) ? argv[1] : NULL;
    const char *key_file = (argc > 2) ? argv[2] : NULL;

    // Initialize SSL context
    ssl_ctx = init_server_ctx();

    // Load certificates if provided
    if (cert_file && key_file) {
        load_certificates(ssl_ctx, cert_file, key_file);
        printf("Server running on HTTPS, port %d...\n", PORT);
    } else {
        printf("Server running on HTTP, port %d...\n", PORT);
    }

    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    // Initialize server address struct
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // Bind the server socket
    bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));

    // Listen for incoming connections
    listen(server_socket, 5);

    while (1) {
        // Accept a connection
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &addr_len);

        if (cert_file && key_file) {
            // If using SSL, create an SSL connection
            SSL *ssl = SSL_new(ssl_ctx);
            SSL_set_fd(ssl, client_socket);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                close(client_socket);
                continue;
            }

            // Handle the request in a separate function
            handle_request(ssl, -1);  // Use -1 to indicate SSL
        } else {
            // If not using SSL, handle the request directly
            handle_request(NULL, client_socket);
        }
    }

    // Close the server socket and cleanup SSL context
    close(server_socket);
    if (cert_file && key_file) {
        SSL_CTX_free(ssl_ctx);
    }

    return 0;
}
