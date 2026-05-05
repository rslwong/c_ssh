#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8022

int load_config_port() {
    int parsed_port = PORT;
    FILE *f = fopen("c_ssh_config", "r");
    if (!f) return parsed_port;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "PORT=", 5) == 0) {
            parsed_port = atoi(line + 5);
        }
    }
    fclose(f);
    return parsed_port;
}

int read_until_newline(SSL *ssl, char* buf, int max_len) {
    int i = 0;
    char c;
    while (i < max_len - 1) {
        if (SSL_read(ssl, &c, 1) <= 0) break;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return i;
}

SSL* connect_to_server(const char* ip) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    int active_port = load_config_port();
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        exit(1);
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(active_port);
    
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        exit(1);
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        exit(1);
    }
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ssl;
}

void push_file(const char* ip, const char* local_file, const char* remote_file) {
    SSL *ssl = connect_to_server(ip);
    int sock = SSL_get_fd(ssl);
    char mode = '3';
    SSL_write(ssl, &mode, 1);
    
    struct stat st;
    if (stat(local_file, &st) < 0) {
        perror("stat local file failed");
        close(sock);
        return;
    }
    long size = st.st_size;
    long file_mode = st.st_mode & 0777;
    long mtime = st.st_mtime;
    
    char header[1024];
    snprintf(header, sizeof(header), "%s\n%ld\n%lo\n%ld\n", remote_file, size, file_mode, mtime);
    SSL_write(ssl, header, strlen(header));
    
    char resp[16];
    read_until_newline(ssl, resp, sizeof(resp));
    if (strncmp(resp, "OK", 2) != 0) {
        printf("Server rejected push.\n");
        close(sock);
        return;
    }
    
    int fd = open(local_file, O_RDONLY);
    char buf[4096];
    long sent = 0;
    while(sent < size) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        SSL_write(ssl, buf, n);
        sent += n;
        printf("\rProgress: %ld/%ld bytes", sent, size);
        fflush(stdout);
    }
    printf("\nUpload complete.\n");
    close(fd);
    close(sock);
}

void pull_file(const char* ip, const char* remote_file, const char* local_file) {
    SSL *ssl = connect_to_server(ip);
    int sock = SSL_get_fd(ssl);
    char mode = '2';
    SSL_write(ssl, &mode, 1);
    
    char header[1024];
    snprintf(header, sizeof(header), "%s\n", remote_file);
    SSL_write(ssl, header, strlen(header));
    
    char resp[128], mode_str[128], mtime_str[128];
    read_until_newline(ssl, resp, sizeof(resp));
    long size = atol(resp);
    if(size < 0) {
        printf("Remote file not found or error.\n");
        close(sock);
        return;
    }
    
    read_until_newline(ssl, mode_str, sizeof(mode_str));
    long file_mode = strtol(mode_str, NULL, 8);
    if (file_mode == 0) file_mode = 0644;
    
    read_until_newline(ssl, mtime_str, sizeof(mtime_str));
    long mtime = atol(mtime_str);
    
    int fd = open(local_file, O_WRONLY | O_CREAT | O_TRUNC, file_mode);
    if (fd < 0) {
        perror("open local file failed");
        close(sock);
        return;
    }
    
    char buf[4096];
    long received = 0;
    while(received < size) {
        long to_read = (size - received < (long)sizeof(buf)) ? (size - received) : (long)sizeof(buf);
        int n = SSL_read(ssl, buf, to_read);
        if(n <= 0) break;
        write(fd, buf, n);
        received += n;
        printf("\rProgress: %ld/%ld bytes", received, size);
        fflush(stdout);
    }
    printf("\nDownload complete.\n");
    close(fd);
    
    struct timeval tv[2];
    tv[0].tv_sec = mtime; tv[0].tv_usec = 0;
    tv[1].tv_sec = mtime; tv[1].tv_usec = 0;
    utimes(local_file, tv);
    chmod(local_file, file_mode);
    
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("  Push: %s <local_file> <IP>:<remote_file>\n", argv[0]);
        printf("  Pull: %s <IP>:<remote_file> <local_file>\n", argv[0]);
        return 1;
    }

    if (strchr(argv[1], ':') != NULL) {
        // Pull
        char* ip = strtok(argv[1], ":");
        char* remote_file = strtok(NULL, ":");
        char* local_file = argv[2];
        pull_file(ip, remote_file, local_file);
    } else if (strchr(argv[2], ':') != NULL) {
        // Push
        char* local_file = argv[1];
        char* ip = strtok(argv[2], ":");
        char* remote_file = strtok(NULL, ":");
        push_file(ip, local_file, remote_file);
    } else {
        printf("Invalid syntax. Use IP:filename to specify the remote target.\n");
    }

    return 0;
}
