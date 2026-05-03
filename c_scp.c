#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PORT 8022

int read_until_newline(int fd, char* buf, int max_len) {
    int i = 0;
    char c;
    while (i < max_len - 1) {
        if (read(fd, &c, 1) <= 0) break;
        buf[i++] = c;
        if (c == '\n') break;
    }
    buf[i] = '\0';
    return i;
}

int connect_to_server(const char* ip) {
    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        exit(1);
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, ip, &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        exit(1);
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        exit(1);
    }
    return sock;
}

void push_file(const char* ip, const char* local_file, const char* remote_file) {
    int sock = connect_to_server(ip);
    char mode = '3';
    write(sock, &mode, 1);
    
    struct stat st;
    if (stat(local_file, &st) < 0) {
        perror("stat local file failed");
        close(sock);
        return;
    }
    long size = st.st_size;
    
    char header[1024];
    snprintf(header, sizeof(header), "%s\n%ld\n", remote_file, size);
    write(sock, header, strlen(header));
    
    char resp[16];
    read_until_newline(sock, resp, sizeof(resp));
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
        write(sock, buf, n);
        sent += n;
        printf("\rProgress: %ld/%ld bytes", sent, size);
        fflush(stdout);
    }
    printf("\nUpload complete.\n");
    close(fd);
    close(sock);
}

void pull_file(const char* ip, const char* remote_file, const char* local_file) {
    int sock = connect_to_server(ip);
    char mode = '2';
    write(sock, &mode, 1);
    
    char header[1024];
    snprintf(header, sizeof(header), "%s\n", remote_file);
    write(sock, header, strlen(header));
    
    char resp[128];
    read_until_newline(sock, resp, sizeof(resp));
    long size = atol(resp);
    if(size < 0) {
        printf("Remote file not found or error.\n");
        close(sock);
        return;
    }
    
    int fd = open(local_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open local file failed");
        close(sock);
        return;
    }
    
    char buf[4096];
    long received = 0;
    while(received < size) {
        long to_read = (size - received < (long)sizeof(buf)) ? (size - received) : (long)sizeof(buf);
        int n = read(sock, buf, to_read);
        if(n <= 0) break;
        write(fd, buf, n);
        received += n;
        printf("\rProgress: %ld/%ld bytes", received, size);
        fflush(stdout);
    }
    printf("\nDownload complete.\n");
    close(fd);
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
