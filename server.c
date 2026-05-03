#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util.h> // macOS forkpty
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>

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

void handle_scp_pull(int client_fd) {
    char remote_file[1024];
    read_until_newline(client_fd, remote_file, sizeof(remote_file));
    remote_file[strcspn(remote_file, "\n")] = 0;
    
    struct stat st;
    if (stat(remote_file, &st) < 0) {
        char err[] = "-1\n";
        write(client_fd, err, strlen(err));
        return;
    }
    
    char header[256];
    snprintf(header, sizeof(header), "%ld\n", (long)st.st_size);
    write(client_fd, header, strlen(header));
    
    int fd = open(remote_file, O_RDONLY);
    if (fd < 0) return;
    
    char buf[4096];
    long sent = 0;
    while(sent < st.st_size) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        write(client_fd, buf, n);
        sent += n;
    }
    close(fd);
}

void handle_scp_push(int client_fd) {
    char remote_file[1024];
    read_until_newline(client_fd, remote_file, sizeof(remote_file));
    remote_file[strcspn(remote_file, "\n")] = 0;
    
    char size_str[128];
    read_until_newline(client_fd, size_str, sizeof(size_str));
    long size = atol(size_str);
    
    int fd = open(remote_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    
    char ok[] = "OK\n";
    write(client_fd, ok, strlen(ok));
    
    char buf[4096];
    long received = 0;
    while(received < size) {
        long to_read = (size - received < (long)sizeof(buf)) ? (size - received) : (long)sizeof(buf);
        int n = read(client_fd, buf, to_read);
        if (n <= 0) break;
        write(fd, buf, n);
        received += n;
    }
    close(fd);
}

void handle_client(int client_fd) {
    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    
    if (pid == -1) {
        perror("forkpty");
        return;
    }
    
    if (pid == 0) {
        // Child process: set terminal environment and run a shell/login
        setenv("TERM", "xterm-256color", 1);
        
        // Try to use login to get an SSH-like password prompt. 
        // If run as non-root, this may just prompt for the current user's password.
        char *args[] = {"/usr/bin/login", NULL};
        execv(args[0], args);
        
        // Fallback to directly starting a shell if login fails or isn't available
        char *args_sh[] = {"/bin/zsh", "-l", NULL};
        execv(args_sh[0], args_sh);
        
        perror("execv");
        exit(1);
    } else {
        // Parent process: forward data between the socket and the pty master fd
        fd_set fds;
        char buffer[4096];
        
        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_fd, &fds);
            FD_SET(master_fd, &fds);
            
            int max_fd = (client_fd > master_fd) ? client_fd : master_fd;
            
            if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                break;
            }
            
            // Data from network, write to pty
            if (FD_ISSET(client_fd, &fds)) {
                int n = read(client_fd, buffer, sizeof(buffer));
                if (n <= 0) break;
                write(master_fd, buffer, n);
            }
            
            // Data from pty, write to network
            if (FD_ISSET(master_fd, &fds)) {
                int n = read(master_fd, buffer, sizeof(buffer));
                if (n <= 0) break;
                write(client_fd, buffer, n);
            }
        }
        close(client_fd);
        close(master_fd);
        waitpid(pid, NULL, 0);
    }
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("SSH-like server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        
        printf("Client connected.\n");
        
        // Handle each client connection in a child process
        if (fork() == 0) {
            close(server_fd);
            
            char mode;
            if (read(client_fd, &mode, 1) > 0) {
                if (mode == '1') {
                    handle_client(client_fd);
                } else if (mode == '2') {
                    handle_scp_pull(client_fd);
                } else if (mode == '3') {
                    handle_scp_push(client_fd);
                }
            }
            
            printf("Client disconnected.\n");
            exit(0);
        }
        close(client_fd);
    }
    
    return 0;
}
