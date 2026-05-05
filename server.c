#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#ifdef __APPLE__
#include <util.h> // macOS forkpty
#else
#include <pty.h>  // Linux forkpty
#endif
#include <sys/select.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/ioctl.h>
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

int read_exact(SSL *ssl, void *buf, size_t count) {
    size_t total_read = 0;
    while (total_read < count) {
        ssize_t n = SSL_read(ssl, (char*)buf + total_read, count - total_read);
        if (n <= 0) return (int)n;
        total_read += n;
    }
    return (int)total_read;
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

void handle_scp_pull(SSL *ssl) {
    char remote_file[1024];
    read_until_newline(ssl, remote_file, sizeof(remote_file));
    remote_file[strcspn(remote_file, "\n")] = 0;
    
    struct stat st;
    if (stat(remote_file, &st) < 0) {
        char err[] = "-1\n";
        SSL_write(ssl, err, strlen(err));
        return;
    }
    
    char header[256];
    snprintf(header, sizeof(header), "%ld\n%lo\n%ld\n", (long)st.st_size, (long)(st.st_mode & 0777), (long)st.st_mtime);
    SSL_write(ssl, header, strlen(header));
    
    int fd = open(remote_file, O_RDONLY);
    if (fd < 0) return;
    
    char buf[4096];
    long sent = 0;
    while(sent < st.st_size) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) break;
        SSL_write(ssl, buf, n);
        sent += n;
    }
    close(fd);
}

void handle_scp_push(SSL *ssl) {
    char remote_file[1024];
    read_until_newline(ssl, remote_file, sizeof(remote_file));
    remote_file[strcspn(remote_file, "\n")] = 0;
    
    char size_str[128], mode_str[128], mtime_str[128];
    read_until_newline(ssl, size_str, sizeof(size_str));
    long size = atol(size_str);
    
    read_until_newline(ssl, mode_str, sizeof(mode_str));
    long mode = strtol(mode_str, NULL, 8);
    if (mode == 0) mode = 0644;
    
    read_until_newline(ssl, mtime_str, sizeof(mtime_str));
    long mtime = atol(mtime_str);
    
    int fd = open(remote_file, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return;
    
    char ok[] = "OK\n";
    SSL_write(ssl, ok, strlen(ok));
    
    char buf[4096];
    long received = 0;
    while(received < size) {
        long to_read = (size - received < (long)sizeof(buf)) ? (size - received) : (long)sizeof(buf);
        int n = SSL_read(ssl, buf, to_read);
        if (n <= 0) break;
        write(fd, buf, n);
        received += n;
    }
    close(fd);
    
    struct timeval tv[2];
    tv[0].tv_sec = mtime; tv[0].tv_usec = 0;
    tv[1].tv_sec = mtime; tv[1].tv_usec = 0;
    utimes(remote_file, tv);
    chmod(remote_file, mode);
}

void handle_client(SSL *ssl)
{
    int client_fd = SSL_get_fd(ssl);
    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    
    if (pid == -1) {
        perror("forkpty");
        return;
    }
    
    if (pid == 0) {
        // Child process: set terminal environment and run a shell/login
        setenv("TERM", "xterm-256color", 1);
        
#ifdef __APPLE__
        char *args[] = {"/usr/bin/login", NULL};
        execv(args[0], args);
        
        char *args_sh[] = {"/bin/zsh", "-l", NULL};
        execv(args_sh[0], args_sh);
#else
        if (getuid() == 0) {
            char *args[] = {"/bin/login", NULL};
            execv(args[0], args);
        } else {
            printf("C-SSH: Running as non-root on Linux. Bypassing native login.\n");
            fflush(stdout);
        }
        
        char *args_sh[] = {"/bin/bash", "-l", NULL};
        execv(args_sh[0], args_sh);
        
        char *args_sh2[] = {"/bin/sh", "-l", NULL};
        execv(args_sh2[0], args_sh2);
#endif
        
        perror("execv");
        exit(1);
    } else {
        // Parent process: forward data between the socket and the pty master fd
        fd_set fds;
        char buffer[4096];
        int tunnel_fd = -1;
        int server_tunnel_listen_fd = -1;
        
        while (1) {
            FD_ZERO(&fds);
            FD_SET(client_fd, &fds);
            FD_SET(master_fd, &fds);
            
            int max_fd = (client_fd > master_fd) ? client_fd : master_fd;
            
            if (server_tunnel_listen_fd != -1) {
                FD_SET(server_tunnel_listen_fd, &fds);
                if (server_tunnel_listen_fd > max_fd) max_fd = server_tunnel_listen_fd;
            }
            if (tunnel_fd != -1) {
                FD_SET(tunnel_fd, &fds);
                if (tunnel_fd > max_fd) max_fd = tunnel_fd;
            }
            
            int pending = SSL_pending(ssl);
            if (pending == 0) {
                if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
            }
            
            // Data from network, write to pty
            if (pending > 0 || FD_ISSET(client_fd, &fds)) {
                uint8_t type;
                if (read_exact(ssl, &type, 1) <= 0) break;
                uint32_t len;
                if (read_exact(ssl, &len, 4) <= 0) break;
                len = ntohl(len);
                
                if (type == 0) {
                    while (len > 0) {
                        int to_read = len > sizeof(buffer) ? sizeof(buffer) : len;
                        int n = read_exact(ssl, buffer, to_read);
                        if (n <= 0) goto disconnect;
                        write(master_fd, buffer, n);
                        len -= n;
                    }
                } else if (type == 1) {
                    struct winsize ws;
                    if (len == sizeof(ws)) {
                        if (read_exact(ssl, &ws, sizeof(ws)) <= 0) goto disconnect;
                        ioctl(master_fd, TIOCSWINSZ, &ws);
                    } else {
                        while (len > 0) {
                            int to_read = len > sizeof(buffer) ? sizeof(buffer) : len;
                            int n = read_exact(ssl, buffer, to_read);
                            if (n <= 0) goto disconnect;
                            len -= n;
                        }
                    }
                } else if (type == 2) {
                    char target[512] = {0};
                    int to_read = len > 511 ? 511 : len;
                    if (read_exact(ssl, target, to_read) <= 0) goto disconnect;
                    target[to_read] = '\0';
                    if (len > 511) {
                        int drain = len - 511;
                        while (drain > 0) {
                            char dummy;
                            if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect;
                            drain--;
                        }
                    }
                    
                    uint8_t status = 0;
                    char *colon = strchr(target, ':');
                    if (colon && tunnel_fd == -1) {
                        *colon = 0;
                        int rport = atoi(colon + 1);
                        tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
                        if (tunnel_fd >= 0) {
                            struct sockaddr_in raddr;
                            raddr.sin_family = AF_INET;
                            raddr.sin_port = htons(rport);
                            inet_pton(AF_INET, target, &raddr.sin_addr);
                            
                            if (connect(tunnel_fd, (struct sockaddr*)&raddr, sizeof(raddr)) == 0) {
                                status = 1;
                            } else {
                                close(tunnel_fd);
                                tunnel_fd = -1;
                            }
                        }
                    }
                    
                    uint8_t t = 3;
                    uint32_t l = htonl(1);
                    SSL_write(ssl, &t, 1);
                    SSL_write(ssl, &l, 4);
                    SSL_write(ssl, &status, 1);
                } else if (type == 4) {
                    while (len > 0) {
                        int to_read = len > sizeof(buffer) ? sizeof(buffer) : len;
                        int n = read_exact(ssl, buffer, to_read);
                        if (n <= 0) goto disconnect;
                        if (tunnel_fd != -1) {
                            write(tunnel_fd, buffer, n);
                        }
                        len -= n;
                    }
                } else if (type == 5) {
                    if (tunnel_fd != -1) {
                        close(tunnel_fd);
                        tunnel_fd = -1;
                    }
                    while (len > 0) {
                        char dummy;
                        if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect;
                        len--;
                    }
                } else if (type == 6) {
                    char target[128] = {0};
                    int to_read = len > 127 ? 127 : len;
                    if (read_exact(ssl, target, to_read) <= 0) goto disconnect;
                    target[to_read] = '\0';
                    if (len > 127) {
                        int drain = len - 127;
                        while(drain--) { char d; if(read_exact(ssl, &d, 1) <= 0) goto disconnect; }
                    }
                    
                    int rport = atoi(target);
                    uint8_t status = 0;
                    if (server_tunnel_listen_fd == -1 && rport > 0) {
                        server_tunnel_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                        int opt = 1;
                        setsockopt(server_tunnel_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
                        struct sockaddr_in l_addr;
                        l_addr.sin_family = AF_INET;
                        l_addr.sin_addr.s_addr = INADDR_ANY;
                        l_addr.sin_port = htons(rport);
                        if (bind(server_tunnel_listen_fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) == 0) {
                            listen(server_tunnel_listen_fd, 5);
                            status = 1;
                        } else {
                            close(server_tunnel_listen_fd);
                            server_tunnel_listen_fd = -1;
                        }
                    }
                    uint8_t t = 7;
                    uint32_t l = htonl(1);
                    SSL_write(ssl, &t, 1);
                    SSL_write(ssl, &l, 4);
                    SSL_write(ssl, &status, 1);
                } else if (type == 9) {
                    uint8_t status;
                    if (read_exact(ssl, &status, 1) <= 0) goto disconnect;
                    len--;
                    while(len > 0) { char d; if(read_exact(ssl, &d, 1) <= 0) goto disconnect; len--; }
                    if (status == 0 && tunnel_fd != -1) {
                        close(tunnel_fd);
                        tunnel_fd = -1;
                    }
                } else {
                    while (len > 0) {
                        int to_read = len > sizeof(buffer) ? sizeof(buffer) : len;
                        int n = read_exact(ssl, buffer, to_read);
                        if (n <= 0) goto disconnect;
                        len -= n;
                    }
                }
            }
            
            // Data from pty, write to network
            if (FD_ISSET(master_fd, &fds)) {
                int n = read(master_fd, buffer, sizeof(buffer));
                if (n <= 0) break;
                uint8_t type = 0;
                uint32_t len = htonl(n);
                SSL_write(ssl, &type, 1);
                SSL_write(ssl, &len, 4);
                SSL_write(ssl, buffer, n);
            }
            
            // New connection on server remote port
            if (server_tunnel_listen_fd != -1 && FD_ISSET(server_tunnel_listen_fd, &fds)) {
                struct sockaddr_in addr;
                socklen_t addrlen = sizeof(addr);
                int new_fd = accept(server_tunnel_listen_fd, (struct sockaddr*)&addr, &addrlen);
                if (new_fd >= 0) {
                    if (tunnel_fd == -1) {
                        tunnel_fd = new_fd;
                        uint8_t t = 8;
                        uint32_t l = htonl(0);
                        SSL_write(ssl, &t, 1);
                        SSL_write(ssl, &l, 4);
                    } else {
                        close(new_fd);
                    }
                }
            }
            
            // Data from tunnel, write to network
            if (tunnel_fd != -1 && FD_ISSET(tunnel_fd, &fds)) {
                int n = read(tunnel_fd, buffer, sizeof(buffer));
                if (n <= 0) {
                    close(tunnel_fd);
                    tunnel_fd = -1;
                    uint8_t t = 5;
                    uint32_t l = htonl(0);
                    SSL_write(ssl, &t, 1);
                    SSL_write(ssl, &l, 4);
                } else {
                    uint8_t t = 4;
                    uint32_t l = htonl(n);
                    SSL_write(ssl, &t, 1);
                    SSL_write(ssl, &l, 4);
                    SSL_write(ssl, buffer, n);
                }
            }
        }
disconnect:
        if (tunnel_fd != -1) close(tunnel_fd);
        if (server_tunnel_listen_fd != -1) close(server_tunnel_listen_fd);
        close(client_fd);
        close(master_fd);
        waitpid(pid, NULL, 0);
    }
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) { perror("Unable to create SSL context"); exit(EXIT_FAILURE); }
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr); exit(EXIT_FAILURE);
    }

    int server_fd, client_fd;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    int active_port = load_config_port();

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
    address.sin_port = htons(active_port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("SSH-like server listening on port %d...\n", active_port);

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
            
            SSL *ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);
            if (SSL_accept(ssl) <= 0) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            
            char mode;
            if (SSL_read(ssl, &mode, 1) > 0) {
                if (mode == '1') {
                    handle_client(ssl);
                } else if (mode == '2') {
                    handle_scp_pull(ssl);
                } else if (mode == '3') {
                    handle_scp_push(ssl);
                }
            }
            
            printf("Client disconnected.\n");
            SSL_free(ssl);
            exit(0);
        }
        close(client_fd);
    }
    
    return 0;
}
