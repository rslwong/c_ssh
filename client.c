#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8022

int sock_fd_global = -1;
volatile sig_atomic_t win_resized = 0;

void sigwinch_handler(int sig) {
    (void)sig;
    win_resized = 1;
}

void send_window_size(SSL *ssl) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1) return;
    
    uint8_t type = 1;
    uint32_t len = htonl(sizeof(ws));
    SSL_write(ssl, &type, 1);
    SSL_write(ssl, &len, 4);
    SSL_write(ssl, &ws, sizeof(ws));
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

struct termios orig_termios;

void disable_raw_mode() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
}

void enable_raw_mode() {
    tcgetattr(STDIN_FILENO, &orig_termios);
    atexit(disable_raw_mode);
    
    struct termios raw = orig_termios;
    // Put terminal in raw mode: disable canonical mode, echo, signals, etc.
    // The server's PTY will handle echo and input processing.
    raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_oflag &= ~(OPOST);
    raw.c_cflag |= (CS8);
    raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
    
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <server_ip> [-L local_port:remote_ip:remote_port | -R remote_port:local_ip:local_port]\n", argv[0]);
        return 1;
    }

    int is_local_forward = 0;
    int is_remote_forward = 0;
    char *tunnel_arg = NULL;

    if (argc >= 4) {
        if (strcmp(argv[2], "-L") == 0) {
            is_local_forward = 1;
            tunnel_arg = argv[3];
        } else if (strcmp(argv[2], "-R") == 0) {
            is_remote_forward = 1;
            tunnel_arg = argv[3];
        } else {
            tunnel_arg = argv[2];
            is_local_forward = 1;
        }
    } else if (argc == 3) {
        tunnel_arg = argv[2];
        is_local_forward = 1;
    }
    
    int tunnel_listen_port = 0;
    char tunnel_target_ip[256] = {0};
    int tunnel_target_port = 0;

    if (tunnel_arg) {
        char *p1 = strchr(tunnel_arg, ':');
        if (p1) {
            *p1 = 0;
            tunnel_listen_port = atoi(tunnel_arg);
            char *p2 = strchr(p1 + 1, ':');
            if (p2) {
                *p2 = 0;
                strncpy(tunnel_target_ip, p1 + 1, sizeof(tunnel_target_ip)-1);
                tunnel_target_port = atoi(p2 + 1);
            }
        }
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    
    int active_port = load_config_port();
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(active_port);
    
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    
    printf("Connected to %s:%d\n", argv[1], active_port);
    
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Verify server certificate fingerprint
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int n;
        X509_digest(cert, EVP_sha256(), md, &n);
        
        char fingerprint[EVP_MAX_MD_SIZE * 3] = {0};
        for (unsigned int i = 0; i < n; i++) {
            sprintf(fingerprint + (i * 3), "%02X%c", md[i], (i == n - 1) ? '\0' : ':');
        }
        
        int found = 0;
        int mismatch = 0;
        FILE *f = fopen("c_ssh_known_hosts", "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                char host[256], fp[256];
                if (sscanf(line, "%s %s", host, fp) == 2) {
                    if (strcmp(host, argv[1]) == 0) {
                        found = 1;
                        if (strcmp(fp, fingerprint) != 0) {
                            mismatch = 1;
                        }
                        break;
                    }
                }
            }
            fclose(f);
        }
        
        if (mismatch) {
            printf("\r\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\r\n");
            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\r\n");
            printf("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\r\n");
            printf("Someone could be eavesdropping on you right now (man-in-the-middle attack)!\r\n");
            printf("The SHA256 fingerprint for the %s host sent by the remote host is\r\n%s.\r\n", argv[1], fingerprint);
            printf("Please contact your system administrator.\r\n");
            return -1;
        }
        
        if (!found) {
            printf("The authenticity of host '%s' can't be established.\r\n", argv[1]);
            printf("SHA256 key fingerprint is %s.\r\n", fingerprint);
            printf("Are you sure you want to continue connecting (yes/no)? ");
            fflush(stdout);
            char resp[16];
            if (fgets(resp, sizeof(resp), stdin)) {
                if (strncmp(resp, "yes", 3) != 0) {
                    printf("Aborted by user.\n");
                    return -1;
                }
                FILE *wf = fopen("c_ssh_known_hosts", "a");
                if (wf) {
                    fprintf(wf, "%s %s\n", argv[1], fingerprint);
                    fclose(wf);
                    printf("Warning: Permanently added '%s' (SHA256) to the list of known hosts.\r\n", argv[1]);
                }
            } else {
                return -1;
            }
        }
        X509_free(cert);
    } else {
        printf("No certificate presented by server.\n");
        return -1;
    }
    
    // Handshake: tell server we want an interactive shell
    char mode = '1';
    SSL_write(ssl, &mode, 1);
    
    int tunnel_listen_fd = -1;
    int tunnel_client_fd = -1;
    
    if (is_local_forward && tunnel_listen_port > 0) {
        tunnel_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        int opt = 1;
        setsockopt(tunnel_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in l_addr;
        l_addr.sin_family = AF_INET;
        l_addr.sin_addr.s_addr = INADDR_ANY;
        l_addr.sin_port = htons(tunnel_listen_port);
        if (bind(tunnel_listen_fd, (struct sockaddr*)&l_addr, sizeof(l_addr)) < 0) {
            perror("bind tunnel");
            return 1;
        }
        listen(tunnel_listen_fd, 5);
        printf("Listening for local tunnel on port %d -> %s:%d\n", tunnel_listen_port, tunnel_target_ip, tunnel_target_port);
    } else if (is_remote_forward && tunnel_listen_port > 0) {
        printf("Requesting remote tunnel on port %d -> %s:%d\n", tunnel_listen_port, tunnel_target_ip, tunnel_target_port);
        char payload[128];
        snprintf(payload, sizeof(payload), "%d", tunnel_listen_port);
        uint8_t t = 6;
        uint32_t l = htonl(strlen(payload));
        SSL_write(ssl, &t, 1);
        SSL_write(ssl, &l, 4);
        SSL_write(ssl, payload, strlen(payload));
    }
    
    // Switch client terminal to raw mode
    enable_raw_mode();
    
    sock_fd_global = sock;
    signal(SIGWINCH, sigwinch_handler);
    send_window_size(ssl);
    
    fd_set fds;
    char buffer[4096];
    
    while (1) {
        if (win_resized) {
            send_window_size(ssl);
            win_resized = 0;
        }

        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock, &fds);
        
        int max_fd = sock;
        if (tunnel_listen_fd != -1) {
            FD_SET(tunnel_listen_fd, &fds);
            if (tunnel_listen_fd > max_fd) max_fd = tunnel_listen_fd;
        }
        if (tunnel_client_fd != -1) {
            FD_SET(tunnel_client_fd, &fds);
            if (tunnel_client_fd > max_fd) max_fd = tunnel_client_fd;
        }
        
        int pending = SSL_pending(ssl);
        if (pending == 0) {
            if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                if (errno == EINTR) continue;
                break;
            }
        }
        
        if (tunnel_listen_fd != -1 && FD_ISSET(tunnel_listen_fd, &fds)) {
            struct sockaddr_in addr;
            socklen_t addrlen = sizeof(addr);
            int new_fd = accept(tunnel_listen_fd, (struct sockaddr*)&addr, &addrlen);
            if (new_fd >= 0) {
                if (tunnel_client_fd == -1) {
                    tunnel_client_fd = new_fd;
                    char payload[512];
                    snprintf(payload, sizeof(payload), "%s:%d", tunnel_target_ip, tunnel_target_port);
                    uint8_t t = 2;
                    uint32_t l = htonl(strlen(payload));
                    SSL_write(ssl, &t, 1);
                    SSL_write(ssl, &l, 4);
                    SSL_write(ssl, payload, strlen(payload));
                } else {
                    close(new_fd); // Reject if already tunneling
                }
            }
        }
        
        if (tunnel_client_fd != -1 && FD_ISSET(tunnel_client_fd, &fds)) {
            int n = read(tunnel_client_fd, buffer, sizeof(buffer));
            if (n <= 0) {
                close(tunnel_client_fd);
                tunnel_client_fd = -1;
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
        
        // Read input from the user, send over the socket
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            int n = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n <= 0) break;
            uint8_t type = 0;
            uint32_t len = htonl(n);
            SSL_write(ssl, &type, 1);
            SSL_write(ssl, &len, 4);
            SSL_write(ssl, buffer, n);
        }
        
        // Read output from the server, print to the user
        if (pending > 0 || FD_ISSET(sock, &fds)) {
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
                    write(STDOUT_FILENO, buffer, n);
                    len -= n;
                }
            } else if (type == 3) {
                uint8_t status;
                if (len == 1) {
                    if (read_exact(ssl, &status, 1) <= 0) goto disconnect;
                    if (status == 0 && tunnel_client_fd != -1) {
                        printf("\r\n[Tunnel connection refused by remote]\r\n");
                        close(tunnel_client_fd);
                        tunnel_client_fd = -1;
                    }
                } else {
                    while (len > 0) {
                        char dummy;
                        if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect;
                        len--;
                    }
                }
            } else if (type == 4) {
                while (len > 0) {
                    int to_read = len > sizeof(buffer) ? sizeof(buffer) : len;
                    int n = read_exact(ssl, buffer, to_read);
                    if (n <= 0) goto disconnect;
                    if (tunnel_client_fd != -1) {
                        write(tunnel_client_fd, buffer, n);
                    }
                    len -= n;
                }
            } else if (type == 5) {
                if (tunnel_client_fd != -1) {
                    close(tunnel_client_fd);
                    tunnel_client_fd = -1;
                }
                while (len > 0) {
                    char dummy;
                    if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect;
                    len--;
                }
            } else if (type == 7) {
                uint8_t status;
                if (len == 1) {
                    if (read_exact(ssl, &status, 1) <= 0) goto disconnect;
                    if (status == 0) {
                        printf("\r\n[Server failed to bind remote port %d]\r\n", tunnel_listen_port);
                    }
                } else {
                    while (len > 0) {
                        char dummy; if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect; len--;
                    }
                }
            } else if (type == 8) {
                uint8_t status = 0;
                if (tunnel_client_fd == -1) {
                    tunnel_client_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (tunnel_client_fd >= 0) {
                        struct sockaddr_in raddr;
                        raddr.sin_family = AF_INET;
                        raddr.sin_port = htons(tunnel_target_port);
                        inet_pton(AF_INET, tunnel_target_ip, &raddr.sin_addr);
                        if (connect(tunnel_client_fd, (struct sockaddr*)&raddr, sizeof(raddr)) == 0) {
                            status = 1;
                        } else {
                            close(tunnel_client_fd);
                            tunnel_client_fd = -1;
                        }
                    }
                }
                uint8_t t = 9;
                uint32_t len_resp = htonl(1);
                SSL_write(ssl, &t, 1);
                SSL_write(ssl, &len_resp, 4);
                SSL_write(ssl, &status, 1);
                while (len > 0) {
                    char dummy; if (read_exact(ssl, &dummy, 1) <= 0) goto disconnect; len--;
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
    }
disconnect:
    if (tunnel_listen_fd != -1) close(tunnel_listen_fd);
    if (tunnel_client_fd != -1) close(tunnel_client_fd);
    close(sock);
    return 0;
}
