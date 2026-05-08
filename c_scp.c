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
#include <dirent.h>
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
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
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
                    if (strcmp(host, ip) == 0) {
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
            printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
            printf("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n");
            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
            printf("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n");
            printf("Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n");
            printf("The SHA256 fingerprint for the %s host sent by the remote host is\n%s.\n", ip, fingerprint);
            printf("Please contact your system administrator.\n");
            exit(1);
        }
        
        if (!found) {
            printf("The authenticity of host '%s' can't be established.\n", ip);
            printf("SHA256 key fingerprint is %s.\n", fingerprint);
            printf("Are you sure you want to continue connecting (yes/no)? ");
            fflush(stdout);
            char resp[16];
            if (fgets(resp, sizeof(resp), stdin)) {
                if (strncmp(resp, "yes", 3) != 0) {
                    printf("Aborted by user.\n");
                    exit(1);
                }
                FILE *wf = fopen("c_ssh_known_hosts", "a");
                if (wf) {
                    fprintf(wf, "%s %s\n", ip, fingerprint);
                    fclose(wf);
                    printf("Warning: Permanently added '%s' (SHA256) to the list of known hosts.\n", ip);
                }
            } else {
                exit(1);
            }
        }
        X509_free(cert);
    } else {
        printf("No certificate presented by server.\n");
        exit(1);
    }
    return ssl;
}

void send_file_push(SSL *ssl, const char* local_path, const char* remote_path) {
    struct stat st;
    if (stat(local_path, &st) < 0) {
        perror("stat failed");
        return;
    }
    
    if (S_ISDIR(st.st_mode)) {
        char header[2048];
        snprintf(header, sizeof(header), "D %s\n%lo\n%ld\n", remote_path, (long)(st.st_mode & 0777), (long)st.st_mtime);
        SSL_write(ssl, header, strlen(header));
        
        char resp[16];
        read_until_newline(ssl, resp, sizeof(resp)); // Wait for OK
        
        DIR *dir = opendir(local_path);
        if (dir) {
            struct dirent *entry;
            while ((entry = readdir(dir)) != NULL) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
                char sub_local[2048], sub_remote[2048];
                snprintf(sub_local, sizeof(sub_local), "%s/%s", local_path, entry->d_name);
                snprintf(sub_remote, sizeof(sub_remote), "%s/%s", remote_path, entry->d_name);
                send_file_push(ssl, sub_local, sub_remote);
            }
            closedir(dir);
        }
    } else {
        char header[2048];
        snprintf(header, sizeof(header), "F %s\n%ld\n%lo\n%ld\n", remote_path, (long)st.st_size, (long)(st.st_mode & 0777), (long)st.st_mtime);
        SSL_write(ssl, header, strlen(header));
        
        char resp[16];
        read_until_newline(ssl, resp, sizeof(resp));
        if (strncmp(resp, "OK", 2) != 0) {
            printf("Server rejected push of %s\n", remote_path);
            return;
        }
        
        int fd = open(local_path, O_RDONLY);
        if (fd >= 0) {
            char buf[4096];
            long sent = 0;
            while (sent < st.st_size) {
                int n = read(fd, buf, sizeof(buf));
                if (n <= 0) break;
                SSL_write(ssl, buf, n);
                sent += n;
            }
            close(fd);
            printf("Pushed: %s (%ld bytes)\n", remote_path, (long)st.st_size);
        }
    }
}

void push_file(const char* ip, const char* local_file, const char* remote_file) {
    SSL *ssl = connect_to_server(ip);
    char mode = '3';
    SSL_write(ssl, &mode, 1);
    
    send_file_push(ssl, local_file, remote_file);
    SSL_write(ssl, "Q\n", 2);
    
    SSL_free(ssl);
}

void pull_file(const char* ip, const char* remote_file, const char* local_file) {
    SSL *ssl = connect_to_server(ip);
    char mode = '2';
    SSL_write(ssl, &mode, 1);
    
    char header[1024];
    snprintf(header, sizeof(header), "%s\n", remote_file);
    SSL_write(ssl, header, strlen(header));
    
    char cmd[2048];
    while (read_until_newline(ssl, cmd, sizeof(cmd)) > 0) {
        cmd[strcspn(cmd, "\n")] = 0;
        if (strcmp(cmd, "Q") == 0) break;
        if (strcmp(cmd, "ERR") == 0) {
            printf("Remote error.\n");
            break;
        }
        
        char type = cmd[0];
        char *path = cmd + 2;
        
        // Map remote path back to local path relative to target
        // For simplicity, we assume we are pulling into local_file (which could be a directory)
        // If pulling a single file, it's local_file.
        // If pulling a directory, we need to handle paths.
        
        // Simple logic: if path starts with remote_file, replace it with local_file
        char actual_local[2048];
        if (strncmp(path, remote_file, strlen(remote_file)) == 0) {
            snprintf(actual_local, sizeof(actual_local), "%s%s", local_file, path + strlen(remote_file));
        } else {
            strncpy(actual_local, path, sizeof(actual_local));
        }

        if (type == 'F') {
            char size_str[128], mode_str[128], mtime_str[128];
            read_until_newline(ssl, size_str, sizeof(size_str));
            long size = atol(size_str);
            read_until_newline(ssl, mode_str, sizeof(mode_str));
            long mode_val = strtol(mode_str, NULL, 8);
            read_until_newline(ssl, mtime_str, sizeof(mtime_str));
            long mtime = atol(mtime_str);
            
            int fd = open(actual_local, O_WRONLY | O_CREAT | O_TRUNC, mode_val);
            if (fd >= 0) {
                char buf[4096];
                long received = 0;
                while (received < size) {
                    long to_read = (size - received < (long)sizeof(buf)) ? (size - received) : (long)sizeof(buf);
                    int n = SSL_read(ssl, buf, (int)to_read);
                    if (n <= 0) break;
                    write(fd, buf, n);
                    received += n;
                }
                close(fd);
                struct timeval tv[2];
                tv[0].tv_sec = mtime; tv[0].tv_usec = 0;
                tv[1].tv_sec = mtime; tv[1].tv_usec = 0;
                utimes(actual_local, tv);
                chmod(actual_local, mode_val);
                printf("Pulled: %s (%ld bytes)\n", actual_local, size);
            } else {
                perror("open local failed");
            }
        } else if (type == 'D') {
            char mode_str[128], mtime_str[128];
            read_until_newline(ssl, mode_str, sizeof(mode_str));
            long mode_val = strtol(mode_str, NULL, 8);
            read_until_newline(ssl, mtime_str, sizeof(mtime_str));
            long mtime = atol(mtime_str);
            
            mkdir(actual_local, mode_val);
            struct timeval tv[2];
            tv[0].tv_sec = mtime; tv[0].tv_usec = 0;
            tv[1].tv_sec = mtime; tv[1].tv_usec = 0;
            utimes(actual_local, tv);
            chmod(actual_local, mode_val);
            printf("Created directory: %s\n", actual_local);
        }
    }
    SSL_free(ssl);
}

int main(int argc, char *argv[]) {
    int arg_idx = 1;
    if (argc > 1 && strcmp(argv[1], "-r") == 0) {
        arg_idx = 2;
    }

    if (argc - arg_idx != 2) {
        printf("Usage:\n");
        printf("  Push: %s [-r] <local_file> <IP>:<remote_file>\n", argv[0]);
        printf("  Pull: %s [-r] <IP>:<remote_file> <local_file>\n", argv[0]);
        return 1;
    }

    char *src = argv[arg_idx];
    char *dest = argv[arg_idx + 1];

    if (strchr(src, ':') != NULL) {
        // Pull
        char* ip = strtok(src, ":");
        char* remote_file = strtok(NULL, ":");
        char* local_file = dest;
        pull_file(ip, remote_file, local_file);
    } else if (strchr(dest, ':') != NULL) {
        // Push
        char* local_file = src;
        char* ip = strtok(dest, ":");
        char* remote_file = strtok(NULL, ":");
        push_file(ip, local_file, remote_file);
    } else {
        printf("Invalid syntax. Use IP:filename to specify the remote target.\n");
    }

    return 0;
}
