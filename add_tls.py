import os

def fix_server():
    with open('server.c', 'r') as f:
        src = f.read()
    
    src = src.replace('#include <sys/ioctl.h>', '#include <sys/ioctl.h>\n#include <openssl/ssl.h>\n#include <openssl/err.h>')
    
    src = src.replace('int read_exact(int fd,', 'int read_exact(SSL *ssl,')
    src = src.replace('read(fd, (char*)buf', 'SSL_read(ssl, (char*)buf')
    
    src = src.replace('int read_until_newline(int fd,', 'int read_until_newline(SSL *ssl,')
    src = src.replace('read(fd, &c, 1)', 'SSL_read(ssl, &c, 1)')
    
    src = src.replace('void handle_scp_pull(int client_fd)', 'void handle_scp_pull(SSL *ssl)')
    src = src.replace('void handle_scp_push(int client_fd)', 'void handle_scp_push(SSL *ssl)')
    src = src.replace('void handle_client(int client_fd)', 'void handle_client(SSL *ssl)\n{\n    int client_fd = SSL_get_fd(ssl);')
    
    src = src.replace('read_exact(client_fd,', 'read_exact(ssl,')
    src = src.replace('read_until_newline(client_fd,', 'read_until_newline(ssl,')
    src = src.replace('write(client_fd,', 'SSL_write(ssl,')
    
    sel = '''if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                if (errno == EINTR) continue;
                break;
            }'''
    rep = '''int pending = SSL_pending(ssl);
            if (pending == 0) {
                if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
            }'''
    src = src.replace(sel, rep)
    
    src = src.replace('if (FD_ISSET(client_fd, &fds)) {', 'if (pending > 0 || FD_ISSET(client_fd, &fds)) {')
    
    main_init = '''int main() {
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
'''
    src = src.replace('int main() {', main_init)
    
    fork_rep = '''if (fork() == 0) {
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
            
            printf("Client disconnected.\\n");
            SSL_free(ssl);
            exit(0);
        }'''
    
    src = src.replace('''if (fork() == 0) {
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
            
            printf("Client disconnected.\\n");
            exit(0);
        }''', fork_rep)

    with open('server.c', 'w') as f:
        f.write(src)

def fix_client():
    with open('client.c', 'r') as f:
        src = f.read()
        
    src = src.replace('#include <errno.h>', '#include <errno.h>\n#include <openssl/ssl.h>\n#include <openssl/err.h>')
    
    src = src.replace('void send_window_size(int sock)', 'void send_window_size(SSL *ssl)')
    src = src.replace('int read_exact(int fd,', 'int read_exact(SSL *ssl,')
    src = src.replace('read(fd, (char*)buf', 'SSL_read(ssl, (char*)buf')
    
    src = src.replace('write(sock,', 'SSL_write(ssl,')
    src = src.replace('read_exact(sock,', 'read_exact(ssl,')
    src = src.replace('send_window_size(sock)', 'send_window_size(ssl)')
    
    hs_new = '''printf("Connected to %s:%d\\n", argv[1], active_port);

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
        return -1;
    }
    
    // Handshake: tell server we want an interactive shell
    char mode = '1';
    SSL_write(ssl, &mode, 1);'''
    
    src = src.replace('''printf("Connected to %s:%d\\n", argv[1], active_port);
    
    // Handshake: tell server we want an interactive shell
    char mode = '1';
    write(sock, &mode, 1);''', hs_new)
    
    sel = '''if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
            if (errno == EINTR) continue;
            break;
        }'''
    rep = '''int pending = SSL_pending(ssl);
        if (pending == 0) {
            if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
                if (errno == EINTR) continue;
                break;
            }
        }'''
    src = src.replace(sel, rep)
    src = src.replace('if (FD_ISSET(sock, &fds)) {', 'if (pending > 0 || FD_ISSET(sock, &fds)) {')

    with open('client.c', 'w') as f:
        f.write(src)

def fix_c_scp():
    with open('c_scp.c', 'r') as f:
        src = f.read()

    src = src.replace('#include <sys/time.h>', '#include <sys/time.h>\n#include <openssl/ssl.h>\n#include <openssl/err.h>')
    
    src = src.replace('int read_until_newline(int fd,', 'int read_until_newline(SSL *ssl,')
    src = src.replace('read(fd, &c, 1)', 'SSL_read(ssl, &c, 1)')
    
    src = src.replace('int connect_to_server', 'SSL* connect_to_server')
    
    conn_end = '''    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\\nConnection Failed \\n");
        exit(1);
    }
    return sock;'''
    
    conn_new = '''    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\\nConnection Failed \\n");
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
    return ssl;'''
    src = src.replace(conn_end, conn_new)
    
    push = '''void push_file(const char* ip, const char* local_file, const char* remote_file) {
    int sock = connect_to_server(ip);
    char mode = '3';
    write(sock, &mode, 1);'''
    push_n = '''void push_file(const char* ip, const char* local_file, const char* remote_file) {
    SSL *ssl = connect_to_server(ip);
    int sock = SSL_get_fd(ssl);
    char mode = '3';
    SSL_write(ssl, &mode, 1);'''
    src = src.replace(push, push_n)
    
    pull = '''void pull_file(const char* ip, const char* remote_file, const char* local_file) {
    int sock = connect_to_server(ip);
    char mode = '2';
    write(sock, &mode, 1);'''
    pull_n = '''void pull_file(const char* ip, const char* remote_file, const char* local_file) {
    SSL *ssl = connect_to_server(ip);
    int sock = SSL_get_fd(ssl);
    char mode = '2';
    SSL_write(ssl, &mode, 1);'''
    src = src.replace(pull, pull_n)
    
    src = src.replace('write(sock, header,', 'SSL_write(ssl, header,')
    src = src.replace('read_until_newline(sock,', 'read_until_newline(ssl,')
    src = src.replace('write(sock, buf, n);', 'SSL_write(ssl, buf, n);')
    src = src.replace('read(sock, buf, to_read);', 'SSL_read(ssl, buf, to_read);')

    with open('c_scp.c', 'w') as f:
        f.write(src)

def fix_makefile():
    new_mf = """CC = gcc
CFLAGS = -Wall -Wextra -O2
OS := $(shell uname)

LDFLAGS = -lssl -lcrypto
ifeq ($(OS),Linux)
	LDFLAGS += -lutil
endif
ifeq ($(OS),Darwin)
	CFLAGS += -I/opt/homebrew/opt/openssl/include -I/usr/local/opt/openssl/include
	LDFLAGS += -L/opt/homebrew/opt/openssl/lib -L/usr/local/opt/openssl/lib
endif

all: cert server client c_scp

cert: server.key server.crt

server.key server.crt:
	openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout server.key -out server.crt -subj "/CN=localhost" 2>/dev/null || true

server: server.c
	$(CC) $(CFLAGS) -o server server.c $(LDFLAGS)

client: client.c
	$(CC) $(CFLAGS) -o client client.c $(LDFLAGS)

c_scp: c_scp.c
	$(CC) $(CFLAGS) -o c_scp c_scp.c $(LDFLAGS)

clean:
	rm -f server client c_scp server.key server.crt
"""
    with open('Makefile', 'w') as f:
        f.write(new_mf)

fix_server()
fix_client()
fix_c_scp()
fix_makefile()
print("Done")
