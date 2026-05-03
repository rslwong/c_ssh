#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/select.h>

#define PORT 8022

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
        printf("Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        printf("\nConnection Failed \n");
        return -1;
    }
    
    printf("Connected to %s:%d\n", argv[1], PORT);
    
    // Handshake: tell server we want an interactive shell
    char mode = '1';
    write(sock, &mode, 1);
    
    // Switch client terminal to raw mode
    enable_raw_mode();
    
    fd_set fds;
    char buffer[4096];
    
    while (1) {
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        FD_SET(sock, &fds);
        
        int max_fd = sock;
        
        if (select(max_fd + 1, &fds, NULL, NULL, NULL) < 0) {
            break;
        }
        
        // Read input from the user, send over the socket
        if (FD_ISSET(STDIN_FILENO, &fds)) {
            int n = read(STDIN_FILENO, buffer, sizeof(buffer));
            if (n <= 0) break;
            write(sock, buffer, n);
        }
        
        // Read output from the server, print to the user
        if (FD_ISSET(sock, &fds)) {
            int n = read(sock, buffer, sizeof(buffer));
            if (n <= 0) break;
            write(STDOUT_FILENO, buffer, n);
        }
    }
    
    close(sock);
    return 0;
}
