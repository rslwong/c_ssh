# C-SSH: A Minimalist SSH & SCP Clone in C

This project provides a lightweight, minimalist implementation of an SSH-like server and client stack written entirely in C for macOS. It demonstrates how to use pseudo-terminals (`pty`), socket programming, and raw terminal modes to create a remote interactive shell, as well as an integrated file transfer tool mimicking `scp`.

## Features

- **Interactive Remote Shell (`client`)**: Connects to the server, allocates a pseudo-terminal (`pty`), and seamlessly passes raw terminal inputs. It mimics a true SSH experience, including handling interactive commands like `vim`, `top`, or `htop`.
- **Native Authentication**: The server hooks directly into macOS's native `/usr/bin/login` to ask for the system username and password, offloading authentication directly to the host OS.
- **File Transfers (`c_scp`)**: A custom command-line utility providing `scp`-like push and pull capabilities.
- **Protocol Multiplexing**: The server listens on a single port (default `8022`). When a connection is established, it parses a 1-byte handshake to determine whether to spawn a shell session, handle an upload, or handle a download.

## Components

- `server.c`: A daemon that listens on port `8022` and handles both interactive PTY shell requests and file transfer requests.
- `client.c`: A client tool that puts your local terminal into "raw" mode and communicates with the server's PTY.
- `c_scp.c`: A file transfer tool that allows pushing and pulling files using standard `scp` command-line syntax.
- `Makefile`: Automates the compilation of all binaries.

## Getting Started

### 1. Build the project

To compile the server, client, and scp tools, simply run:

```bash
make
```

### 2. Start the Server

Start the background server on your host machine:

```bash
./server
```
*(The server will begin listening on port 8022).*

### 3. Connect to the Shell

Open a new terminal tab/window and connect using the client:

```bash
./client 127.0.0.1
```
You will be greeted with the standard macOS `login:` prompt. Enter your system credentials to start a secure shell session!

### 4. Copy Files using SCP

To **push (upload)** a local file to the server:
```bash
./c_scp local_file.txt 127.0.0.1:remote_file.txt
```

To **pull (download)** a remote file from the server to your local machine:
```bash
./c_scp 127.0.0.1:remote_file.txt local_file.txt
```

## Technical Details

- **Terminal Raw Mode**: The client disables local echo and intercept signals (like `Ctrl+C`). It relies entirely on the remote PTY to manage the terminal state, ensuring that keystrokes act directly on the server instead of terminating your client tool.
- **Multiplexed Port**: The system establishes the intent of the connection with a 1-byte header:
  - `0x31` ('1'): Request interactive shell.
  - `0x32` ('2'): Request SCP Pull (Download).
  - `0x33` ('3'): Request SCP Push (Upload).
