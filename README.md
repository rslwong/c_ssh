# C-SSH: A Minimalist SSH & SCP Clone in C

This project provides a lightweight, minimalist implementation of an SSH-like server and client stack written entirely in C. Fully cross-platform across macOS and Linux, it demonstrates how to use pseudo-terminals (`pty`), socket programming, and raw terminal modes to create a remote interactive shell, as well as an integrated file transfer tool mimicking `scp`.

## Features

- **End-to-End Encryption (TLS/SSL)**: All traffic—including shell data, window resizing signals, file transfers, and port-forwarded traffic—is securely wrapped inside an OpenSSL/TLS 1.2+ layer.
- **Certificate Verification (Known Hosts)**: The client and SCP tools now verify the server's SHA-256 fingerprint upon connection. This implements a "trust on first use" (TOFU) security model similar to OpenSSH, protecting against Man-in-the-Middle (MITM) attacks.
- **Cross-Platform**: Fully compatible with both macOS and Linux, auto-detecting the appropriate system headers and `login` binaries during compilation.
- **Interactive Remote Shell (`client`)**: Connects to the server, allocates a pseudo-terminal (`pty`), and seamlessly passes raw terminal inputs. Mimics a true SSH experience, handling interactive programs like `vim`, `top`, or `htop`.
- **Dynamic Window Resizing**: The client listens for terminal resize events (`SIGWINCH`) and instantly synchronizes the remote server's PTY dimensions out-of-band so your UI never breaks.
- **Port Forwarding (Tunneling)**: Supports bidirectional tunneling directly integrated into the client tool!
  - Local Forwarding (`-L`): Forward local ports securely to remote targets.
  - Remote Forwarding (`-R`): Bind remote ports on the server to forward traffic back to your local network.
- **Native Authentication**: The server hooks directly into the host OS's native `/usr/bin/login` (macOS) or `/bin/login` (Linux) to offload system authentication and password verification safely.
- **Advanced File Transfers (`c_scp`)**: A custom command-line utility providing `scp`-like push and pull capabilities. Supports **recursive directory transfers** (`-r`) and natively fetches and preserves the original file's size, permissions (`chmod`), and last modified timestamps (`utimes`).
- **Configuration File Support**: Easily configure the default port by creating a simple `c_ssh_config` file.
- **Packet-Based Protocol**: Communication is structured into a dynamic custom packet protocol (`[Type][Length][Payload]`), allowing multiplexed concurrent channels for shell data, resize signals, and port forwarding streams over a single TCP connection.

## Components

- `server.c`: A daemon that listens on port `8022` (or configured port) and multiplexes interactive PTY shell requests, tunneling requests, and file transfers.
- `client.c`: A client tool that manages raw terminal state, out-of-band resizing signals, and port-forwarding tunnels.
- `c_scp.c`: A file transfer tool that allows pushing and pulling files with exact attribute preservation.
- `Makefile`: Automates the cross-platform compilation of all binaries.

## Getting Started

### 1. Build the project

To compile the server, client, and scp tools, simply run:

```bash
make
```

*(Note: The build process automatically links `libssl` and `libcrypto`, and will auto-generate a self-signed `server.crt` and `server.key` if they do not exist!)*

### 2. Configure (Optional)

By default, the server and clients use port `8022`. You can override this by creating a `c_ssh_config` file in the same directory:
```
PORT=9000
```

### 3. Start the Server

Start the background server on your host machine:

```bash
./server
```

### 4. Connect to the Shell

Open a new terminal and connect using the client:

```bash
./client 127.0.0.1
```
You will be greeted with your system's native `login:` prompt. Enter your credentials to start a secure shell session!

### 5. Port Forwarding (Tunneling)

To forward a local port (e.g. 9000) to a target on the server's network (e.g. 127.0.0.1:80):
```bash
./client 127.0.0.1 -L 9000:127.0.0.1:80
```

To bind a remote port on the server (e.g. 8080) and forward incoming connections back to your local machine (e.g. 3000):
```bash
./client 127.0.0.1 -R 8080:127.0.0.1:3000
```

### 6. Copy Files using SCP

To **push (upload)** a local file to the server:
```bash
./c_scp local_file.txt 127.0.0.1:remote_file.txt
```

To **pull (download)** a remote file from the server to your local machine:
```bash
./c_scp 127.0.0.1:remote_file.txt local_file.txt
```

## Protocol Technical Details

Instead of streaming raw TCP bytes, the system uses a 1-byte handshake to determine the root mode (`1` for Shell/Tunnels, `2` for SCP Pull, `3` for SCP Push).

If the Shell mode is chosen, the connection upgrades to a packetized protocol to allow concurrency:
- `Type 0`: Standard Terminal I/O
- `Type 1`: `SIGWINCH` Terminal Resize Notifications
- `Type 2`: Tunnel Setup Request (Local Forwarding)
- `Type 3`: Tunnel Status Response
- `Type 4`: Tunnel Stream Data
- `Type 5`: Tunnel Connection Closed
- `Type 6`: Remote Bind Request (Remote Forwarding)
- `Type 7`: Remote Bind Status Response
- `Type 8`: Incoming Remote Connection Event
- `Type 9`: Incoming Remote Connection Status
