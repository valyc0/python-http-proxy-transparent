# HTTP/HTTPS Proxy Logger with SSL Interception

A powerful HTTP/HTTPS proxy server that logs all requests and responses that pass through it, including HTTPS traffic through TLS interception (Man-In-The-Middle). This is useful for debugging, analyzing, and inspecting both encrypted and unencrypted web traffic.

## Features

- Logs both HTTP and HTTPS requests and responses with full content inspection
- HTTPS interception with SSL/TLS MITM capabilities
- Supports all HTTP methods (GET, POST, PUT, DELETE, etc.)
- Formats JSON bodies for better readability
- Handles binary content
- Threading support for multiple simultaneous connections
- Two operating modes:
  - **Direct mode**: All requests are forwarded to a specific target
  - **Transparent mode**: Acts as a real proxy, forwarding requests to any host requested by client
- Configurable target host, port, log file, and SSL certificates

## Usage

### Using the Start Script

The easiest way to start the proxy is by using the provided start script:

```bash
./start_proxy_with_mitm.sh
```

This will start the proxy in transparent mode on port 8080 with logs to console only.

You can view the help message with:
```bash
./start_proxy_with_mitm.sh --help
```

You can customize the settings:

```bash
./start_proxy_with_mitm.sh 9000                    # Transparent mode, custom port
./start_proxy_with_mitm.sh 8080 http://target.com  # Direct mode to specific target
./start_proxy_with_mitm.sh 8080 transparent        # Explicit transparent mode
./start_proxy_with_mitm.sh 8080 transparent proxy.log  # Transparent mode with logging
./start_proxy_with_mitm.sh 8080 transparent proxy.log 0  # No truncation of bodies
```

### Direct Usage

Alternatively, you can run the Python script directly:

```bash
python3 http_proxy_logger_with_mitm.py
```

With custom settings:

```bash
python3 http_proxy_logger_with_mitm.py --port 9000 --target http://api.example.com --logfile proxy.log --cert ./certs/proxy.crt --key ./certs/proxy.key
```

### Command-line Options

- `--host HOST`: Host to bind the proxy server to (default: 0.0.0.0)
- `--port PORT`: Port to run the proxy server on (default: 8080)
- `--target TARGET`: Target host to proxy to (default: http://example.com). Ignored if --transparent is used.
- `--logfile LOGFILE`: Log file to write to (default: console only)
- `--transparent`: Run in transparent mode, acting as a real proxy that forwards to requested hosts
- `--cert CERT`: Path to SSL certificate file for HTTPS interception
- `--key KEY`: Path to SSL key file for HTTPS interception
- `--truncate-limit LIMIT`: Maximum characters to display in request/response bodies (default: 10000)

## HTTPS Interception Setup

For HTTPS interception to work properly:

1. The proxy generates a self-signed certificate on first run (or you can create one using `./generate_cert.sh`)
2. This certificate must be added to your system/browser's trusted certificate authorities
3. For testing, you can use the `-k` flag with curl to ignore certificate validation

## Testing the Proxy

### Testing with curl

You can test the proxy using curl:

```bash
# For HTTP:
curl -v -x http://localhost:8080 http://example.com

# For HTTPS (with certificate validation):
curl -v -x http://localhost:8080 https://example.com

# For HTTPS (ignoring certificate validation):
curl -v -k -x http://localhost:8080 https://example.com
```

The `-v` flag shows detailed information about the request and response.

## Log Format

The logs include:

- Request method, URL, headers, and body
- Response status code, headers, and body
- Timestamp for each log entry

For JSON content, the body is formatted with proper indentation for easier reading.

## Requirements

- Python 3.x (tested with Python 3.6+)
- OpenSSL (for generating certificates)
- No external Python dependencies required (uses standard library only)

## Security Notice

This tool is intended for development, debugging, and educational purposes only. Intercepting HTTPS traffic raises significant privacy and security concerns. Only use this tool on your own traffic or in environments where you have explicit permission to intercept network communications.
