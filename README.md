# HTTP Proxy Logger

A simple HTTP proxy server that logs all requests and responses that pass through it. This is useful for debugging and analyzing HTTP traffic.

## Features

- Logs both HTTP requests and responses
- Supports all HTTP methods (GET, POST, PUT, DELETE, etc.)
- Formats JSON bodies for better readability
- Handles binary content
- Threading support for multiple simultaneous connections
- Two operating modes:
  - **Direct mode**: All requests are forwarded to a specific target (default)
  - **Transparent mode**: Acts as a real proxy, forwarding requests to any host requested by client
- Support for HTTPS connections via CONNECT method (in transparent mode)
- Configurable target host, port, and log file

## Usage

### Using the Start Script

The easiest way to start the proxy is by using the provided start script:

```bash
./start_proxy.sh
```

This will start the proxy in transparent mode on port 8080 with logs to console only.

You can view the help message with:
```bash
./start_proxy.sh --help
```

You can customize the settings:

```bash
./start_proxy.sh 9000                          # Transparent mode, custom port
./start_proxy.sh 8080 http://api.example.com   # Direct mode to specific target
./start_proxy.sh 8080 http://api.example.com proxy.log  # Direct mode with logging
./start_proxy.sh 8080 transparent              # Explicit transparent mode
./start_proxy.sh 8080 transparent proxy.log    # Transparent mode with logging
```

### Direct Usage

Alternatively, you can run the Python script directly:

```bash
python3 http_proxy_logger.py
```

With custom settings:

```bash
python3 http_proxy_logger.py --port 9000 --target http://api.example.com --logfile proxy.log
```

### Command-line Options

- `--host HOST`: Host to bind the proxy server to (default: 0.0.0.0)
- `--port PORT`: Port to run the proxy server on (default: 8080)
- `--target TARGET`: Target host to proxy to (default: http://example.com). Ignored if --transparent is used.
- `--logfile LOGFILE`: Log file to write to (default: console only)
- `--transparent`: Run in transparent mode, acting as a real proxy that forwards to requested hosts

## Testing the Proxy

### Using the Test Script

We've included a test script that starts a local HTTP server and makes a request through the proxy:

```bash
# First start the proxy in transparent mode
./start_proxy.sh 8080 transparent

# Then in another terminal, run the test script
./test_proxy.py
```

### Manual Testing with curl

You can also test the proxy manually using curl:

```bash
curl -v -x http://localhost:8080 http://example.com
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
- No external dependencies required (uses standard library only)
