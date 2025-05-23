#!/usr/bin/env python3
"""
HTTP Proxy Server with Request/Response Logging

This script implements a simple HTTP proxy server that logs all requests and responses
that pass through it. It's useful for debugging and analyzing HTTP traffic.

Usage:
    python3 http_proxy_logger.py [--host HOST] [--port PORT] [--target TARGET] [--logfile LOGFILE]

Examples:
    python3 http_proxy_logger.py --port 8080 --target http://example.com
    python3 http_proxy_logger.py --port 9000 --target http://api.example.org --logfile proxy.log
"""

import argparse
import datetime
import http.server
import json
import logging
import os
import socket
import socketserver
import sys
import threading
import urllib.parse
import urllib.request
from http.client import HTTPResponse
from io import BytesIO


# Configure logging
def setup_logging(log_file=None):
    """Configure logging to file and console"""
    logger = logging.getLogger('http_proxy')
    logger.setLevel(logging.DEBUG)
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Console handler
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)  # Changed from INFO to DEBUG to show all request/response details
    console.setFormatter(formatter)
    logger.addHandler(console)
    
    # File handler (if specified)
    if log_file:
        file_handler = logging.FileHandler(log_file, mode='a')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# Custom HTTPResponse class to capture raw response data
class HttpResponseWrapper(BytesIO):
    """Wrapper to capture raw HTTP response"""
    
    def __init__(self, sock):
        BytesIO.__init__(self)
        self.sock = sock
    
    def makefile(self, *args, **kwargs):
        return self


# Parse HTTP headers from raw bytes
def parse_headers(header_bytes):
    """Parse HTTP headers from raw data"""
    headers = {}
    header_lines = header_bytes.decode('utf-8', errors='replace').split('\r\n')
    for line in header_lines[1:]:  # Skip the status line
        if line:
            key, _, value = line.partition(':')
            headers[key.strip()] = value.strip()
    return headers


# Format request or response for logging
def format_http_message(headers, body, is_request=True, truncate_limit=None):
    """Format HTTP request or response for logging"""
    # Use the global truncate limit if not specified
    if truncate_limit is None:
        truncate_limit = ProxyHTTPRequestHandler.truncate_limit
    result = ""
    
    if is_request:
        result += "┌───────────────────────────────────────────────────\n"
        result += "│ REQUEST:\n"
        if 'requestline' in headers:
            result += f"│ {headers.pop('requestline')}\n"
    else:
        result += "┌───────────────────────────────────────────────────\n"
        result += "│ RESPONSE:\n"
        if 'statusline' in headers:
            result += f"│ {headers.pop('statusline')}\n"
    
    result += "│\n│ HEADERS:\n"
    for key, value in headers.items():
        result += f"│ {key}: {value}\n"
    
    result += "│\n│ BODY:\n"
    
    # Try to parse as JSON for prettier output
    if body:
        try:
            parsed_body = json.loads(body)
            json_str = json.dumps(parsed_body, indent=2)
            # Add "│ " prefix to each line for better visual separation
            json_lines = json_str.split('\n')
            result += '│ ' + '\n│ '.join(json_lines) + '\n'
        except (json.JSONDecodeError, UnicodeDecodeError):
            # If not JSON, try to decode as string
            try:
                decoded_body = body.decode('utf-8', errors='replace')
                # Truncate if body exceeds the truncate limit and limit is not 0 (0 means no truncation)
                if truncate_limit > 0 and len(decoded_body) > truncate_limit:
                    result += f"│ {decoded_body[:truncate_limit]}...\n│ [Truncated - total length: {len(decoded_body)} bytes]\n"
                else:
                    # Split by lines and add prefix
                    body_lines = decoded_body.split('\n')
                    result += '│ ' + '\n│ '.join(body_lines) + '\n'
            except Exception:
                result += f"│ [Binary data - {len(body)} bytes]\n"
    else:
        result += "│ [Empty body]\n"
    
    result += "└───────────────────────────────────────────────────\n"
    return result


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Proxy Request Handler with logging"""
    
    protocol_version = 'HTTP/1.1'
    logger = None
    target_host = None
    target_port = None
    transparent_mode = False
    truncate_limit = 10000  # Default truncate limit (10000 characters)
    
    def parse_target(self, path):
        """Parse and validate target URL"""
        # Check if we're in transparent mode or direct target mode
        if self.transparent_mode:
            # In CONNECT method this is handled separately
            if self.command == "CONNECT":
                return path
                
            # For regular HTTP requests in transparent mode,
            # check if the path starts with http:// or https://
            if path.startswith('http://') or path.startswith('https://'):
                return path
            else:
                # Extract host from headers (transparent mode requires Host header)
                host = self.headers.get('Host')
                if not host:
                    self.logger.error("No Host header in transparent mode")
                    return None
                return f"http://{host}{path}"
        else:
            # Direct target mode (original behavior)
            if path.startswith('http://') or path.startswith('https://'):
                return path
            else:
                return f"http://{self.target_host}:{self.target_port}{path}"
    
    def do_request(self, method):
        """Handle any type of request"""
        # Parse target URL
        url = self.parse_target(self.path)
        if url is None:
            self.send_error(400, "Bad Request - Cannot determine target URL")
            return
            
        self.logger.info(f"{self.client_address[0]} - {method} {url}")
        
        # Get request content if any
        content_length = int(self.headers.get('Content-Length', 0))
        request_body = self.rfile.read(content_length) if content_length > 0 else None
        
        # Log request
        headers_dict = dict(self.headers.items())
        headers_dict['requestline'] = f"{method} {self.path} {self.protocol_version}"
        self.logger.debug(format_http_message(headers_dict, request_body, is_request=True))
        
        # Create a new headers dictionary without the proxy-connection header
        request_headers = dict(self.headers.items())
        if 'proxy-connection' in request_headers:
            del request_headers['proxy-connection']
            
        # Prepare request
        request = urllib.request.Request(
            url,
            data=request_body,
            headers=request_headers,
            method=method
        )
        
        # Forward request to target and get response
        try:
            response = urllib.request.urlopen(request, timeout=10)
            
            # Get response data
            status_code = response.status
            response_headers = response.getheaders()
            response_body = response.read()
            
            # Send response headers to client
            self.send_response(status_code)
            for header, value in response_headers:
                # Skip headers that could cause connection issues or that we'll handle ourselves
                if header.lower() not in ('transfer-encoding', 'connection', 'keep-alive'):
                    self.send_header(header, value)
            
            # Explicitly close the connection to prevent hanging
            self.send_header('Connection', 'close')
            self.end_headers()
            
            # Send response body to client
            self.wfile.write(response_body)
            
            # Log response
            resp_headers = dict(response_headers)
            resp_headers['statusline'] = f"HTTP/1.1 {status_code} {response.reason}"
            self.logger.debug(format_http_message(resp_headers, response_body, is_request=False))
            
        except Exception as e:
            self.logger.error(f"Error forwarding request: {e}")
            self.send_error(502, f"Bad Gateway: {e}")
    
    def do_GET(self):
        """Handle GET requests"""
        self.do_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self.do_request('POST')
    
    def do_PUT(self):
        """Handle PUT requests"""
        self.do_request('PUT')
    
    def do_DELETE(self):
        """Handle DELETE requests"""
        self.do_request('DELETE')
    
    def do_OPTIONS(self):
        """Handle OPTIONS requests"""
        self.do_request('OPTIONS')
    
    def do_HEAD(self):
        """Handle HEAD requests"""
        self.do_request('HEAD')
    
    def do_PATCH(self):
        """Handle PATCH requests"""
        self.do_request('PATCH')
    
    def do_CONNECT(self):
        """Handle CONNECT requests (for HTTPS tunneling)"""
        if not self.transparent_mode:
            self.send_error(405, "Method Not Allowed - CONNECT is only available in transparent mode")
            return
            
        # Extract target host and port from the path
        target = self.path.split(':')
        host = target[0]
        port = int(target[1]) if len(target) > 1 else 443
        
        self.logger.info(f"{self.client_address[0]} - CONNECT {host}:{port}")
        
        try:
            # Connect to the target server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(10)
            server_socket.connect((host, port))
            
            # Send connection established response
            self.send_response(200, "Connection established")
            self.end_headers()
            
            # Log the connection
            headers_dict = dict(self.headers.items())
            headers_dict['requestline'] = f"CONNECT {self.path} {self.protocol_version}"
            self.logger.debug(format_http_message(headers_dict, None, is_request=True))
            
            # Create a two-way tunnel
            # We need to use select to handle both connections, but for simplicity's sake,
            # we'll use threads here (less efficient but easier to understand)
            client_socket = self.request
            
            # Set up tunneling in both directions
            def forward_to_server():
                try:
                    while True:
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        server_socket.sendall(data)
                except:
                    pass
                finally:
                    server_socket.close()
            
            def forward_to_client():
                try:
                    while True:
                        data = server_socket.recv(4096)
                        if not data:
                            break
                        client_socket.sendall(data)
                except:
                    pass
                finally:
                    client_socket.close()
            
            # Start forwarding threads
            threading.Thread(target=forward_to_server, daemon=True).start()
            threading.Thread(target=forward_to_client, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Error establishing CONNECT tunnel: {e}")
            self.send_error(502, f"Bad Gateway: {e}")
            return
    
    def log_message(self, format, *args):
        """Override default log_message to use our logger"""
        # Suppress the default log_message output
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True


def run_server(host, port, target, log_file, transparent=False, truncate_limit=10000):
    """Run the HTTP proxy server"""
    # Set up logger
    logger = setup_logging(log_file)
    
    # Set class variables
    ProxyHTTPRequestHandler.logger = logger
    ProxyHTTPRequestHandler.transparent_mode = transparent
    ProxyHTTPRequestHandler.truncate_limit = truncate_limit
    
    if not transparent and target:
        # Parse target URL for direct mode
        parsed_target = urllib.parse.urlparse(target)
        target_host = parsed_target.netloc.split(':')[0]
        target_port = parsed_target.port or (443 if parsed_target.scheme == 'https' else 80)
        
        # Set target info
        ProxyHTTPRequestHandler.target_host = target_host
        ProxyHTTPRequestHandler.target_port = target_port
    
    # Create server
    server_address = (host, port)
    httpd = ThreadedHTTPServer(server_address, ProxyHTTPRequestHandler)
    
    logger.info(f"Starting HTTP Proxy Server on {host}:{port}")
    if transparent:
        logger.info("Mode: Transparent (will proxy to requested hosts)")
    else:
        logger.info(f"Mode: Direct (will proxy all requests to: {target})")
    logger.info(f"Log file: {log_file or 'console only'}")
    logger.info("Press Ctrl+C to stop the proxy")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server...")
        httpd.server_close()
    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        logger.info("Proxy server stopped")


def main():
    """Parse command line arguments and start the server"""
    parser = argparse.ArgumentParser(description="HTTP Proxy Server with Request/Response Logging")
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the proxy server to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to run the proxy server on (default: 8080)')
    parser.add_argument('--target', type=str, default='http://example.com', help='Target host to proxy to (default: http://example.com). Ignored if --transparent is used.')
    parser.add_argument('--logfile', type=str, default=None, help='Log file to write to (default: console only)')
    parser.add_argument('--transparent', action='store_true', help='Run in transparent mode (proxy to any host requested by the client)')
    parser.add_argument('--truncate-limit', type=int, default=10000, help='Maximum number of characters to display for response/request bodies (default: 10000, 0 for no truncation)')
    
    args = parser.parse_args()
    run_server(args.host, args.port, args.target, args.logfile, args.transparent, args.truncate_limit)


if __name__ == "__main__":
    main()
