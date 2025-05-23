#!/usr/bin/env python3
"""
HTTP/HTTPS Proxy Server with Request/Response Logging and HTTPS Interception

This script implements a proxy server that logs all requests and responses that pass through it,
including HTTPS traffic through TLS interception (MITM).

Usage:
    python3 http_proxy_logger_with_mitm.py [--host HOST] [--port PORT] [--target TARGET] 
                                           [--logfile LOGFILE] [--transparent] [--cert CERT] [--key KEY]

Note: For HTTPS interception to work, clients need to trust the provided certificate or ignore SSL errors.
"""

import argparse
import datetime
import http.server
import json
import logging
import os
import select
import socket
import socketserver
import ssl
import sys
import tempfile
import threading
import time
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
    console.setLevel(logging.DEBUG)
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
        truncate_limit = 10000  # Default
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


def generate_self_signed_cert(cert_file, key_file):
    """Generate a self-signed certificate if the provided files don't exist"""
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return
    
    from OpenSSL import crypto
    
    # Create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    
    # Create a self-signed cert
    cert = crypto.X509()
    cert.get_subject().C = "US"
    cert.get_subject().ST = "State"
    cert.get_subject().L = "City"
    cert.get_subject().O = "Organization"
    cert.get_subject().OU = "Organizational Unit"
    cert.get_subject().CN = "HTTP Proxy Logger"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)  # 10 years
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')
    
    # Save the certificate
    with open(cert_file, "wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    
    # Save the key
    with open(key_file, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Proxy Request Handler with logging"""
    
    protocol_version = 'HTTP/1.1'
    logger = None
    target_host = None
    target_port = None
    transparent_mode = False
    truncate_limit = 10000  # Default truncate limit (10000 characters)
    ssl_context = None
    cert_file = None
    key_file = None
    
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
            # Log the connection request
            headers_dict = dict(self.headers.items())
            headers_dict['requestline'] = f"CONNECT {self.path} {self.protocol_version}"
            self.logger.debug(format_http_message(headers_dict, None, is_request=True))
            
            # Send connection established response
            self.send_response(200, "Connection established")
            self.end_headers()
            self.wfile.flush()  # Make sure the 200 response is sent immediately
            
            # Record start time
            start_time = time.time()
            bytes_to_server = 0
            bytes_to_client = 0
            
            # Get client connection
            client_socket = self.connection
            
            if self.ssl_context:
                # Create an SSL socket for the client
                ssl_socket = self.ssl_context.wrap_socket(
                    client_socket, 
                    server_side=True,
                    do_handshake_on_connect=True
                )
                
                # Create a wrapper handler with the SSL socket
                # This allows us to handle HTTPS requests directly
                from io import BytesIO
                
                class SSLHandler(http.server.BaseHTTPRequestHandler):
                    def __init__(self, request, client_address, server):
                        self.connection = request
                        self.client_address = client_address
                        self.server = server
                        # Create file-like objects for the socket
                        self.rfile = request.makefile('rb', -1)
                        self.wfile = request.makefile('wb', 0)
                        
                        # Save the target info
                        self.target_host = host
                        self.target_port = port
                        self.logger = ProxyHTTPRequestHandler.logger
                        self.transparent_mode = True  # Always true for SSL handler
                        
                    def handle_one_request(self):
                        """Handle a single HTTP request."""
                        try:
                            self.raw_requestline = self.rfile.readline(65537)
                            if len(self.raw_requestline) > 65536:
                                self.requestline = ''
                                self.request_version = ''
                                self.command = ''
                                self.send_error(414)
                                return
                            if not self.raw_requestline:
                                return
                            if not self.parse_request():
                                # An error code has been sent, just exit
                                return
                                
                            # Log this HTTPS request
                            self.logger.info(f"HTTPS: {self.command} {self.path} (via {host}:{port})")
                            
                            # Modify the path to include the target host
                            if not self.path.startswith('http://') and not self.path.startswith('https://'):
                                self.path = f"https://{host}:{port}{self.path}"
                                
                            # Handle the request using the original handler's methods
                            mname = 'do_' + self.command
                            if not hasattr(self, mname):
                                self.send_error(
                                    501,
                                    "Unsupported method (%r)" % self.command)
                                return
                            method = getattr(self, mname)
                            method()
                        except OSError as e:
                            if e.errno == 9:  # Bad file descriptor
                                self.logger.debug(f"Connection closed by client: {e}")
                            else:
                                self.logger.error(f"Socket error in HTTPS request handling: {e}")
                            return
                        except Exception as e:
                            self.logger.error(f"Error handling HTTPS request: {e}")
                            return
                
                # Add all the request handling methods to our SSL handler
                for method_name in ['do_GET', 'do_POST', 'do_PUT', 'do_DELETE', 'do_OPTIONS', 'do_HEAD', 'do_PATCH', 'parse_target', 'do_request']:
                    setattr(SSLHandler, method_name, getattr(ProxyHTTPRequestHandler, method_name))
                
                try:
                    # Handle the SSL connection
                    handler = SSLHandler(ssl_socket, self.client_address, self.server)
                    handler.handle_one_request()
                    # Don't try to read more after the first request is handled
                    # This prevents Bad file descriptor errors when the connection is closed
                except ssl.SSLError as e:
                    self.logger.error(f"SSL Error: {e}")
                except OSError as e:
                    if e.errno == 9:  # Bad file descriptor
                        self.logger.debug(f"Connection closed by client: {e}")
                    else:
                        self.logger.error(f"Socket error in HTTPS interception: {e}")
                except Exception as e:
                    self.logger.error(f"Error in HTTPS interception: {e}")
            else:
                # Without SSL interception, we just tunnel the traffic
                # Connect to the target server
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.settimeout(10)
                server_socket.connect((host, port))
                
                # Use select to handle both connections efficiently
                client_socket.setblocking(0)
                server_socket.setblocking(0)
                
                is_active = True
                while is_active:
                    # Wait for data on either socket
                    readable, _, exceptional = select.select(
                        [client_socket, server_socket], [], [client_socket, server_socket], 60
                    )
                    
                    if not readable and not exceptional:  # Timeout with no activity
                        break
                    
                    # Handle readable sockets
                    for sock in readable:
                        try:
                            if sock == client_socket:  # Client -> Server
                                data = sock.recv(8192)
                                if not data:
                                    is_active = False
                                    break
                                server_socket.sendall(data)
                                bytes_to_server += len(data)
                            else:  # Server -> Client
                                data = sock.recv(8192)
                                if not data:
                                    is_active = False
                                    break
                                client_socket.sendall(data)
                                bytes_to_client += len(data)
                        except (ConnectionResetError, BrokenPipeError, socket.error) as e:
                            self.logger.debug(f"Socket error in CONNECT tunnel: {e}")
                            is_active = False
                            break
                    
                    # Handle exceptional conditions
                    for sock in exceptional:
                        self.logger.debug(f"Exception condition on socket in CONNECT tunnel")
                        is_active = False
                        break
                
                # Clean up
                server_socket.close()
            
            # Record end time and log statistics
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"HTTPS tunnel to {host}:{port} closed after {duration:.2f} seconds")
            self.logger.info(f"HTTPS tunnel statistics: {bytes_to_server} bytes sent, {bytes_to_client} bytes received")
            
            # Log a simplified response summary for the CONNECT tunnel
            summary_headers = {
                'statusline': 'HTTPS Connection (Encrypted)',
                'Host': host,
                'Port': str(port),
                'Duration': f"{duration:.2f} seconds",
                'Client-Bytes-Sent': str(bytes_to_server),
                'Server-Bytes-Received': str(bytes_to_client)
            }
            self.logger.debug(format_http_message(summary_headers, b"[Encrypted HTTPS Data]", is_request=False))
            
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


def run_server(host, port, target, log_file, transparent=False, truncate_limit=10000, cert_file=None, key_file=None):
    """Run the HTTP proxy server"""
    # Set up logger
    logger = setup_logging(log_file)
    
    # Set class variables
    ProxyHTTPRequestHandler.logger = logger
    ProxyHTTPRequestHandler.transparent_mode = transparent
    ProxyHTTPRequestHandler.truncate_limit = truncate_limit
    
    # Set up SSL interception if certificate and key are provided
    if cert_file and key_file:
        try:
            # Ensure certificate files exist
            generate_self_signed_cert(cert_file, key_file)
            
            # Create SSL context
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(certfile=cert_file, keyfile=key_file)
            
            # Disable certificate verification (since we're using a self-signed cert)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            
            ProxyHTTPRequestHandler.ssl_context = ssl_context
            ProxyHTTPRequestHandler.cert_file = cert_file
            ProxyHTTPRequestHandler.key_file = key_file
            logger.info(f"HTTPS interception enabled with certificate: {cert_file}")
        except Exception as e:
            logger.error(f"Failed to initialize SSL context: {e}")
            logger.info("Continuing without HTTPS interception")
            ProxyHTTPRequestHandler.ssl_context = None
    else:
        ProxyHTTPRequestHandler.ssl_context = None
    
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
    logger.info(f"HTTPS interception: {'Enabled' if ProxyHTTPRequestHandler.ssl_context else 'Disabled'}")
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
    parser = argparse.ArgumentParser(description="HTTP/HTTPS Proxy Server with Request/Response Logging")
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind the proxy server to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='Port to run the proxy server on (default: 8080)')
    parser.add_argument('--target', type=str, default='http://example.com', help='Target host to proxy to (default: http://example.com). Ignored if --transparent is used.')
    parser.add_argument('--logfile', type=str, default=None, help='Log file to write to (default: console only)')
    parser.add_argument('--transparent', action='store_true', help='Run in transparent mode (proxy to any host requested by the client)')
    parser.add_argument('--truncate-limit', type=int, default=10000, help='Maximum number of characters to display for response/request bodies (default: 10000, 0 for no truncation)')
    parser.add_argument('--cert', type=str, default=None, help='Path to SSL certificate for HTTPS interception')
    parser.add_argument('--key', type=str, default=None, help='Path to SSL key for HTTPS interception')
    
    args = parser.parse_args()
    run_server(args.host, args.port, args.target, args.logfile, args.transparent, args.truncate_limit, args.cert, args.key)


if __name__ == "__main__":
    main()
