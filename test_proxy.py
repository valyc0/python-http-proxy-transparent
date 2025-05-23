#!/usr/bin/env python3
"""
Test script for the HTTP proxy logger
This script starts a simple HTTP server and then makes a request through the proxy
"""

import http.server
import socketserver
import threading
import time
import urllib.request
import sys
import json

# Configuration
TEST_SERVER_PORT = 8000
PROXY_PORT = 8080
TEST_CONTENT = {"message": "This is a test response", "status": "ok", "code": 200}

class TestHandler(http.server.SimpleHTTPRequestHandler):
    """Test HTTP handler that returns JSON content"""
    
    def do_GET(self):
        """Handle GET request with a simple JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Test-Header', 'test-value')
        self.end_headers()
        
        # Create a JSON response
        response = json.dumps(TEST_CONTENT, indent=2)
        self.wfile.write(response.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        return

def start_test_server():
    """Start a test HTTP server in a separate thread"""
    handler = TestHandler
    httpd = socketserver.TCPServer(("", TEST_SERVER_PORT), handler)
    print(f"Starting test HTTP server on port {TEST_SERVER_PORT}")
    
    server_thread = threading.Thread(target=httpd.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    
    return httpd

def test_proxy():
    """Test the proxy with a simple HTTP request"""
    print("\n1. Starting test HTTP server...")
    test_server = start_test_server()
    
    try:
        print("\n2. Making request through the proxy...")
        # Configure proxy
        proxy_handler = urllib.request.ProxyHandler({
            'http': f'http://localhost:{PROXY_PORT}',
            'https': f'http://localhost:{PROXY_PORT}'
        })
        opener = urllib.request.build_opener(proxy_handler)
        urllib.request.install_opener(opener)
        
        # Send test request
        response = urllib.request.urlopen(f'http://localhost:{TEST_SERVER_PORT}/')
        
        # Read and display response
        content = response.read().decode('utf-8')
        print("\n3. Received response:")
        print(f"Status code: {response.status}")
        print("Headers:")
        for header in response.getheaders():
            print(f"  {header[0]}: {header[1]}")
        print("Body:")
        print(content)
        
        print("\n4. Test completed successfully!")
        
    except Exception as e:
        print(f"\nError during test: {e}")
        return 1
    finally:
        test_server.shutdown()
    
    return 0

if __name__ == "__main__":
    print("HTTP Proxy Logger Test")
    print("=====================")
    print("This test script will:")
    print("1. Start a test HTTP server on port 8000")
    print("2. Make a request to the test server through the proxy")
    print("3. Display the response received through the proxy")
    print("\nMake sure the proxy is running in transparent mode with:")
    print("  ./start_proxy.sh 8080 transparent")
    print("\nPress Enter to continue or Ctrl+C to abort...")
    
    try:
        input()
    except KeyboardInterrupt:
        print("\nTest aborted.")
        sys.exit(1)
    
    sys.exit(test_proxy())
