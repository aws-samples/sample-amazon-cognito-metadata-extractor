#!/usr/bin/env python3
"""
Simple HTTP server to serve the test-api.html file without CORS issues
"""
import http.server
import socketserver
import os
import webbrowser

# Configuration
PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))
FILE_TO_OPEN = "view_metadata.html"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def run_server():
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"Serving at http://localhost:{PORT}")
        print(f"Opening {FILE_TO_OPEN} in your browser...")
        webbrowser.open(f"http://localhost:{PORT}/{FILE_TO_OPEN}")
        print("Press Ctrl+C to stop the server")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()