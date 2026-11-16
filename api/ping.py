from http.server import BaseHTTPRequestHandler
import json
import sys
import os

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        headers_dict = dict(self.headers)
        data = {
            "status": "ok",
            "self_path": self.path,
            "headers": headers_dict,
        }
        self.wfile.write(json.dumps(data, indent=2).encode('utf-8'))
