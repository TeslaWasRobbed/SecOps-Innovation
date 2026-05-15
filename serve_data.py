"""Simple HTTP server to serve actor tracking data for local development."""

import http.server
import json
import socketserver
from pathlib import Path


class ActorDataHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/actor-tracking':
            # Serve the actor tracking data as JSON API
            tracking_file = Path("shared/actor_tracking_data.json")
            
            if tracking_file.exists():
                try:
                    with open(tracking_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Access-Control-Allow-Origin', '*')
                    self.end_headers()
                    
                    response = json.dumps(data, indent=2)
                    self.wfile.write(response.encode('utf-8'))
                    return
                except Exception as e:
                    self.send_error(500, f"Error loading tracking data: {e}")
                    return
            else:
                self.send_error(404, "Actor tracking data not found")
                return
        
        # For all other requests, use default behavior
        super().do_GET()


def start_server(port=8000):
    """Start the development server."""
    with socketserver.TCPServer(("", port), ActorDataHandler) as httpd:
        print(f"Serving at http://localhost:{port}")
        print(f"Actor tracking API: http://localhost:{port}/api/actor-tracking")
        print("Press Ctrl+C to stop")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped")


if __name__ == "__main__":
    start_server()