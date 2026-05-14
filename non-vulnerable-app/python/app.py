from http.server import BaseHTTPRequestHandler, HTTPServer
import json

HOST = "0.0.0.0"
PORT = 8000

class AppHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self._set_headers(200, "text/plain; charset=utf-8")
            self.wfile.write(b"OK")
            return

        if self.path == "/api/status":
            self._set_headers(200, "application/json; charset=utf-8")
            payload = {
                "status": "ok",
                "application": "cra-pipeline-test-app"
            }
            self.wfile.write(json.dumps(payload).encode("utf-8"))
            return

        if self.path == "/":
            self._set_headers()
            html = """
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>CRA Pipeline Test App</title>
            </head>
            <body>
                <h1>CRA Pipeline Test App</h1>
                <p>Application is running correctly.</p>
                <p>Health endpoint: <a href="/health">/health</a></p>
                <p>API endpoint: <a href="/api/status">/api/status</a></p>
            </body>
            </html>
            """
            self.wfile.write(html.encode("utf-8"))
            return

        self._set_headers(404, "text/plain; charset=utf-8")
        self.wfile.write(b"Not Found")

    def log_message(self, format, *args):
        return

if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), AppHandler)
    server.serve_forever()