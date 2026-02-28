"""Minimal SPA-aware HTTP server for GUI testing.

Serves static files from the working directory. For any path that
doesn't match a real file, serves index.html (SPA fallback routing).
"""

import http.server
import os
import sys
import socketserver

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8787


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?")[0]
        local_path = os.path.join(os.getcwd(), path.lstrip("/"))
        if os.path.isfile(local_path):
            return super().do_GET()
        self.path = "/index.html"
        return super().do_GET()

    def log_message(self, format, *args):
        pass


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    server = ThreadedHTTPServer(("127.0.0.1", PORT), SPAHandler)
    print(f"SPA server on http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
