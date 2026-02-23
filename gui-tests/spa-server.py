"""Minimal SPA-aware HTTP server for GUI testing.

Serves static files from the working directory. For any path that
doesn't match a real file, serves index.html (SPA fallback routing).
"""

import http.server
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8787


class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Strip query string for file lookup
        path = self.path.split("?")[0]

        # Serve real files normally (JS, CSS, WASM, images, etc.)
        local_path = os.path.join(os.getcwd(), path.lstrip("/"))
        if os.path.isfile(local_path):
            return super().do_GET()

        # SPA fallback: serve index.html for all non-file routes
        self.path = "/index.html"
        return super().do_GET()

    def log_message(self, format, *args):
        pass  # Suppress request logging


if __name__ == "__main__":
    server = http.server.HTTPServer(("127.0.0.1", PORT), SPAHandler)
    print(f"SPA server on http://127.0.0.1:{PORT}", flush=True)
    server.serve_forever()
