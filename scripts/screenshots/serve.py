#!/usr/bin/env python3
"""Static server with SPA fallback: unknown paths serve index.html so the
Leptos client-side router resolves /analysis, /fleet-apply, etc. Localhost only."""
import http.server
import os
import socketserver

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "serve")
PORT = 8137


class SpaHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def do_GET(self):
        # translate_path, not a hand-built join: it is the same resolution the
        # parent will use to serve the file, it strips the query and fragment,
        # and it discards `..` components. Joining ROOT with the raw request
        # path let an existence probe escape ROOT, which is what CodeQL #14
        # flagged. Serving never escaped, because the parent re-resolved the
        # path safely, so only the `isfile` answer was ever wrong.
        target = self.translate_path(self.path)
        if os.path.isfile(target):
            return super().do_GET()
        # Fallback: hand back index.html for client-side routes.
        self.path = "/index.html"
        return super().do_GET()

    def log_message(self, *a):
        pass  # quiet


with socketserver.ThreadingTCPServer(("127.0.0.1", PORT), SpaHandler) as httpd:
    httpd.allow_reuse_address = True
    print(f"serving {ROOT} on http://127.0.0.1:{PORT}", flush=True)
    httpd.serve_forever()
