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
        rel = self.path.split("?", 1)[0].lstrip("/")
        target = os.path.join(ROOT, rel)
        if rel and os.path.isfile(target):
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
