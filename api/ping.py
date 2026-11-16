from http.server import BaseHTTPRequestHandler
import json
import sys
import os
import traceback
from pathlib import Path

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        diag = {
            "status": "ok",
            "python": sys.version,
            "cwd": os.getcwd(),
        }

        # Check dependencies
        modules_status = {}
        for mod in ["fastapi", "pydantic", "pydantic_settings", "sqlalchemy", "aiosqlite", "numpy", "joblib", "sklearn", "google.genai", "greenlet"]:
            try:
                __import__(mod)
                modules_status[mod] = "OK"
            except Exception as e:
                modules_status[mod] = f"FAILED: {e}"
        diag["modules"] = modules_status

        # Check backend import and lifespan
        try:
            root = Path(__file__).resolve().parent.parent
            for p in [str(root), str(root / "backend"), os.getcwd(), os.path.join(os.getcwd(), "backend")]:
                if p not in sys.path:
                    sys.path.insert(0, p)
            import backend.app.main as bm
            diag["backend_import"] = "OK"
            diag["backend_routes"] = len(bm.app.routes)
            diag["demo_mode"] = getattr(bm.settings, "DEMO_MODE", None)
        except Exception as e:
            diag["backend_import"] = f"FAILED: {e}"
            diag["backend_traceback"] = traceback.format_exc().splitlines()[-10:]

        self.wfile.write(json.dumps(diag, indent=2).encode('utf-8'))
