from http.server import BaseHTTPRequestHandler
import json
import sys
import os
import traceback

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        diag = {
            "status": "ok",
            "message": "BaseHTTPRequestHandler reached successfully on Vercel!",
            "python": sys.version,
            "cwd": os.getcwd(),
            "sys_path": sys.path[:8],
            "environ_keys": list(os.environ.keys())[:15],
        }

        # Check what modules can be imported
        checks = {}
        for mod in ["fastapi", "uvicorn", "pydantic", "sklearn", "numpy", "sqlalchemy"]:
            try:
                __import__(mod)
                checks[mod] = "OK"
            except Exception as e:
                checks[mod] = f"FAILED: {e}"
        diag["module_checks"] = checks

        # Check if backend can be imported
        try:
            from pathlib import Path
            root = Path(__file__).resolve().parent.parent
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            if str(root / "backend") not in sys.path:
                sys.path.insert(0, str(root / "backend"))
            import backend.app.main
            diag["backend_import"] = "OK"
        except Exception as e:
            diag["backend_import"] = f"FAILED: {e}"
            diag["backend_traceback"] = traceback.format_exc().splitlines()[-10:]

        self.wfile.write(json.dumps(diag, indent=2).encode('utf-8'))
