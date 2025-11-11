import re
import tempfile
import subprocess
import os
import sys
import http.server
import socketserver
import json
from typing import Dict
from datetime import datetime

# --- Whitelist patterns (unchanged) ---
PY_PRINT_PATTERN = re.compile(r'^\s*print\(\s*["\'].*Hello.*["\']\s*\)\s*$', re.MULTILINE)
PS_WRITE_PATTERN  = re.compile(r'^\s*Write-Output\s+["\'].*Hello.*["\']\s*$', re.IGNORECASE)
PS_INVOKE_IPIFY_PATTERN = re.compile(r'^\s*Invoke-RestMethod\s+-Uri\s+["\']https://api\.ipify\.org["\']\s*$', re.IGNORECASE)
PS_INVOKE_WEBREQUEST_OUTFILE_PATTERN = re.compile(
    r'^\s*Invoke-WebRequest\s+["\']https?://[a-zA-Z0-9\.\-~/%_]+\??[a-zA-Z0-9=&]*["\']\s+-OutFile\s+["\'][\w\.\\/]+["\']\s*$',
    re.IGNORECASE
)

# ==========================================================
# NEW: Whitelist patterns for starting the server
# ==========================================================
# Pattern for: Start-Process -FilePath 'python' -ArgumentList '.\server.py','--host','8001'
PS_START_PROCESS_SERVER_PATTERN = re.compile(
    r'^\s*Start-Process\s+-FilePath\s+[\'"]python[\'"]\s+-ArgumentList\s+[\'"].\\server\.py[\'"]\s*,\s*[\'"]--host[\'"]\s*,\s*[\'"]\d+[\'"]\s*$',
    re.IGNORECASE
)

# Pattern for: python .\server.py --host 8001
PS_PYTHON_SERVER_PATTERN = re.compile(
    r'^\s*python(?:\.exe)?\s+\.\\server\.py\s+--host\s+\d+\s*$',
    re.IGNORECASE
)


LOG_FILE = "api_activity.jsonl"

def log_event(event_data: Dict):
    """Appends a new event as a JSON line to the log file."""
    try:
        event_data['timestamp'] = datetime.utcnow().isoformat()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event_data) + "\n")
    except Exception as e:
        print(f"!!! Fout tijdens het schrijven naar logbestand: {e}")

# ... (is_python_print, is_powershell_write, etc. functions) ...
def is_python_print(code: str) -> bool: return bool(PY_PRINT_PATTERN.match(code.strip()))
def is_powershell_write(code: str) -> bool: return bool(PS_WRITE_PATTERN.match(code.strip()))
def is_powershell_invoke_ipify(code: str) -> bool: return bool(PS_INVOKE_IPIFY_PATTERN.match(code.strip()))
def is_powershell_invoke_webrequest_outfile(code: str) -> bool: return bool(PS_INVOKE_WEBREQUEST_OUTFILE_PATTERN.match(code.strip()))

# ==========================================================
# NEW: Functions to check for the new whitelist patterns
# ==========================================================
def is_powershell_start_process_server(code: str) -> bool:
    """Checks if the code matches the Start-Process server pattern."""
    return bool(PS_START_PROCESS_SERVER_PATTERN.match(code.strip()))

def is_powershell_python_server(code: str) -> bool:
    """Checks if the code matches the python server execution pattern."""
    return bool(PS_PYTHON_SERVER_PATTERN.match(code.strip()))


def execute_python(code: str):
    with tempfile.TemporaryDirectory() as td:
        script_path = os.path.join(td, "generated_script.py")
        with open(script_path, "w", encoding="utf-8") as f: f.write(code + "\n")
        return subprocess.run([sys.executable, script_path], capture_output=True, text=True, timeout=5)

def execute_powershell(code: str):
    return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy Unrestricted", "-NonInteractive", "-Command", code], capture_output=True, text=True, shell=False, timeout=15)

def process_and_execute_code(code: str) -> Dict:
    # This function is now updated for whitelisted commands
    if is_python_print(code):
        res = execute_python(code)
        return {"status": "executed", "language": "python", "stdout": res.stdout, "stderr": res.stderr}
    if is_powershell_write(code):
        res = execute_powershell(code)
        return {"status": "executed", "language": "powershell", "stdout": res.stdout, "stderr": res.stderr}
    if is_powershell_invoke_ipify(code):
        res = execute_powershell(code)
        return {"status": "executed", "language": "powershell", "stdout": res.stdout, "stderr": res.stderr}
    if is_powershell_invoke_webrequest_outfile(code):
        res = execute_powershell(code)
        if res.returncode == 0:
            return {"status": "executed", "language": "powershell", "stdout": "File downloaded successfully.", "stderr": res.stderr}
        else:
            return {"status": "error", "language": "powershell", "stdout": res.stdout, "stderr": f"Failed to execute command. {res.stderr}"}

    # ==========================================================
    # NEW: Check for the server start commands
    # ==========================================================
    if is_powershell_start_process_server(code) or is_powershell_python_server(code):
        res = execute_powershell(code)
        # Note: Since Start-Process runs in the background, stdout/stderr may be empty.
        # We just confirm the command was accepted by PowerShell (returncode 0).
        if res.returncode == 0:
            return {"status": "executed", "language": "powershell", "stdout": "Server start command issued.", "stderr": res.stderr}
        else:
            return {"status": "error", "language": "powershell", "stdout": res.stdout, "stderr": f"Failed to execute command. {res.stderr}"}

    return {"status": "blocked", "message": "The provided code is not allowed by the security whitelist."}


class RequestHandler(http.server.BaseHTTPRequestHandler):
    """A custom request handler for our C2 server."""
    def _send_json_response(self, status_code: int, data: Dict):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        if self.path == '/logs':
            try:
                if not os.path.exists(LOG_FILE):
                    self._send_json_response(200, [])
                    return
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    logs = [json.loads(line) for line in f]
                self._send_json_response(200, logs)
            except Exception as e:
                self._send_json_response(500, {"status": "error", "message": str(e)})
        else:
            self._send_json_response(404, {"status": "error", "message": "Not Found"})

    def do_POST(self):
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            body = json.loads(post_data.decode('utf-8')) if post_data else {}
        except Exception as e:
            self._send_json_response(400, {"status": "error", "message": f"Bad Request: {e}"})
            return

        if self.path == '/execute':
            prompt = body.get('prompt')
            if not prompt:
                self._send_json_response(400, {"status": "error", "message": "'prompt' key is required."})
                return
            result = process_and_execute_code(prompt)
            log_event({"request": "/execute", "code": prompt, "result": result})
            self._send_json_response(200, result)
        else:
            self._send_json_response(404, {"status": "error", "message": "Not Found"})


def run_server(port=8000, host='0.0.0.0'):
    # Simple argument parsing to allow changing the port
    if '--host' in sys.argv:
        try:
            port_index = sys.argv.index('--host') + 1
            port = int(sys.argv[port_index])
        except (ValueError, IndexError):
            print("Invalid port specified. Using default 8000.")
            port = 8000
            
    with socketserver.TCPServer((host, port), RequestHandler) as httpd:
        print("======================================================")
        print("         COMMAND & CONTROL SERVER GESTART          ")
        print("======================================================")
        print(f"Server luistert op http://{host}:{port}")
        print("Endpoints:")
        print("  - POST /execute        : Voer een whitelisted commando uit.")
        print("  - GET  /logs           : Bekijk het activiteitenlogboek.")
        print("======================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer wordt gestopt...")
            httpd.server_close()

if __name__ == "__main__":
    run_server()