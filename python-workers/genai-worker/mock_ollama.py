from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')
        try:
            req = json.loads(body)
        except Exception:
            req = {}

        # Build a fake LLM response: embed JSON string in 'response' field
        fake_output = {
            "summary": "APK exhibits SMS-sending behavior and dangerous permissions.",
            "risk_explanation": "High-risk permissions (SEND_SMS) and runtime telemetry show SMS API usage.",
            "recommended_actions": [
                "Isolate the APK and block network access.",
                "Perform manual dynamic analysis under emulator.",
                "Update detection rules and notify stakeholders."
            ],
            "confidence": 0.87
        }

        response_body = {
            "response": json.dumps(fake_output)
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response_body).encode('utf-8'))

if __name__ == '__main__':
    # Use a different port to avoid conflicts with a local Ollama instance
    PORT = 11435
    server = HTTPServer(('127.0.0.1', PORT), MockHandler)
    print(f'Mock Ollama server listening on http://127.0.0.1:{PORT}')
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        print('Server stopped')
