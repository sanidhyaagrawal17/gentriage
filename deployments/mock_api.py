import json
from http.server import HTTPServer, BaseHTTPRequestHandler

SAMPLE_DASHBOARD = {
    "summary": {
        "total_alerts": 2,
        "high_risk": 1,
        "medium_risk": 1
    },
    "alerts": [
        {
            "id": "alert-1",
            "apk_name": "com.evil.fraud",
            "score": 0.92,
            "status": "Critical",
            "source": "frauddropper_v1.apk",
            "summary": "Excessive sensitive permissions, suspicious API usage, and outbound network activity.",
            "timestamp": "2026-05-26T12:00:00Z",
            "why_malicious": [
                "Requested SMS and contact permissions without clear user value.",
                "Static scan found URLs and suspicious crypto/runtime APIs.",
                "Runtime telemetry captured outbound URL creation and encoding activity."
            ],
            "static_evidence": {
                "permissions": ["android.permission.SEND_SMS", "android.permission.READ_CONTACTS", "android.permission.INTERNET"],
                "urls": ["https://bad.example.com/api/v1/push"],
                "domains": ["bad.example.com"],
                "suspicious_api_hits": [{"keyword": "DexClassLoader", "count": 2}]
            },
            "runtime_summary": {
                "network_targets": ["https://bad.example.com/api/v1/push"],
                "suspicious_network_targets": ["https://bad.example.com/api/v1/push"],
                "action_counts": {"URL_INIT": 3, "BASE64_ENCODE": 2}
            },
            "llm": {
                "summary": "The APK is high risk because it combines sensitive permissions with clear network and runtime indicators of exfiltration.",
                "detected_patterns": ["credential harvesting", "silent exfiltration"],
                "evidence_snippets": ["URL_INIT -> https://bad.example.com/api/v1/push", "android.permission.SEND_SMS"],
                "confidence": 0.93,
                "confidence_by_claim": {"summary": 0.94, "severity_justification": 0.91},
                "recommended_actions": ["Quarantine the APK", "Block the observed domains", "Reverse engineer the payload further"],
                "severity_justification": "Multiple independent indicators support a critical severity verdict.",
                "risk_explanation": "Permissions and runtime events align with data theft and command-and-control behavior."
            }
        },
        {
            "id": "alert-2",
            "apk_name": "com.suspicious.adware",
            "score": 0.63,
            "status": "High Risk",
            "source": "adtrack_pro.apk",
            "summary": "Possible adware behavior: background services, network calls, and encoded payloads.",
            "timestamp": "2026-05-26T11:30:00Z",
            "why_malicious": [
                "Background services and network endpoints were observed.",
                "Encoded payload handling suggests hidden behavior.",
                "Risk remains elevated even without direct data theft evidence."
            ],
            "static_evidence": {
                "permissions": ["android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"],
                "domains": ["ads.example.net"],
                "suspicious_api_hits": [{"keyword": "Base64", "count": 4}]
            },
            "runtime_summary": {
                "network_targets": ["http://ads.example.net/collect"],
                "suspicious_network_targets": ["http://ads.example.net/collect"],
                "action_counts": {"URL_INIT": 2, "BASE64_ENCODE": 1}
            },
            "llm": {
                "summary": "The APK is moderately high risk due to background persistence, ad-style network activity, and encoded payload handling.",
                "detected_patterns": ["adware", "persistence"],
                "evidence_snippets": ["RECEIVE_BOOT_COMPLETED", "ads.example.net/collect"],
                "confidence": 0.79,
                "confidence_by_claim": {"summary": 0.82, "severity_justification": 0.76},
                "recommended_actions": ["Inspect bundled SDKs", "Monitor outbound connections", "Review persistence logic"],
                "severity_justification": "The runtime and static behaviors are consistent with adware-like persistence.",
                "risk_explanation": "The app requests persistence and contacts ad endpoints from background flows."
            }
        }
    ]
}

class Handler(BaseHTTPRequestHandler):
    def _set_json(self, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

    def do_GET(self):
        if self.path.startswith('/api/dashboard'):
            self._set_json(200)
            self.wfile.write(json.dumps(SAMPLE_DASHBOARD).encode('utf-8'))
        elif self.path.startswith('/api/alerts'):
            self._set_json(200)
            self.wfile.write(json.dumps(SAMPLE_DASHBOARD['alerts']).encode('utf-8'))
        elif self.path == '/health' or self.path == '/':
            self._set_json(200)
            self.wfile.write(json.dumps({"status":"ok"}).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', '8081'))
    server_address = ('0.0.0.0', port)
    httpd = HTTPServer(server_address, Handler)
    print(f'Mock API serving on http://0.0.0.0:{port}')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
