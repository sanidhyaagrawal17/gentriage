import sys
import json
import urllib.request

GATEWAY_URL = "http://127.0.0.1:8080"

def main(task_id, status):
    url = f"{GATEWAY_URL}/api/v1/tasks/{task_id}/status"
    payload = {"status": status}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:
        print(resp.read().decode('utf-8'))

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: update_status.py <task_id> <status>')
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
