# GenTriage

GenTriage — a demo APK triage platform (dashboard, gateway, and workers).

Quick start (development):

1. Start required services (Kafka, Mongo, etc) via Docker Compose:

```powershell
cd deployments
docker compose up -d
```

2. Run the API gateway (if developing locally):

```powershell
cd go-services
go run ./cmd/api-gateway
```

3. Start the frontend dev server:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
```

4. Start workers (optional):

```powershell
python -u python-workers/simulator/sim_analyzer.py
```

This repository is a work-in-progress demo. See `go-services/cmd/api-gateway/main.go` and `frontend/src/pages/Dashboard.jsx` for recent frontend/backend upload progress work.
# GenTriage — Local dev notes

This workspace contains a demo pipeline (API gateway, Kafka, workers, frontend) for APK triage.

Quick start (local development):

1. Start Kafka (KRaft) using docker-compose:

```powershell
# from repo root
docker compose -f deployments/docker-compose.yml up -d kafka
```

2. Start the API gateway (if you prefer Docker) or run locally (Go build). Gateway default: `http://127.0.0.1:8080`.

3. Start the frontend dev server:

```powershell
cd frontend
npm.cmd install
npm.cmd run dev
# open http://localhost:5173 (or the port printed by Vite)
```

4. Start the simulator worker (Python):

```powershell
# ensure requirements installed (kafka-python)
python -m pip install -r python-workers/simulator/requirements.txt
# run simulator, ensure it can reach Kafka
$env:GENTRIAGE_KAFKA_BROKER='127.0.0.1:9094'; python -u python-workers/simulator/sim_analyzer.py
```

5. Test a demo ingest:

```powershell
Invoke-RestMethod -Method POST -Uri http://127.0.0.1:8080/api/v1/simulate -ContentType 'application/json' -Body '{"dataset":"Malicious APK Corpus"}'
Invoke-RestMethod -Method GET -Uri http://127.0.0.1:8080/api/v1/tasks
```

Notes
- A local MongoDB is included in `deployments/docker-compose.yml` for dev (`mongodb-dev`) if you want the gateway to persist into Mongo.
- `.gitignore` has been added to prevent large data files from being tracked. We removed `data/` from the index.
- The frontend now supports drag-and-drop uploads with real upload progress (XHR), task search and filters, a simple activity feed, and page-specific improvements.

If you want me to push a branch to a remote, tell me the remote URL or add one and I'll push the changes.
