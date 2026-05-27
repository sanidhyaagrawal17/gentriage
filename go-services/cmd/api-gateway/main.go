package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
)

const (
	defaultPort      = ":8080"
	defaultUploadDir = "../../data/apks"
	kafkaTopic       = "apk_uploaded"
	defaultKafkaAddr = "localhost:9092"
	defaultMongo     = "mongodb://admin:password@localhost:27017"
)

type APKUploadEvent struct {
	TaskID    string    `json:"task_id"`
	FilePath  string    `json:"file_path"`
	FileName  string    `json:"file_name"`
	Timestamp time.Time `json:"timestamp"`
}

type Task struct {
	TaskID    string    `json:"task_id" bson:"task_id"`
	FileName  string    `json:"file_name" bson:"file_name"`
	FilePath  string    `json:"file_path" bson:"file_path"`
	Status    string    `json:"status" bson:"status"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

// Upload progress record (tracked server-side)
type UploadProgress struct {
	Total   int64 `json:"total"`
	Written int64 `json:"written"`
}

// countingWriter updates a sync.Map progress store while writing to destination
type countingWriter struct {
	TaskID        string
	Dst           io.Writer
	ProgressStore *sync.Map
}

func (cw *countingWriter) Write(p []byte) (int, error) {
	n, err := cw.Dst.Write(p)
	if n > 0 {
		v, _ := cw.ProgressStore.LoadOrStore(cw.TaskID, UploadProgress{Total: 0, Written: 0})
		prev := v.(UploadProgress)
		prev.Written += int64(n)
		cw.ProgressStore.Store(cw.TaskID, prev)
	}
	return n, err
}


func tasksFilePath(uploadDir string) string {
	return filepath.Join(uploadDir, "tasks.json")
}

func loadTasks(uploadDir string) (map[string]Task, error) {
	path := tasksFilePath(uploadDir)
	tasks := make(map[string]Task)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return tasks, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return tasks, nil
	}
	if err := json.Unmarshal(data, &tasks); err != nil {
		return nil, err
	}
	return tasks, nil
}

func saveTasks(uploadDir string, tasks map[string]Task) error {
	path := tasksFilePath(uploadDir)
	data, err := json.MarshalIndent(tasks, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func getAllTasks(uploadDir string) ([]Task, error) {
	m, err := loadTasks(uploadDir)
	if err != nil {
		return nil, err
	}
	list := make([]Task, 0, len(m))
	for _, t := range m {
		list = append(list, t)
	}
	return list, nil
}

func getTaskByID(uploadDir, id string) (Task, bool, error) {
	tasks, err := loadTasks(uploadDir)
	if err != nil {
		return Task{}, false, err
	}
	t, ok := tasks[id]
	return t, ok, nil
}

func upsertTask(uploadDir string, t Task) error {
	tasks, err := loadTasks(uploadDir)
	if err != nil {
		return err
	}
	tasks[t.TaskID] = t
	return saveTasks(uploadDir, tasks)
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	port := envOrDefault("GENTRIAGE_PORT", defaultPort)
	uploadDir := envOrDefault("GENTRIAGE_UPLOAD_DIR", defaultUploadDir)
	kafkaBroker := envOrDefault("GENTRIAGE_KAFKA_BROKER", defaultKafkaAddr)

	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Fatalf("Failed to create upload directory: %v", err)
	}

	// Use in-memory mock data for alerts/dashboard while Mongo is not required for frontend testing
	sampleAlerts := []map[string]interface{}{
		{
			"id": "T-1001",
			"status": "Critical",
			"risk": 96,
			"source": "frauddropper_v1.apk",
			"explanation": "Suspicious SMS behavior detected.",
			"why_malicious": []string{"Requested SMS and contact permissions without clear user value.", "Static scan found URLs and suspicious crypto/runtime APIs.", "Runtime telemetry captured outbound URL creation and encoding activity."},
			"static_evidence": map[string]interface{}{
				"permissions": []string{"android.permission.SEND_SMS", "android.permission.READ_CONTACTS", "android.permission.INTERNET"},
				"domains": []string{"bad.example.com"},
				"urls": []string{"https://bad.example.com/api/v1/push"},
			},
			"runtime_summary": map[string]interface{}{
				"network_targets": []string{"https://bad.example.com/api/v1/push"},
				"suspicious_network_targets": []string{"https://bad.example.com/api/v1/push"},
			},
			"llm": map[string]interface{}{
				"summary": "The APK is high risk because it combines sensitive permissions with clear network and runtime indicators of exfiltration.",
				"detected_patterns": []string{"credential harvesting", "silent exfiltration"},
				"evidence_snippets": []string{"URL_INIT -> https://bad.example.com/api/v1/push", "android.permission.SEND_SMS"},
				"confidence": 0.93,
				"recommended_actions": []string{"Quarantine the APK", "Block the observed domains", "Reverse engineer the payload further"},
			},
		},
		{
			"id": "T-1002",
			"status": "High Risk",
			"risk": 84,
			"source": "adtrack_pro.apk",
			"explanation": "Dangerous permissions and runtime telemetry.",
			"why_malicious": []string{"Background services and network endpoints were observed.", "Encoded payload handling suggests hidden behavior."},
			"static_evidence": map[string]interface{}{
				"permissions": []string{"android.permission.INTERNET", "android.permission.RECEIVE_BOOT_COMPLETED"},
				"domains": []string{"ads.example.net"},
			},
			"runtime_summary": map[string]interface{}{
				"network_targets": []string{"http://ads.example.net/collect"},
			},
			"llm": map[string]interface{}{
				"summary": "The APK is moderately high risk due to background persistence and ad-style network activity.",
				"evidence_snippets": []string{"RECEIVE_BOOT_COMPLETED", "ads.example.net/collect"},
				"confidence": 0.79,
			},
		},
	}

	kafkaWriter := &kafka.Writer{
		Addr:                   kafka.TCP(kafkaBroker),
		Topic:                  kafkaTopic,
		AllowAutoTopicCreation: true,
		Balancer:               &kafka.LeastBytes{},
	}
	defer kafkaWriter.Close()

	log.Printf("Kafka Writer initialized. Connected to broker at %s", kafkaBroker)

	// Note: MongoDB support optional; currently using file-backed tasks.json

	var uploadProgress sync.Map // map[string]UploadProgress

	enableCors := func(w *http.ResponseWriter) {
		(*w).Header().Set("Access-Control-Allow-Origin", "*")
		(*w).Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		(*w).Header().Set("Access-Control-Allow-Headers", "Content-Type")
	}

	http.HandleFunc("/api/v1/upload", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Support optional task_id query parameter so clients can poll server-side progress
		taskID := r.URL.Query().Get("task_id")
		// Use multipart streaming to copy file and update progress
		mr, err := r.MultipartReader()
		if err != nil {
			http.Error(w, "Failed to parse multipart data", http.StatusBadRequest)
			return
		}

		if taskID == "" {
			taskID = uuid.New().String()
		}

		// initialize progress record if content length available
		total := r.ContentLength
		uploadProgress.Store(taskID, UploadProgress{Total: total, Written: 0})

		var savedFilePath string
		var savedFileName string
		// iterate parts
		for {
			part, perr := mr.NextPart()
			if perr == io.EOF {
				break
			}
			if perr != nil {
				log.Printf("multipart next part error: %v", perr)
				break
			}
			if part.FormName() != "apk" {
				// consume and ignore other fields
				io.Copy(io.Discard, part)
				part.Close()
				continue
			}

			savedFileName = filepath.Base(part.FileName())
			safeFileName := fmt.Sprintf("%s_%s", taskID, savedFileName)
			savedFilePath = filepath.Join(uploadDir, safeFileName)
			dst, derr := os.Create(savedFilePath)
			if derr != nil {
				log.Printf("Failed to create file: %v", derr)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}

			// counting writer updates progress map
			cw := &countingWriter{TaskID: taskID, Dst: dst, ProgressStore: &uploadProgress}
			if _, err := io.Copy(cw, part); err != nil {
				log.Printf("Failed to save file: %v", err)
				dst.Close()
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			dst.Close()
			part.Close()
		}

		event := APKUploadEvent{
			TaskID:    taskID,
			FilePath:  savedFilePath,
			FileName:  savedFileName,
			Timestamp: time.Now(),
		}

		eventBytes, err := json.Marshal(event)
		if err != nil {
			log.Printf("Failed to marshal Kafka event: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		msg := kafka.Message{
			Key:   []byte(taskID),
			Value: eventBytes,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := kafkaWriter.WriteMessages(ctx, msg); err != nil {
			log.Printf("Failed to write message to Kafka: %v", err)
			http.Error(w, "Failed to queue analysis task", http.StatusInternalServerError)
			return
		}

		// persist basic task metadata so the frontend can list tasks
		task := Task{
			TaskID:    taskID,
			FileName:  savedFileName,
			FilePath:  savedFilePath,
			Status:    "queued",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := upsertTask(uploadDir, task); err != nil {
			log.Printf("Failed to persist task: %v", err)
		}

		log.Printf("Task %s queued successfully for file %s", taskID, savedFileName)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		response := map[string]string{
			"status":  "queued",
			"task_id": taskID,
			"message": "APK successfully uploaded and queued for GenTriage analysis.",
		}
		json.NewEncoder(w).Encode(response)
	})

	// Initialize an upload session: client calls this to receive a task_id before uploading
	http.HandleFunc("/api/v1/upload/init", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		id := uuid.New().String()
		uploadProgress.Store(id, UploadProgress{Total: 0, Written: 0})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"task_id": id})
	})

	// GET upload progress: /api/v1/upload/progress?task_id=...
	http.HandleFunc("/api/v1/upload/progress", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		id := r.URL.Query().Get("task_id")
		if id == "" {
			http.Error(w, "Missing task_id", http.StatusBadRequest)
			return
		}
		v, ok := uploadProgress.Load(id)
		if !ok {
			// return zero progress if not found
			json.NewEncoder(w).Encode(map[string]int64{"total": 0, "written": 0})
			return
		}
		json.NewEncoder(w).Encode(v)
	})

	http.HandleFunc("/api/v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		list, err := getAllTasks(uploadDir)
		if err != nil {
			log.Printf("Failed to load tasks: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(list)
	})

	// Simulate ingest for demo datasets: POST {"dataset":"name","file_name":"optional.apk"}
	http.HandleFunc("/api/v1/simulate", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			log.Printf("Failed to decode simulate body: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}
		dataset := body["dataset"]
		fileName := body["file_name"]
		if fileName == "" {
			fileName = fmt.Sprintf("demo_%s.apk", strings.ReplaceAll(dataset, " ", "_"))
		}

		taskID := uuid.New().String()
		safeFileName := fmt.Sprintf("%s_%s", taskID, filepath.Base(fileName))
		filePath := filepath.Join(uploadDir, safeFileName)

		// create a lightweight task and persist
		task := Task{
			TaskID:    taskID,
			FileName:  fileName,
			FilePath:  filePath,
			Status:    "queued",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := upsertTask(uploadDir, task); err != nil {
			log.Printf("Failed to persist simulated task: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// publish an APKUploadEvent so workers can react the same as a real upload
		event := APKUploadEvent{TaskID: taskID, FilePath: filePath, FileName: fileName, Timestamp: time.Now()}
		eventBytes, _ := json.Marshal(event)
		msg := kafka.Message{Key: []byte(taskID), Value: eventBytes}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := kafkaWriter.WriteMessages(ctx, msg); err != nil {
			log.Printf("Failed to write simulate message to Kafka: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"task_id": taskID, "status": "queued"})
	})

	http.HandleFunc("/api/v1/tasks/", func(w http.ResponseWriter, r *http.Request) {
 		enableCors(&w)
 		if r.Method == http.MethodOptions {
 			w.WriteHeader(http.StatusOK)
 			return
 		}

 		path := strings.TrimPrefix(r.URL.Path, "/api/v1/tasks/")
 		if path == "" {
 			http.NotFound(w, r)
 			return
 		}

 		// POST /api/v1/tasks/{id}/status => update status
 		if strings.HasSuffix(path, "/status") && r.Method == http.MethodPost {
 			id := strings.TrimSuffix(path, "/status")
 			if id == "" {
 				http.Error(w, "Missing task id", http.StatusBadRequest)
 				return
 			}

 			var body map[string]interface{}
 			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
 				log.Printf("Failed to decode status update: %v", err)
 				http.Error(w, "Bad request", http.StatusBadRequest)
 				return
 			}

			task, ok, err := getTaskByID(uploadDir, id)
			if err != nil {
				log.Printf("Failed to query task for update: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			if s, ok := body["status"].(string); ok && s != "" {
				task.Status = s
			}
			task.UpdatedAt = time.Now()
			if err := upsertTask(uploadDir, task); err != nil {
				log.Printf("Failed to save task after update: %v", err)
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(task)
 			return
 		}

 		// GET /api/v1/tasks/{id} => return task
 		if r.Method == http.MethodGet {
 			id := path
			task, ok, err := getTaskByID(uploadDir, id)
			if err != nil {
				log.Printf("Failed to load task: %v", err)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !ok {
				http.Error(w, "Not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(task)
 			return
 		}

 		http.NotFound(w, r)
 	})


	http.HandleFunc("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		enableCors(&w)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sampleAlerts)
	})

	http.HandleFunc("/api/dashboard", func(w http.ResponseWriter, r *http.Request) {
		enableCors(&w)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		enableCors(&w)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"alerts": sampleAlerts,
			"metrics": []map[string]string{
				{"label": "Total Analyzed", "value": "2", "hint": "", "tone": "#3b82f6"},
				{"label": "Critical", "value": "1", "hint": "", "tone": "#e46b6b"},
				{"label": "High Risk", "value": "1", "hint": "", "tone": "#e08f45"},
			},
			"datasets": []map[string]interface{}{},
			"activity": []interface{}{},
			"featureBars": []map[string]interface{}{},
		})
	})

	log.Printf("GenTriage API Gateway listening on port %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
