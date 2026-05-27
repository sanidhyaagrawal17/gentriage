package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/segmentio/kafka-go"
)

const (
	consumeTopic       = "apk_uploaded"
	produceAnalyzeTopic = "analyze_apk"
	defaultKafkaAddr   = "localhost:9092"
)

// APKUploadEvent matches the structure from api-gateway
type APKUploadEvent struct {
	TaskID    string `json:"task_id"`
	FilePath  string `json:"file_path"`
	FileName  string `json:"file_name"`
	Timestamp string `json:"timestamp"` // simplified for reading
}

// AnalyzeTaskEvent is sent to the frida worker
type AnalyzeTaskEvent struct {
	TaskID   string `json:"task_id"`
	FilePath string `json:"file_path"`
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func main() {
	kafkaBroker := envOrDefault("GENTRIAGE_KAFKA_BROKER", defaultKafkaAddr)

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{kafkaBroker},
		GroupID:  "pipeline-manager-group",
		Topic:    consumeTopic,
		MinBytes: 10e3,
		MaxBytes: 10e6,
	})
	defer reader.Close()

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(kafkaBroker),
		Topic:                  produceAnalyzeTopic,
		AllowAutoTopicCreation: true,
		Balancer:               &kafka.LeastBytes{},
	}
	defer writer.Close()

	log.Printf("Pipeline Manager started. Listening to %s, pushing to %s on broker %s", consumeTopic, produceAnalyzeTopic, kafkaBroker)

	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil {
			log.Printf("Error reading message: %v", err)
			continue
		}

		var uploadEvent APKUploadEvent
		if err := json.Unmarshal(m.Value, &uploadEvent); err != nil {
			log.Printf("Failed to unmarshal APKUploadEvent: %v", err)
			continue
		}

		log.Printf("Received upload event for task: %s, file: %s", uploadEvent.TaskID, uploadEvent.FileName)

		
		analyzeEvent := AnalyzeTaskEvent{
			TaskID:   uploadEvent.TaskID,
			FilePath: uploadEvent.FilePath,
		}

		eventBytes, err := json.Marshal(analyzeEvent)
		if err != nil {
			log.Printf("Failed to marshal AnalyzeTaskEvent: %v", err)
			continue
		}

		err = writer.WriteMessages(context.Background(),
			kafka.Message{
				Key:   []byte(uploadEvent.TaskID),
				Value: eventBytes,
			},
		)

		if err != nil {
			log.Printf("Failed to route task %s to %s: %v", uploadEvent.TaskID, produceAnalyzeTopic, err)
		} else {
			log.Printf("Successfully routed task %s to %s", uploadEvent.TaskID, produceAnalyzeTopic)
		}
	}
}
