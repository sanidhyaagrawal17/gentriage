package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	defaultKafka   = "localhost:9092"
	defaultMongo   = "mongodb://admin:password@localhost:27017"
	defaultOllama  = "http://localhost:11434/api/generate"
	ollamaModel    = "llama3" // Assuming llama3, can be customized
)

type LLMInsight struct {
	Summary             string                 `bson:"summary" json:"summary"`
	DetectedPatterns    []string               `bson:"detected_patterns" json:"detected_patterns"`
	EvidenceSnippets    []string               `bson:"evidence_snippets" json:"evidence_snippets"`
	ConfidenceByClaim   map[string]float64     `bson:"confidence_by_claim" json:"confidence_by_claim"`
	SeverityJustification string               `bson:"severity_justification" json:"severity_justification"`
	RiskExplanation     string                 `bson:"risk_explanation" json:"risk_explanation"`
	RecommendedActions  []string               `bson:"recommended_actions" json:"recommended_actions"`
	Confidence          float64                `bson:"confidence" json:"confidence"`
	AnalystPriority     string                 `bson:"analyst_priority" json:"analyst_priority"`
}

type AnalysisReport struct {
	TaskID       string      `json:"task_id"`
	FilePath     string      `json:"file_path,omitempty"`
	FileName     string      `json:"file_name,omitempty"`
	Package      string      `json:"package,omitempty"`
	RiskScore    float64     `json:"risk_score,omitempty"`
	AnalysisMode string      `json:"analysis_mode,omitempty"`
	Status       string      `json:"status"`
	Timestamp    float64     `json:"timestamp,omitempty"`
	Telemetry    interface{} `json:"telemetry"`
	StaticEvidence map[string]interface{} `json:"static_evidence,omitempty"`
	RuntimeSummary map[string]interface{} `json:"runtime_summary,omitempty"`
	WhyMalicious []string `json:"why_malicious,omitempty"`
	Evidence     map[string]interface{} `json:"evidence,omitempty"`
	LLM          LLMInsight `json:"llm,omitempty"`
}

type FinalReport struct {
	TaskID            string                 `bson:"task_id" json:"task_id"`
	Status            string                 `bson:"status" json:"status"`
	RiskScore         float64                `bson:"risk_score" json:"risk_score"`
	LLMSummary        string                 `bson:"llm_summary" json:"llm_summary"`
	LLM               LLMInsight             `bson:"llm" json:"llm"`
	RawTelemetry      interface{}            `bson:"raw_telemetry" json:"raw_telemetry"`
	StaticEvidence    map[string]interface{} `bson:"static_evidence" json:"static_evidence"`
	RuntimeSummary    map[string]interface{} `bson:"runtime_summary" json:"runtime_summary"`
	WhyMalicious      []string               `bson:"why_malicious" json:"why_malicious"`
	Evidence          map[string]interface{} `bson:"evidence" json:"evidence"`
	CreatedAt         time.Time              `bson:"created_at" json:"created_at"`
}

func envOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func generateLLMSummary(ollamaURL string, report AnalysisReport) (string, error) {
	telemetryBytes, _ := json.Marshal(report.Telemetry)
	prompt := fmt.Sprintf(`Analyze the following APK analysis telemetry and provide a concise risk assessment and threat summary.
Status: %s
Risk Score: %f
Telemetry: %s

Please provide a brief, professional summary explaining the potential risks based on these logs.`, report.Status, report.RiskScore, string(telemetryBytes))

	reqBody := map[string]interface{}{
		"model":  envOrDefault("GENTRIAGE_OLLAMA_MODEL", ollamaModel),
		"prompt": prompt,
		"stream": false,
	}

	reqBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(ollamaURL, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Ollama returned status: %d", resp.StatusCode)
	}

	var ollamaResp struct {
		Response string `json:"response"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ollamaResp); err != nil {
		return "", err
	}

	return strings.TrimSpace(ollamaResp.Response), nil
}

func main() {
	kafkaBroker := envOrDefault("GENTRIAGE_KAFKA_BROKER", defaultKafka)
	mongoURI := envOrDefault("GENTRIAGE_MONGO_URI", defaultMongo)
	ollamaURL := envOrDefault("GENTRIAGE_OLLAMA_URL", defaultOllama)
	consumeTopic := envOrDefault("GENTRIAGE_CONSUME_TOPIC", "analysis_enriched")

	// Setup MongoDB
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	clientOpts := options.Client().ApplyURI(mongoURI)
	mongoClient, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer mongoClient.Disconnect(context.Background())

	collection := mongoClient.Database("gentriage").Collection("reports")

	// Setup Kafka Reader
	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers:  []string{kafkaBroker},
		GroupID:  "reporter-group",
		Topic:    consumeTopic,
		MinBytes: 10e3,
		MaxBytes: 10e6,
	})
	defer reader.Close()

	log.Printf("Reporter started. Listening to %s, using MongoDB at %s", consumeTopic, mongoURI)

	for {
		m, err := reader.ReadMessage(context.Background())
		if err != nil {
			log.Printf("Error reading message: %v", err)
			continue
		}

		var report AnalysisReport
		if err := json.Unmarshal(m.Value, &report); err != nil {
			log.Printf("Failed to unmarshal AnalysisReport: %v", err)
			continue
		}

		log.Printf("Received complete analysis for task: %s", report.TaskID)

		// 1. Use GenAI enrichment when available, fall back to an extra summary pass only if needed.
		summary := report.LLM.Summary
		if strings.TrimSpace(summary) == "" {
			generated, err := generateLLMSummary(ollamaURL, report)
			if err != nil {
				log.Printf("Warning: Failed to generate LLM summary: %v", err)
				summary = "LLM Summary unavailable due to an error."
			} else {
				summary = generated
			}
		}

		// 2. Save to MongoDB
		finalReport := FinalReport{
			TaskID:         report.TaskID,
			Status:         report.Status,
			RiskScore:      report.RiskScore,
			LLMSummary:     summary,
			LLM:            report.LLM,
			RawTelemetry:   report.Telemetry,
			StaticEvidence: report.StaticEvidence,
			RuntimeSummary: report.RuntimeSummary,
			WhyMalicious:   report.WhyMalicious,
			Evidence:       report.Evidence,
			CreatedAt:      time.Now(),
		}

		_, err = collection.InsertOne(context.Background(), finalReport)
		if err != nil {
			log.Printf("Failed to insert report into MongoDB: %v", err)
		} else {
			log.Printf("Successfully saved final report for task %s to MongoDB", report.TaskID)
		}
	}
}
