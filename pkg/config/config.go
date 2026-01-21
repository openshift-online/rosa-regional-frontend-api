package config

import "time"

type Config struct {
	Server   ServerConfig
	Maestro  MaestroConfig
	DynamoDB DynamoDBConfig
	Logging  LoggingConfig
}

type ServerConfig struct {
	APIBindAddress     string
	APIPort            int
	HealthBindAddress  string
	HealthPort         int
	MetricsBindAddress string
	MetricsPort        int
	ShutdownTimeout    time.Duration
}

type MaestroConfig struct {
	BaseURL string
	Timeout time.Duration
}

type DynamoDBConfig struct {
	TableName string
	Region    string
	Endpoint  string // Optional, for local development
}

type LoggingConfig struct {
	Level  string
	Format string
}

func NewConfig() *Config {
	return &Config{
		Server: ServerConfig{
			APIBindAddress:     "0.0.0.0",
			APIPort:            8000,
			HealthBindAddress:  "0.0.0.0",
			HealthPort:         8080,
			MetricsBindAddress: "0.0.0.0",
			MetricsPort:        9090,
			ShutdownTimeout:    30 * time.Second,
		},
		Maestro: MaestroConfig{
			BaseURL: "http://maestro:8000",
			Timeout: 30 * time.Second,
		},
		DynamoDB: DynamoDBConfig{
			TableName: "rosa-customer-accounts",
			Region:    "us-east-1",
			Endpoint:  "",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}
}
