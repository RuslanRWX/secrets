// Package config loads runtime settings from the environment.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds everything the server needs to start.
type Config struct {
	Port          string
	DatabaseURL   string
	MasterKey     string
	JWTSecret     string
	SessionTTL    time.Duration
	CORSOrigins   []string
	TrustedProxy  bool
	LogLevel      string
	MigrateOnBoot bool
}

// Load reads configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		Port:          env("PORT", "8080"),
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		MasterKey:     os.Getenv("MASTER_KEY"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		LogLevel:      env("LOG_LEVEL", "info"),
		TrustedProxy:  envBool("TRUST_PROXY_HEADERS", false),
		MigrateOnBoot: envBool("AUTO_MIGRATE", true),
	}

	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = databaseURLFromParts()
	}

	ttl, err := time.ParseDuration(env("SESSION_TTL", "12h"))
	if err != nil {
		return nil, fmt.Errorf("SESSION_TTL: %w", err)
	}
	cfg.SessionTTL = ttl

	if origins := os.Getenv("CORS_ORIGINS"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				cfg.CORSOrigins = append(cfg.CORSOrigins, o)
			}
		}
	}

	var problems []string
	if cfg.DatabaseURL == "" {
		problems = append(problems, "DATABASE_URL is required")
	}
	if len(cfg.MasterKey) < 16 {
		problems = append(problems, "MASTER_KEY is required and must be at least 16 characters")
	}
	if len(cfg.JWTSecret) < 16 {
		problems = append(problems, "JWT_SECRET is required and must be at least 16 characters")
	}
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "; "))
	}

	return cfg, nil
}

// databaseURLFromParts assembles a connection string from discrete PG* variables,
// which is how Helm wires up an in-cluster PostgreSQL.
func databaseURLFromParts() string {
	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		return ""
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
		env("POSTGRES_USER", "secrets"),
		os.Getenv("POSTGRES_PASSWORD"),
		host,
		env("POSTGRES_PORT", "5432"),
		env("POSTGRES_DB", "secrets"),
		env("POSTGRES_SSLMODE", "disable"),
	)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func envBool(key string, fallback bool) bool {
	v, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return fallback
	}

	return v
}
