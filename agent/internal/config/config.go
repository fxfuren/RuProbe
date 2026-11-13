// Package config читает настройки агента из окружения.
package config

import (
	"os"
	"strconv"
	"time"
)

// Config — настройки агента. Значения по умолчанию рассчитаны на запуск
// в docker-сети, где наружу ничего не публикуется.
type Config struct {
	Addr             string
	Workers          int
	JobTTL           time.Duration
	DefaultTimeout   time.Duration
	DefaultBytes     int64
	DefaultNeighbors int
	NeighborScope    string
}

// Load собирает конфигурацию из переменных окружения.
func Load() Config {
	return Config{
		Addr:             env("AGENT_ADDR", ":8080"),
		Workers:          envInt("AGENT_WORKERS", 8),
		JobTTL:           envDuration("AGENT_JOB_TTL", 10*time.Minute),
		DefaultTimeout:   envDuration("AGENT_DEFAULT_TIMEOUT", 5*time.Second),
		DefaultBytes:     envInt64("AGENT_THROUGHPUT_BYTES", 1<<20),
		DefaultNeighbors: envInt("AGENT_NEIGHBOR_LIMIT", 16),
		NeighborScope:    env("AGENT_NEIGHBOR_SCOPE", "/24"),
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if secs, err := strconv.Atoi(v); err == nil {
			return time.Duration(secs) * time.Second
		}
	}
	return fallback
}
