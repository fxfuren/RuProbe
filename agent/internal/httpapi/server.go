// Package httpapi предоставляет внутренний HTTP-контракт между ботом и агентом:
// POST /probe/batch, GET /jobs/{id}, GET /health. Наружу не публикуется.
package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ruprobe/agent/internal/config"
	"github.com/ruprobe/agent/internal/probe"
	"github.com/ruprobe/agent/internal/queue"
)

// Server — HTTP-обёртка над очередью.
type Server struct {
	queue *queue.Queue
	cfg   config.Config
}

// NewServer создаёт сервер.
func NewServer(q *queue.Queue, cfg config.Config) *Server {
	return &Server{queue: q, cfg: cfg}
}

// Handler возвращает маршрутизатор. Используется стандартный ServeMux с
// методами и wildcard-сегментами: этого достаточно для трёх маршрутов.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /probe/batch", s.handleBatch)
	mux.HandleFunc("GET /jobs/{id}", s.handleJob)
	mux.HandleFunc("GET /health", s.handleHealth)
	return mux
}

type batchRequest struct {
	Targets         []string `json:"targets"`
	Probes          []string `json:"probes"`
	TimeoutMS       int      `json:"timeout_ms"`
	Port            int      `json:"port"`
	ThroughputBytes int64    `json:"throughput_bytes"`
	NeighborLimit   int      `json:"neighbor_limit"`
	NeighborScope   string   `json:"neighbor_scope"`
	ExpandLimit     int      `json:"expand_limit"`
}

type batchResponse struct {
	JobID string `json:"job_id"`
	Total int    `json:"total"`
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	var req batchRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if len(req.Targets) == 0 {
		writeError(w, http.StatusBadRequest, "targets must not be empty")
		return
	}

	kinds := make([]probe.Kind, 0, len(req.Probes))
	for _, p := range req.Probes {
		k := probe.Kind(strings.TrimSpace(p))
		if !k.Valid() {
			writeError(w, http.StatusBadRequest, "unknown probe: "+string(k))
			return
		}
		kinds = append(kinds, k)
	}
	if len(kinds) == 0 {
		// Пустой список означает «все зонды» и это явно задокументировано
		// в контракте, поэтому не ошибка.
		kinds = probe.AllKinds()
	}

	timeoutMS := req.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = int(s.cfg.DefaultTimeout / time.Millisecond)
	}
	bytes := req.ThroughputBytes
	if bytes <= 0 {
		bytes = s.cfg.DefaultBytes
	}
	neighbors := req.NeighborLimit
	if neighbors <= 0 {
		neighbors = s.cfg.DefaultNeighbors
	}
	scope := req.NeighborScope
	if scope == "" {
		scope = s.cfg.NeighborScope
	}

	id, err := s.queue.Submit(queue.Volume{
		Targets:         req.Targets,
		Probes:          kinds,
		TimeoutMS:       timeoutMS,
		Port:            req.Port,
		ThroughputBytes: bytes,
		NeighborLimit:   neighbors,
		NeighborScope:   scope,
		ExpandLimit:     req.ExpandLimit,
	})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	state, _ := s.queue.Get(id)
	writeJSON(w, http.StatusAccepted, batchResponse{JobID: id, Total: state.Progress.Total})
}

func (s *Server) handleJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "job id required")
		return
	}
	state, err := s.queue.Get(id)
	if err != nil {
		if errors.Is(err, queue.ErrNotFound) {
			// Агент потерял задание: после рестарта состояние эфемерно.
			// Бот трактует 404 как «проверка провалена», а не как «ещё идёт».
			writeError(w, http.StatusNotFound, "job not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
		"probes": probe.AllKinds(),
	})
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]string{"error": message})
}
