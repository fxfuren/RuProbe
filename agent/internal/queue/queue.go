// Package queue реализует эфемерную очередь заданий агента.
//
// Состояние намеренно живёт только в памяти (вариант B из плана): история
// хранится в SQLite на стороне Python. При рестарте агента in-flight задания
// теряются, и это допустимо — Python обязан пометить такие проверки упавшими.
package queue

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ruprobe/agent/internal/probe"
)

// Status — состояние задания.
type Status string

const (
	StatusQueued  Status = "queued"
	StatusRunning Status = "running"
	StatusDone    Status = "done"
	StatusFailed  Status = "failed"
)

// Volume — запрос батча от бота.
type Volume struct {
	Targets         []string     `json:"targets"`
	Probes          []probe.Kind `json:"probes"`
	TimeoutMS       int          `json:"timeout_ms"`
	Port            int          `json:"port"`
	ThroughputBytes int64        `json:"throughput_bytes"`
	NeighborLimit   int          `json:"neighbor_limit"`
	NeighborScope   string       `json:"neighbor_scope"`
	// ExpandLimit ограничивает разворачивание диапазонов: /29 разворачивается
	// целиком, /16 — только до лимита.
	ExpandLimit int `json:"expand_limit"`
}

// Progress — сколько целей уже обработано.
type Progress struct {
	Completed int `json:"completed"`
	Total     int `json:"total"`
}

// JobState — наблюдаемое состояние задания.
type JobState struct {
	JobID     string         `json:"job_id"`
	Status    Status         `json:"status"`
	Progress  Progress       `json:"progress"`
	Results   []probe.Result `json:"results"`
	Err       string         `json:"error,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// TTL — момент, после которого завершённое задание можно выбросить.
	tTL time.Time
}

// ErrNotFound — задание неизвестно (в т.ч. потеряно при рестарте агента).
var ErrNotFound = errors.New("job not found")

// Queue — пул воркеров с состоянием под RWMutex.
type Queue struct {
	mu     sync.RWMutex
	jobs   map[string]*JobState
	ch     chan *job
	ttl    time.Duration
	closed bool

	workers int
	counter uint64
}

type job struct {
	id     string
	volume Volume
}

// New создаёт очередь с заданным числом воркеров и TTL завершённых заданий.
func New(workers int, ttl time.Duration) *Queue {
	if workers < 1 {
		workers = 4
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	q := &Queue{
		jobs:    make(map[string]*JobState),
		ch:      make(chan *job, 256),
		ttl:     ttl,
		workers: workers,
	}
	return q
}

// Run поднимает воркеров и TTL-сборщик. Возвращается, когда ctx отменён.
func (q *Queue) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < q.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.worker(ctx)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		q.sweeper(ctx)
	}()
	<-ctx.Done()
	wg.Wait()
}

// Submit ставит батч в очередь и возвращает идентификатор задания.
func (q *Queue) Submit(volume Volume) (string, error) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return "", errors.New("queue closed")
	}
	q.counter++
	id := formatJobID(q.counter)
	total := len(expandTargets(volume))
	state := &JobState{
		JobID:     id,
		Status:    StatusQueued,
		Progress:  Progress{Total: total},
		Results:   []probe.Result{},
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	q.jobs[id] = state
	q.mu.Unlock()

	select {
	case q.ch <- &job{id: id, volume: volume}:
		return id, nil
	default:
		q.mu.Lock()
		state.Status = StatusFailed
		state.Err = "queue full"
		state.UpdatedAt = time.Now().UTC()
		q.mu.Unlock()
		return "", errors.New("queue full")
	}
}

// Get возвращает снимок состояния задания.
func (q *Queue) Get(id string) (JobState, error) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	state, ok := q.jobs[id]
	if !ok {
		return JobState{}, ErrNotFound
	}
	return snapshot(state), nil
}

// Close останавливает приём заданий. Уже выданные идентификаторы остаются
// доступными до истечения TTL, чтобы бот успел забрать результат.
func (q *Queue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return
	}
	q.closed = true
	close(q.ch)
}

func (q *Queue) worker(ctx context.Context) {
	for j := range q.ch {
		q.setRunning(j.id)
		results := q.execute(ctx, j.volume, func(done int) {
			q.setProgress(j.id, done)
		})
		q.finish(j.id, results)
	}
}

// execute прогоняет все цели батча. Цели обрабатываются последовательно внутри
// задания, параллелизм даётся пулом воркеров: так один большой диапазон не
// вытесняет остальные задания.
func (q *Queue) execute(ctx context.Context, volume Volume, onDone func(int)) []probe.Result {
	targets := expandTargets(volume)
	timeout := time.Duration(volume.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	kinds := volume.Probes
	for i, k := range kinds {
		if !k.Valid() {
			// Неизвестный зонд игнорируем: лучше меньше данных, чем отказ батча.
			kinds = append(kinds[:i], kinds[i+1:]...)
		}
	}

	results := make([]probe.Result, 0, len(targets))
	for i, raw := range targets {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		target, err := probe.ParseTarget(raw)
		if err != nil {
			results = append(results, probe.Result{
				Target: raw,
				Kind:   string(probe.TargetUnknown),
				Errors: []string{err.Error()},
			})
			onDone(i + 1)
			continue
		}
		results = append(results, probe.Run(ctx, probe.Options{
			Target:          target,
			Kinds:           kinds,
			Port:            volume.Port,
			Timeout:         timeout,
			ThroughputBytes: volume.ThroughputBytes,
			NeighborLimit:   volume.NeighborLimit,
			NeighborScope:   volume.NeighborScope,
		}))
		onDone(i + 1)
	}
	return results
}

// expandTargets разворачивает CIDR/диапазоны в отдельные цели.
func expandTargets(volume Volume) []string {
	limit := volume.ExpandLimit
	if limit <= 0 {
		limit = 32
	}
	var out []string
	for _, raw := range volume.Targets {
		t, err := probe.ParseTarget(raw)
		if err != nil {
			// Оставляем как есть: ошибка разбора станет результатом с пояснением.
			out = append(out, raw)
			continue
		}
		switch t.Kind {
		case probe.TargetCIDR:
			out = append(out, t.Expand(limit)...)
		default:
			out = append(out, raw)
		}
	}
	return out
}

func (q *Queue) setRunning(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, ok := q.jobs[id]; ok {
		s.Status = StatusRunning
		s.UpdatedAt = time.Now().UTC()
	}
}

func (q *Queue) setProgress(id string, completed int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if s, ok := q.jobs[id]; ok {
		s.Progress.Completed = completed
		s.UpdatedAt = time.Now().UTC()
	}
}

func (q *Queue) finish(id string, results []probe.Result) {
	q.mu.Lock()
	defer q.mu.Unlock()
	s, ok := q.jobs[id]
	if !ok {
		return
	}
	s.Status = StatusDone
	s.Results = results
	s.Progress.Completed = s.Progress.Total
	s.UpdatedAt = time.Now().UTC()
	s.tTL = s.UpdatedAt.Add(q.ttl)
}

// sweeper выбрасывает завершённые задания после TTL. Незавершённые не трогает:
// их потеря видна боту как timeout опроса, и это честнее молчаливого удаления.
func (q *Queue) sweeper(ctx context.Context) {
	ticker := time.NewTicker(minDuration(q.ttl/4, 30*time.Second))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			q.sweep(now.UTC())
		}
	}
}

func (q *Queue) sweep(now time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for id, s := range q.jobs {
		if s.tTL.IsZero() {
			continue
		}
		if now.After(s.tTL) {
			delete(q.jobs, id)
		}
	}
}

func snapshot(s *JobState) JobState {
	out := *s
	out.Results = append([]probe.Result{}, s.Results...)
	return out
}

func formatJobID(n uint64) string {
	const digits = "0123456789abcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%36]
		n /= 36
	}
	return string(buf[i:])
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
