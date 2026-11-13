package queue

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ruprobe/agent/internal/probe"
)

// TestSweepRemovesFinishedJobs — TTL-очистка завершённых заданий.
func TestSweepRemovesFinishedJobs(t *testing.T) {
	q := New(1, time.Minute)
	id, err := q.Submit(Volume{Targets: []string{"192.0.2.1"}, Probes: []probe.Kind{probe.KindTCP}, TimeoutMS: 100})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	// Завершаем задание вручную: сеть в тесте не нужна.
	q.finish(id, []probe.Result{{Target: "192.0.2.1"}})

	state, err := q.Get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if state.Status != StatusDone {
		t.Fatalf("status = %s, want done", state.Status)
	}

	// До истечения TTL задание остаётся доступным.
	q.sweep(time.Now().UTC())
	if _, err := q.Get(id); err != nil {
		t.Fatalf("job removed before TTL: %v", err)
	}

	// После истечения — удаляется.
	q.sweep(time.Now().UTC().Add(2 * time.Minute))
	if _, err := q.Get(id); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after TTL, got %v", err)
	}
}

// TestSweepKeepsUnfinishedJobs: незавершённые задания сборщик не трогает, иначе
// бот получил бы 404 и не смог отличить «ещё идёт» от «потеряно при рестарте».
func TestSweepKeepsUnfinishedJobs(t *testing.T) {
	q := New(1, time.Millisecond)
	id, err := q.Submit(Volume{Targets: []string{"192.0.2.1"}})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	q.sweep(time.Now().UTC().Add(time.Hour))
	if _, err := q.Get(id); err != nil {
		t.Fatalf("unfinished job was swept: %v", err)
	}
}

func TestQueueRunsJobAndReportsDone(t *testing.T) {
	q := New(2, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)

	id, err := q.Submit(Volume{
		Targets:   []string{"192.0.2.0/30"},
		Probes:    []probe.Kind{probe.KindTCP},
		TimeoutMS: 150,
	})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		state, err := q.Get(id)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if state.Status == StatusDone {
			if state.Progress.Completed != state.Progress.Total {
				t.Errorf("completed %d != total %d", state.Progress.Completed, state.Progress.Total)
			}
			if len(state.Results) != 4 {
				t.Errorf("expected 4 results for /30, got %d", len(state.Results))
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish in time")
}

func TestSubmitRejectsEmptyQueueAfterClose(t *testing.T) {
	q := New(1, time.Minute)
	q.Close()
	if _, err := q.Submit(Volume{Targets: []string{"192.0.2.1"}}); err == nil {
		t.Fatal("expected error after close")
	}
}

func TestGetUnknownJob(t *testing.T) {
	q := New(1, time.Minute)
	if _, err := q.Get("missing"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestConcurrentAccess — состояние читается под блокировкой, гонок быть не должно.
func TestConcurrentAccessNoRace(t *testing.T) {
	q := New(4, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go q.Run(ctx)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		id, err := q.Submit(Volume{Targets: []string{"192.0.2.1"}, TimeoutMS: 50})
		if err != nil {
			t.Fatalf("submit: %v", err)
		}
		for j := 0; j < 3; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, _ = q.Get(id)
			}()
		}
	}
	wg.Wait()
}

func TestExpandTargetsBounded(t *testing.T) {
	targets := expandTargets(Volume{Targets: []string{"192.0.2.0/24"}, ExpandLimit: 3})
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d: %v", len(targets), targets)
	}
}
