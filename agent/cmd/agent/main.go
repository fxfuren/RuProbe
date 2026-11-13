// Команда agent — Go-зонд RuProbe.
//
// Вариант B из плана: агент не хранит постоянного состояния и не знает ничего
// о пользователях, регионах и истории. Он умеет ровно одно — выполнить зонды
// для набора целей и вернуть структурированные факты.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ruprobe/agent/internal/config"
	"github.com/ruprobe/agent/internal/httpapi"
	"github.com/ruprobe/agent/internal/queue"
)

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg := config.Load()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	q := queue.New(cfg.Workers, cfg.JobTTL)
	go q.Run(ctx)

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           httpapi.NewServer(q, cfg).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// WriteTimeout не ставим: ответ по завершённому заданию может быть
		// большим (диапазон /29), а пробы и так ограничены собственным дедлайном.
		IdleTimeout: 120 * time.Second,
	}

	go func() {
		log.Printf("agent: listening on %s, workers=%d, job ttl=%s", cfg.Addr, cfg.Workers, cfg.JobTTL)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("agent: listen failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Print("agent: shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("agent: shutdown error: %v", err)
	}
	q.Close()
	log.Print("agent: stopped")
}
