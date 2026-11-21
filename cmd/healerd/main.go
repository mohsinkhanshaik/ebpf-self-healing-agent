// Command healerd watches kernel signals with eBPF and runs guarded
// remediations.
//
//	sudo healerd -config /etc/healerd/healerd.yaml
//	healerd -config examples/healerd.yaml -replay examples/incident.jsonl -dry-run
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/actions"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/config"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/engine"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/metrics"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/probe"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

var version = "dev"

func main() {
	os.Exit(run())
}

func run() int {
	cfgPath := flag.String("config", "/etc/healerd/healerd.yaml", "path to the policy file")
	dryRun := flag.Bool("dry-run", false, "log decisions without acting (overrides the config)")
	replay := flag.String("replay", "", "feed events from a JSON-lines file instead of the kernel")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return 0
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Error("invalid config", "path", *cfgPath, "err", err)
		return 2
	}
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "dry-run" {
			cfg.DryRun = *dryRun
		}
	})

	reg := metrics.New()
	runner := actions.NewRunner(cfg.NodeName)
	eng := engine.New(cfg.Rules, engine.Options{
		Actuator:  runner,
		Verifier:  runner,
		Escalator: runner,
		DryRun:    cfg.DryRun,
		Logger:    log,
		Metrics:   reg,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *replay != "" {
		err := replayFile(ctx, *replay, eng)
		eng.Wait()
		printStatus(eng)
		if err != nil {
			log.Error("replay failed", "err", err)
			return 1
		}
		return 0
	}

	p, err := probe.Load(cfg.WatchedComms(), log)
	if err != nil {
		log.Error("cannot start eBPF probes", "err", err)
		return 1
	}
	defer p.Close()

	srv := &http.Server{Addr: cfg.MetricsAddr, Handler: newMux(reg, eng), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
		}
	}()

	log.Info("healerd started", "version", version, "node", cfg.NodeName, "rules", len(cfg.Rules),
		"hooks", p.Attached(), "dry_run", cfg.DryRun, "metrics", cfg.MetricsAddr)

	events := make(chan signals.Event, 4096)
	probeErr := make(chan error, 1)
	go func() { probeErr <- p.Run(ctx, events, cfg.RetransmitPoll) }()

	code := 0
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-probeErr:
			if err != nil {
				log.Error("probe stopped", "err", err)
				code = 1
			}
			break loop
		case ev := <-events:
			eng.Handle(ctx, ev)
		}
	}

	log.Info("shutting down; waiting for in-flight remediations")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	eng.Wait()
	return code
}

func newMux(reg *metrics.Registry, eng *engine.Engine) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(eng.Status())
	})
	// Close a rule's circuit breaker once a human has fixed the root cause.
	mux.HandleFunc("POST /rules/{name}/reset", func(w http.ResponseWriter, r *http.Request) {
		if !eng.Reset(r.PathValue("name")) {
			http.Error(w, "unknown rule", http.StatusNotFound)
			return
		}
		fmt.Fprintln(w, "reset")
	})
	return mux
}

func replayFile(ctx context.Context, path string, eng *engine.Engine) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		b := sc.Bytes()
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		var ev signals.Event
		if err := json.Unmarshal(b, &ev); err != nil {
			return fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if !ev.Kind.Valid() {
			return fmt.Errorf("%s:%d: unknown kind %q", path, line, ev.Kind)
		}
		if ev.Time.IsZero() {
			ev.Time = time.Now()
		}
		eng.Handle(ctx, ev)
		eng.Wait() // keep replay output in order
	}
	return sc.Err()
}

func printStatus(eng *engine.Engine) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(eng.Status())
}
