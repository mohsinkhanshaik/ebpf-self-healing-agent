package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/config"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/metrics"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type fakeActuator struct {
	mu    sync.Mutex
	calls []signals.Event
	err   error
}

func (f *fakeActuator) Execute(_ context.Context, _ config.Rule, ev signals.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, ev)
	return f.err
}

func (f *fakeActuator) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type fakeVerifier struct{ err error }

func (f fakeVerifier) Verify(context.Context, config.Verify) error { return f.err }

type fakeEscalator struct {
	mu      sync.Mutex
	reasons []string
}

func (f *fakeEscalator) Escalate(_ context.Context, _ config.Rule, reason string, _ signals.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reasons = append(f.reasons, reason)
	return nil
}

func (f *fakeEscalator) n() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reasons)
}

type harness struct {
	eng *Engine
	clk *clock
	act *fakeActuator
	esc *fakeEscalator
	m   *metrics.Registry
}

func newHarness(t *testing.T, r config.Rule, dryRun bool, verifyErr error) *harness {
	t.Helper()
	if r.Name == "" {
		r.Name = "test"
	}
	if r.Threshold == 0 {
		r.Threshold = 1
	}
	if r.Window == 0 {
		r.Window = time.Minute
	}
	if r.MaxPerHour == 0 {
		r.MaxPerHour = 100
	}
	if r.MaxFailures == 0 {
		r.MaxFailures = 3
	}
	if r.Action.Type == "" {
		r.Action.Type = config.ActionExec
	}
	r.Escalate = &config.Escalate{Webhook: "http://example.invalid"}

	h := &harness{
		clk: &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		act: &fakeActuator{},
		esc: &fakeEscalator{},
		m:   metrics.New(),
	}
	h.eng = New([]config.Rule{r}, Options{
		Actuator:  h.act,
		Verifier:  fakeVerifier{err: verifyErr},
		Escalator: h.esc,
		DryRun:    dryRun,
		Now:       h.clk.now,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:   h.m,
	})
	return h
}

func (h *harness) send(ev signals.Event) {
	h.eng.Handle(context.Background(), ev)
	h.eng.Wait()
}

var oom = signals.Event{Kind: signals.OOMKill, PID: 42, Comm: "api-server"}

func TestThresholdWithinWindow(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, Threshold: 3, Window: time.Minute}, false, nil)

	h.send(oom)
	h.clk.advance(10 * time.Second)
	h.send(oom)
	if h.act.n() != 0 {
		t.Fatal("fired before threshold")
	}
	h.clk.advance(10 * time.Second)
	h.send(oom)
	if h.act.n() != 1 {
		t.Fatalf("actions = %d, want 1", h.act.n())
	}
}

func TestWindowExpiry(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, Threshold: 2, Window: time.Minute}, false, nil)

	h.send(oom)
	h.clk.advance(61 * time.Second)
	h.send(oom)
	if h.act.n() != 0 {
		t.Fatal("events outside the window should not add up")
	}
}

func TestRetransmitCountsAreWeighted(t *testing.T) {
	h := newHarness(t, config.Rule{
		Signal: signals.TCPRetransmit, Threshold: 100, Window: 30 * time.Second,
		Match: config.Match{Dest: "10.0.0.5:5432"},
	}, false, nil)

	h.send(signals.Event{Kind: signals.TCPRetransmit, Dest: "10.0.0.9:5432", Count: 500})
	if h.act.n() != 0 {
		t.Fatal("other destinations must not match")
	}
	h.send(signals.Event{Kind: signals.TCPRetransmit, Dest: "10.0.0.5:5432", Count: 60})
	h.send(signals.Event{Kind: signals.TCPRetransmit, Dest: "10.0.0.5:5432", Count: 40})
	if h.act.n() != 1 {
		t.Fatalf("actions = %d, want 1", h.act.n())
	}
}

func TestCooldown(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, Cooldown: 5 * time.Minute}, false, nil)

	h.send(oom)
	h.clk.advance(time.Minute)
	h.send(oom)
	if h.act.n() != 1 {
		t.Fatalf("cooldown not enforced: %d actions", h.act.n())
	}
	if v := h.m.Value("healer_suppressed_total", "reason", "cooldown", "rule", "test"); v != 1 {
		t.Fatalf("suppressed metric = %v", v)
	}
	h.clk.advance(5 * time.Minute)
	h.send(oom)
	if h.act.n() != 2 {
		t.Fatalf("should act again after cooldown: %d actions", h.act.n())
	}
}

func TestBudgetOpensCircuitAndEscalates(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, MaxPerHour: 2, Cooldown: time.Second}, false, nil)

	for i := 0; i < 5; i++ {
		h.send(oom)
		h.clk.advance(2 * time.Second)
	}
	if h.act.n() != 2 {
		t.Fatalf("actions = %d, want 2 (budget)", h.act.n())
	}
	if h.esc.n() != 1 {
		t.Fatalf("escalations = %d, want exactly 1", h.esc.n())
	}
	if !h.eng.Status()[0].CircuitOpen {
		t.Fatal("circuit should be open")
	}
}

func TestConsecutiveFailuresOpenCircuit(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, MaxFailures: 2, Cooldown: time.Second}, false, nil)
	h.act.err = errors.New("unit not found")

	h.send(oom)
	h.clk.advance(2 * time.Second)
	h.send(oom)
	h.clk.advance(2 * time.Second)
	h.send(oom) // circuit open: must not act

	if h.act.n() != 2 {
		t.Fatalf("actions = %d, want 2", h.act.n())
	}
	if h.esc.n() != 1 {
		t.Fatalf("escalations = %d, want 1", h.esc.n())
	}
	if got := h.m.Value("healer_remediations_total", "action", "exec", "result", "failure", "rule", "test"); got != 2 {
		t.Fatalf("failure metric = %v", got)
	}

	if !h.eng.Reset("test") {
		t.Fatal("reset failed")
	}
	h.act.err = nil
	h.send(oom)
	if h.act.n() != 3 {
		t.Fatal("should act again after reset")
	}
}

func TestFailedVerifyCountsAsFailure(t *testing.T) {
	h := newHarness(t, config.Rule{
		Signal: signals.OOMKill, MaxFailures: 1,
		Verify: &config.Verify{HTTPGet: "http://127.0.0.1/healthz"},
	}, false, errors.New("503"))

	h.send(oom)
	st := h.eng.Status()[0]
	if !st.CircuitOpen || st.CircuitReason != "consecutive_failures" {
		t.Fatalf("status = %+v", st)
	}
}

func TestSuccessResetsFailureCount(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill, MaxFailures: 2, Cooldown: time.Second}, false, nil)

	h.act.err = errors.New("flaky")
	h.send(oom)
	h.clk.advance(2 * time.Second)
	h.act.err = nil
	h.send(oom)
	h.clk.advance(2 * time.Second)
	h.act.err = errors.New("flaky")
	h.send(oom)

	if h.eng.Status()[0].CircuitOpen {
		t.Fatal("non-consecutive failures must not open the circuit")
	}
}

func TestDryRunNeverActs(t *testing.T) {
	h := newHarness(t, config.Rule{Signal: signals.OOMKill}, true, nil)
	h.send(oom)
	if h.act.n() != 0 {
		t.Fatal("dry run executed an action")
	}
	if v := h.m.Value("healer_remediations_total", "action", "exec", "result", "dry_run", "rule", "test"); v != 1 {
		t.Fatalf("dry_run metric = %v", v)
	}
}

func TestMatching(t *testing.T) {
	r := config.Rule{
		Signal: signals.ProcessExit,
		Match:  config.Match{Comm: "worker", OnlyFailures: true},
	}
	cases := []struct {
		ev   signals.Event
		want bool
	}{
		{signals.Event{Kind: signals.ProcessExit, Comm: "worker", ExitStatus: 1}, true},
		{signals.Event{Kind: signals.ProcessExit, Comm: "worker", Signal: 11}, true},
		{signals.Event{Kind: signals.ProcessExit, Comm: "worker"}, false},               // clean exit
		{signals.Event{Kind: signals.ProcessExit, Comm: "other", ExitStatus: 1}, false}, // wrong process
		{signals.Event{Kind: signals.OOMKill, Comm: "worker"}, false},                   // wrong kind
	}
	for i, c := range cases {
		if got := matches(r, c.ev); got != c.want {
			t.Errorf("case %d: matches = %v, want %v", i, got, c.want)
		}
	}

	crash := config.Rule{Signal: signals.CrashSignal, Match: config.Match{Signals: []int{11, 6}}}
	if !matches(crash, signals.Event{Kind: signals.CrashSignal, Signal: 11}) {
		t.Error("SIGSEGV should match")
	}
	if matches(crash, signals.Event{Kind: signals.CrashSignal, Signal: 9}) {
		t.Error("SIGKILL should not match")
	}
}
