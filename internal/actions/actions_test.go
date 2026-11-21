package actions

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/config"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

func recordingRunner() (*Runner, *[]string) {
	var got []string
	r := NewRunner("node-7")
	r.run = func(_ context.Context, name string, args ...string) error {
		got = append(got, name+" "+strings.Join(args, " "))
		return nil
	}
	return r, &got
}

func TestCommandActions(t *testing.T) {
	r, got := recordingRunner()
	ev := signals.Event{Kind: signals.OOMKill, PID: 1234, Comm: "api"}
	ctx := context.Background()

	_ = r.Execute(ctx, config.Rule{Name: "a", Action: config.Action{Type: config.ActionRestartSystemd, Unit: "api.service"}}, ev)
	_ = r.Execute(ctx, config.Rule{Name: "b", Action: config.Action{Type: config.ActionExec,
		Command: []string{"/usr/local/bin/dump", "--pid=${PID}", "--comm=${COMM}", "--rule=${RULE}", "--node=${NODE}"}}}, ev)
	_ = r.Execute(ctx, config.Rule{Name: "c", Action: config.Action{Type: config.ActionCordonNode}}, ev)

	want := []string{
		"systemctl restart api.service",
		"/usr/local/bin/dump --pid=1234 --comm=api --rule=b --node=node-7",
		"kubectl cordon node-7",
	}
	if strings.Join(*got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(*got, "\n"), strings.Join(want, "\n"))
	}
}

func TestVerifyRetriesUntilHealthy(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := NewRunner("n")
	err := r.Verify(context.Background(), config.Verify{HTTPGet: srv.URL, Timeout: time.Second, Retries: 5, Interval: time.Millisecond})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, want 3", calls.Load())
	}
}

func TestVerifyGivesUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := NewRunner("n")
	err := r.Verify(context.Background(), config.Verify{HTTPGet: srv.URL, Timeout: time.Second, Retries: 2, Interval: time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "unhealthy after 2 checks") {
		t.Fatalf("err = %v", err)
	}
}

func TestEscalationPayload(t *testing.T) {
	var body payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewDecoder(req.Body).Decode(&body)
	}))
	defer srv.Close()

	r := NewRunner("node-7")
	rule := config.Rule{Name: "api-oom", Escalate: &config.Escalate{Webhook: srv.URL}}
	ev := signals.Event{Kind: signals.OOMKill, PID: 9, Comm: "api"}
	if err := r.Escalate(context.Background(), rule, "3 consecutive remediations failed", ev); err != nil {
		t.Fatal(err)
	}
	if body.Type != "escalation" || body.Node != "node-7" || body.Event.PID != 9 ||
		!strings.Contains(body.Text, "3 consecutive remediations failed") {
		t.Fatalf("payload = %+v", body)
	}
}
