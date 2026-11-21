package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExposition(t *testing.T) {
	r := New()
	r.Describe("healer_events_total", "Signals observed.")
	r.Inc("healer_events_total", "signal", "oom_kill")
	r.Inc("healer_events_total", "signal", "oom_kill")
	r.Add("healer_events_total", 5, "signal", "tcp_retransmit")
	r.Inc("healer_remediations_total", "result", "success", "rule", `say "hi"`)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	got := rec.Body.String()

	want := `# HELP healer_events_total Signals observed.
# TYPE healer_events_total counter
healer_events_total{signal="oom_kill"} 2
healer_events_total{signal="tcp_retransmit"} 5
# TYPE healer_remediations_total counter
healer_remediations_total{result="success",rule="say \"hi\""} 1
`
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestNilRegistryIsSafe(t *testing.T) {
	var r *Registry
	r.Inc("x")
	r.Describe("x", "y")
}

func TestLabelOrderDoesNotMatter(t *testing.T) {
	r := New()
	r.Inc("m", "a", "1", "b", "2")
	r.Inc("m", "b", "2", "a", "1")
	if v := r.Value("m", "a", "1", "b", "2"); v != 1+1 {
		t.Fatalf("value = %v", v)
	}
	if !strings.Contains(func() string {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, nil)
		return rec.Body.String()
	}(), `m{a="1",b="2"} 2`) {
		t.Fatal("labels not normalized")
	}
}
