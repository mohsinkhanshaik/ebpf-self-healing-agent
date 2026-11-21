package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseDefaults(t *testing.T) {
	c, err := Parse([]byte(`
node_name: node-a
rules:
  - name: api-oom
    signal: oom_kill
    match: {comm: api-server}
    action: {type: restart_systemd, unit: api.service}
    verify: {http_get: "http://127.0.0.1:8080/healthz"}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := c.Rules[0]
	if r.Threshold != 1 || r.Window != time.Minute || r.Cooldown != time.Minute || r.MaxPerHour != 6 || r.MaxFailures != 3 {
		t.Fatalf("defaults not applied: %+v", r)
	}
	if r.Verify.Timeout != 5*time.Second || r.Verify.Retries != 5 {
		t.Fatalf("verify defaults not applied: %+v", r.Verify)
	}
	if c.MetricsAddr != ":9464" || c.RetransmitPoll != time.Second {
		t.Fatalf("global defaults not applied: %+v", c)
	}
}

func TestValidateErrors(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - name: a
    signal: disk_full
    action: {type: restart_systemd}
  - name: a
    signal: process_exit
    action: {type: teleport}
  - name: c
    signal: tcp_retransmit
    match: {dest: "not-an-addr"}
    action: {type: kill_process}
`))
	if err == nil {
		t.Fatal("expected errors")
	}
	for _, want := range []string{
		`unknown signal "disk_full"`,
		"restart_systemd needs action.unit",
		"duplicate name",
		"process_exit rules need match.comm",
		`unknown action.type "teleport"`,
		"match.dest must be ip:port",
		"kill_process needs a PID",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing error %q in:\n%v", want, err)
		}
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte(`
rules:
  - name: a
    signal: oom_kill
    treshold: 3
    action: {type: cordon_node}
`))
	if err == nil || !strings.Contains(err.Error(), "treshold") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	b, err := os.ReadFile("../../examples/healerd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatalf("examples/healerd.yaml: %v", err)
	}
	if got := c.WatchedComms(); len(got) == 0 {
		t.Fatal("example should watch at least one process")
	}
}
