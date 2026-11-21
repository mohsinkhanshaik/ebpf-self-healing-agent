// Package actions implements remediations, health verification and
// escalation for the engine.
package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/config"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

// Runner executes actions on this node. It implements engine.Actuator,
// engine.Verifier and engine.Escalator.
type Runner struct {
	NodeName string
	HTTP     *http.Client

	// run executes a command; replaced in tests.
	run func(ctx context.Context, name string, args ...string) error
}

// NewRunner returns a Runner that shells out to real binaries.
func NewRunner(node string) *Runner {
	return &Runner{
		NodeName: node,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
		run:      runCommand,
	}
}

func runCommand(ctx context.Context, name string, args ...string) error {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 512 {
			msg = msg[:512] + "..."
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return nil
}

// Execute runs the rule's action for ev.
func (r *Runner) Execute(ctx context.Context, rule config.Rule, ev signals.Event) error {
	a := rule.Action
	switch a.Type {
	case config.ActionRestartSystemd:
		return r.run(ctx, "systemctl", "restart", r.expand(a.Unit, rule, ev))
	case config.ActionKillProcess:
		if ev.PID == 0 {
			return errors.New("event has no PID")
		}
		if err := syscall.Kill(int(ev.PID), syscall.Signal(a.Signal)); err != nil && !errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("kill %d: %w", ev.PID, err)
		}
		return nil
	case config.ActionExec:
		args := make([]string, len(a.Command))
		for i, s := range a.Command {
			args[i] = r.expand(s, rule, ev)
		}
		return r.run(ctx, args[0], args[1:]...)
	case config.ActionCordonNode:
		return r.run(ctx, "kubectl", "cordon", r.NodeName)
	case config.ActionWebhook:
		return r.post(ctx, r.expand(a.URL, rule, ev), r.payload(rule, ev, "remediation", ""))
	}
	return fmt.Errorf("unknown action %q", a.Type)
}

// expand replaces ${PID}, ${COMM}, ${DEST}, ${SIGNAL}, ${NODE} and ${RULE}.
func (r *Runner) expand(s string, rule config.Rule, ev signals.Event) string {
	return strings.NewReplacer(
		"${PID}", strconv.FormatUint(uint64(ev.PID), 10),
		"${COMM}", ev.Comm,
		"${DEST}", ev.Dest,
		"${SIGNAL}", strconv.Itoa(ev.Signal),
		"${NODE}", r.NodeName,
		"${RULE}", rule.Name,
	).Replace(s)
}

// Verify polls an HTTP endpoint until it returns 2xx or retries run out.
func (r *Runner) Verify(ctx context.Context, v config.Verify) error {
	if err := sleep(ctx, v.InitialDelay); err != nil {
		return err
	}
	var last error
	for i := 0; i < v.Retries; i++ {
		if i > 0 {
			if err := sleep(ctx, v.Interval); err != nil {
				return err
			}
		}
		last = r.probe(ctx, v)
		if last == nil {
			return nil
		}
	}
	return fmt.Errorf("unhealthy after %d checks: %w", v.Retries, last)
}

func (r *Runner) probe(ctx context.Context, v config.Verify) error {
	ctx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.HTTPGet, nil)
	if err != nil {
		return err
	}
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("GET %s: %s", v.HTTPGet, resp.Status)
	}
	return nil
}

// Escalate posts to the rule's escalation webhook. The payload includes a
// "text" field so Slack and similar incoming webhooks render it directly.
func (r *Runner) Escalate(ctx context.Context, rule config.Rule, reason string, ev signals.Event) error {
	if rule.Escalate == nil {
		return nil
	}
	return r.post(ctx, rule.Escalate.Webhook, r.payload(rule, ev, "escalation", reason))
}

type payload struct {
	Type   string        `json:"type"`
	Text   string        `json:"text"`
	Rule   string        `json:"rule"`
	Node   string        `json:"node"`
	Reason string        `json:"reason,omitempty"`
	Event  signals.Event `json:"event"`
	Time   time.Time     `json:"time"`
}

func (r *Runner) payload(rule config.Rule, ev signals.Event, typ, reason string) payload {
	text := fmt.Sprintf("[healerd] %s on %s: rule %q (%s)", typ, r.NodeName, rule.Name, ev.Kind)
	if reason != "" {
		text += ": " + reason
	}
	return payload{Type: typ, Text: text, Rule: rule.Name, Node: r.NodeName, Reason: reason, Event: ev, Time: time.Now().UTC()}
}

func (r *Runner) post(ctx context.Context, url string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.HTTP.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode > 299 {
		return fmt.Errorf("POST %s: %s", url, resp.Status)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
