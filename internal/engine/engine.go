// Package engine decides when to remediate and enforces the safety rails that
// keep a self-healing loop from making an incident worse:
//
//   - thresholds over a sliding window (one blip is not an incident)
//   - a cooldown after every action
//   - an hourly action budget per rule
//   - a circuit breaker that stops acting and pages a human after repeated
//     failed remediations or an exhausted budget
//   - one in-flight remediation per rule
//   - global dry-run mode
package engine

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/config"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/metrics"
	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

// Actuator performs a remediation.
type Actuator interface {
	Execute(ctx context.Context, rule config.Rule, ev signals.Event) error
}

// Verifier checks that a remediation fixed the problem.
type Verifier interface {
	Verify(ctx context.Context, v config.Verify) error
}

// Escalator pages a human.
type Escalator interface {
	Escalate(ctx context.Context, rule config.Rule, reason string, ev signals.Event) error
}

// Options wires the engine's dependencies.
type Options struct {
	Actuator      Actuator
	Verifier      Verifier
	Escalator     Escalator
	DryRun        bool
	ActionTimeout time.Duration
	Now           func() time.Time
	Logger        *slog.Logger
	Metrics       *metrics.Registry
}

// Engine evaluates events against rules.
type Engine struct {
	opts  Options
	mu    sync.Mutex
	rules []*ruleState
	wg    sync.WaitGroup
}

type sample struct {
	at time.Time
	n  uint64
}

type ruleState struct {
	cfg        config.Rule
	window     []sample
	lastAction time.Time
	actions    []time.Time
	failures   int
	open       bool
	openReason string
	inFlight   bool
}

// RuleStatus is a point-in-time view of a rule, served on /status.
type RuleStatus struct {
	Name                string    `json:"name"`
	Signal              string    `json:"signal"`
	WindowCount         uint64    `json:"window_count"`
	Threshold           uint64    `json:"threshold"`
	ActionsLastHour     int       `json:"actions_last_hour"`
	MaxPerHour          int       `json:"max_per_hour"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	CircuitOpen         bool      `json:"circuit_open"`
	CircuitReason       string    `json:"circuit_reason,omitempty"`
	InFlight            bool      `json:"in_flight"`
	LastAction          time.Time `json:"last_action,omitempty"`
}

// New builds an engine for the given rules.
func New(rules []config.Rule, opts Options) *Engine {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ActionTimeout == 0 {
		opts.ActionTimeout = 30 * time.Second
	}
	e := &Engine{opts: opts}
	for _, r := range rules {
		e.rules = append(e.rules, &ruleState{cfg: r})
	}
	m := opts.Metrics
	m.Describe("healer_events_total", "Signals observed, by kind.")
	m.Describe("healer_rule_triggers_total", "Times a rule crossed its threshold.")
	m.Describe("healer_suppressed_total", "Triggers that a safety rail blocked, by reason.")
	m.Describe("healer_remediations_total", "Remediations attempted, by result.")
	m.Describe("healer_escalations_total", "Times the agent gave up and paged a human.")
	return e
}

// Handle feeds one event through every rule. Remediations run asynchronously.
func (e *Engine) Handle(ctx context.Context, ev signals.Event) {
	e.opts.Metrics.Add("healer_events_total", float64(ev.Weight()), "signal", string(ev.Kind))

	type job struct {
		rs       *ruleState
		escalate string
	}
	var jobs []job

	e.mu.Lock()
	now := e.opts.Now()
	for _, rs := range e.rules {
		if !matches(rs.cfg, ev) {
			continue
		}
		rs.add(now, ev.Weight())
		if rs.sum(now) < rs.cfg.Threshold {
			continue
		}
		e.opts.Metrics.Inc("healer_rule_triggers_total", "rule", rs.cfg.Name)

		reason := rs.blocked(now)
		if reason != "" {
			e.opts.Metrics.Inc("healer_suppressed_total", "rule", rs.cfg.Name, "reason", reason)
			e.opts.Logger.Warn("remediation suppressed", "rule", rs.cfg.Name, "reason", reason)
			if reason == "budget_exhausted" {
				rs.open, rs.openReason = true, reason
				jobs = append(jobs, job{rs: rs, escalate: fmt.Sprintf(
					"rule fired more than %d times in an hour; automatic remediation is not fixing the problem", rs.cfg.MaxPerHour)})
			}
			continue
		}

		rs.window = nil
		rs.lastAction = now
		rs.actions = append(rs.actions, now)
		rs.inFlight = true
		jobs = append(jobs, job{rs: rs})
	}
	e.mu.Unlock()

	for _, j := range jobs {
		e.wg.Add(1)
		go func(j job) {
			defer e.wg.Done()
			if j.escalate != "" {
				e.escalate(ctx, j.rs.cfg, j.escalate, ev)
				return
			}
			e.remediate(ctx, j.rs, ev)
		}(j)
	}
}

func (e *Engine) remediate(ctx context.Context, rs *ruleState, ev signals.Event) {
	r := rs.cfg
	log := e.opts.Logger.With("rule", r.Name, "action", r.Action.Type, "signal", ev.Kind, "pid", ev.PID, "comm", ev.Comm, "dest", ev.Dest)

	result := "success"
	var err error
	if e.opts.DryRun {
		result = "dry_run"
		log.Info("dry run: would remediate")
	} else {
		log.Info("remediating")
		actx, cancel := context.WithTimeout(ctx, e.opts.ActionTimeout)
		err = e.opts.Actuator.Execute(actx, r, ev)
		cancel()
		if err != nil {
			err = fmt.Errorf("action: %w", err)
		} else if r.Verify != nil && e.opts.Verifier != nil {
			if verr := e.opts.Verifier.Verify(ctx, *r.Verify); verr != nil {
				err = fmt.Errorf("verify: %w", verr)
			}
		}
		if err != nil {
			result = "failure"
		}
	}

	var giveUp string
	e.mu.Lock()
	rs.inFlight = false
	if err != nil {
		rs.failures++
		if rs.failures >= r.MaxFailures && !rs.open {
			rs.open, rs.openReason = true, "consecutive_failures"
			giveUp = fmt.Sprintf("%d consecutive remediations failed, last error: %v", rs.failures, err)
		}
	} else {
		rs.failures = 0
	}
	e.mu.Unlock()

	e.opts.Metrics.Inc("healer_remediations_total", "rule", r.Name, "action", r.Action.Type, "result", result)
	if err != nil {
		log.Error("remediation failed", "err", err)
	} else if result == "success" {
		log.Info("remediation succeeded")
	}
	if giveUp != "" {
		e.escalate(ctx, r, giveUp, ev)
	}
}

func (e *Engine) escalate(ctx context.Context, r config.Rule, reason string, ev signals.Event) {
	e.opts.Metrics.Inc("healer_escalations_total", "rule", r.Name)
	e.opts.Logger.Error("ESCALATION: circuit open, automatic remediation disabled for rule", "rule", r.Name, "reason", reason)
	if e.opts.DryRun || r.Escalate == nil || e.opts.Escalator == nil {
		return
	}
	ectx, cancel := context.WithTimeout(ctx, e.opts.ActionTimeout)
	defer cancel()
	if err := e.opts.Escalator.Escalate(ectx, r, reason, ev); err != nil {
		e.opts.Logger.Error("escalation failed", "rule", r.Name, "err", err)
	}
}

// Reset closes a rule's circuit breaker after a human has looked at it.
func (e *Engine) Reset(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, rs := range e.rules {
		if rs.cfg.Name == name {
			rs.open, rs.openReason = false, ""
			rs.failures = 0
			rs.actions = nil
			rs.window = nil
			return true
		}
	}
	return false
}

// Status reports the state of every rule.
func (e *Engine) Status() []RuleStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.opts.Now()
	out := make([]RuleStatus, 0, len(e.rules))
	for _, rs := range e.rules {
		rs.pruneActions(now)
		out = append(out, RuleStatus{
			Name:                rs.cfg.Name,
			Signal:              string(rs.cfg.Signal),
			WindowCount:         rs.sum(now),
			Threshold:           rs.cfg.Threshold,
			ActionsLastHour:     len(rs.actions),
			MaxPerHour:          rs.cfg.MaxPerHour,
			ConsecutiveFailures: rs.failures,
			CircuitOpen:         rs.open,
			CircuitReason:       rs.openReason,
			InFlight:            rs.inFlight,
			LastAction:          rs.lastAction,
		})
	}
	return out
}

// Wait blocks until in-flight remediations finish.
func (e *Engine) Wait() { e.wg.Wait() }

func matches(r config.Rule, ev signals.Event) bool {
	if r.Signal != ev.Kind {
		return false
	}
	if r.Match.Comm != "" && ev.Comm != r.Match.Comm {
		return false
	}
	if r.Match.Dest != "" && ev.Dest != r.Match.Dest {
		return false
	}
	if len(r.Match.Signals) > 0 {
		found := false
		for _, s := range r.Match.Signals {
			if s == ev.Signal {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.Match.OnlyFailures && !ev.Failed() {
		return false
	}
	return true
}

func (rs *ruleState) add(now time.Time, n uint64) {
	rs.window = append(rs.window, sample{at: now, n: n})
}

func (rs *ruleState) sum(now time.Time) uint64 {
	cut := now.Add(-rs.cfg.Window)
	i := 0
	for i < len(rs.window) && !rs.window[i].at.After(cut) {
		i++
	}
	rs.window = rs.window[i:]
	var total uint64
	for _, s := range rs.window {
		total += s.n
	}
	return total
}

func (rs *ruleState) pruneActions(now time.Time) {
	cut := now.Add(-time.Hour)
	i := 0
	for i < len(rs.actions) && !rs.actions[i].After(cut) {
		i++
	}
	rs.actions = rs.actions[i:]
}

// blocked returns why a triggered rule may not act now, or "".
func (rs *ruleState) blocked(now time.Time) string {
	if rs.open {
		return "circuit_open"
	}
	if rs.inFlight {
		return "in_flight"
	}
	if !rs.lastAction.IsZero() && now.Sub(rs.lastAction) < rs.cfg.Cooldown {
		return "cooldown"
	}
	rs.pruneActions(now)
	if len(rs.actions) >= rs.cfg.MaxPerHour {
		return "budget_exhausted"
	}
	return ""
}
