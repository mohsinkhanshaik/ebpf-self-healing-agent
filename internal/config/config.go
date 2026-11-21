// Package config loads and validates the healerd policy file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

// Action types.
const (
	ActionRestartSystemd = "restart_systemd"
	ActionKillProcess    = "kill_process"
	ActionExec           = "exec"
	ActionWebhook        = "webhook"
	ActionCordonNode     = "cordon_node"
)

// Config is the whole policy file.
type Config struct {
	NodeName       string        `yaml:"node_name"`
	DryRun         bool          `yaml:"dry_run"`
	MetricsAddr    string        `yaml:"metrics_addr"`
	RetransmitPoll time.Duration `yaml:"retransmit_poll_interval"`
	Rules          []Rule        `yaml:"rules"`
}

// Rule maps a signal pattern to a remediation.
type Rule struct {
	Name        string        `yaml:"name"`
	Signal      signals.Kind  `yaml:"signal"`
	Match       Match         `yaml:"match"`
	Threshold   uint64        `yaml:"threshold"`
	Window      time.Duration `yaml:"window"`
	Cooldown    time.Duration `yaml:"cooldown"`
	MaxPerHour  int           `yaml:"max_per_hour"`
	MaxFailures int           `yaml:"max_consecutive_failures"`
	Action      Action        `yaml:"action"`
	Verify      *Verify       `yaml:"verify"`
	Escalate    *Escalate     `yaml:"escalate"`
}

// Match narrows which events count toward a rule. Empty fields match anything.
type Match struct {
	Comm         string `yaml:"comm"`
	Dest         string `yaml:"dest"`
	Signals      []int  `yaml:"signals"`
	OnlyFailures bool   `yaml:"only_failures"`
}

// Action is what the agent does when a rule fires.
type Action struct {
	Type    string   `yaml:"type"`
	Unit    string   `yaml:"unit"`
	Command []string `yaml:"command"`
	URL     string   `yaml:"url"`
	Signal  int      `yaml:"signal"`
}

// Verify checks that the remediation worked.
type Verify struct {
	HTTPGet      string        `yaml:"http_get"`
	InitialDelay time.Duration `yaml:"initial_delay"`
	Timeout      time.Duration `yaml:"timeout"`
	Retries      int           `yaml:"retries"`
	Interval     time.Duration `yaml:"interval"`
}

// Escalate is where to page a human when self-healing gives up.
type Escalate struct {
	Webhook string `yaml:"webhook"`
}

// Load reads, defaults and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse decodes YAML, rejecting unknown fields so typos fail loudly.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.NodeName == "" {
		c.NodeName = os.Getenv("NODE_NAME") // set by the DaemonSet's downward API
	}
	if c.NodeName == "" {
		c.NodeName, _ = os.Hostname()
	}
	if c.MetricsAddr == "" {
		c.MetricsAddr = ":9464"
	}
	if c.RetransmitPoll == 0 {
		c.RetransmitPoll = time.Second
	}
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Threshold == 0 {
			r.Threshold = 1
		}
		if r.Window == 0 {
			r.Window = time.Minute
		}
		if r.Cooldown == 0 {
			r.Cooldown = time.Minute
		}
		if r.MaxPerHour == 0 {
			r.MaxPerHour = 6
		}
		if r.MaxFailures == 0 {
			r.MaxFailures = 3
		}
		if r.Action.Type == ActionKillProcess && r.Action.Signal == 0 {
			r.Action.Signal = 9
		}
		if v := r.Verify; v != nil {
			if v.Timeout == 0 {
				v.Timeout = 5 * time.Second
			}
			if v.Retries == 0 {
				v.Retries = 5
			}
			if v.Interval == 0 {
				v.Interval = 2 * time.Second
			}
		}
	}
}

// Validate reports every problem in the config at once.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Rules) == 0 {
		errs = append(errs, errors.New("no rules defined"))
	}
	seen := map[string]bool{}
	for i, r := range c.Rules {
		bad := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("rule %d (%s): %s", i, r.Name, fmt.Sprintf(format, a...)))
		}
		if r.Name == "" {
			bad("name is required")
		} else if seen[r.Name] {
			bad("duplicate name")
		}
		seen[r.Name] = true

		if !r.Signal.Valid() {
			bad("unknown signal %q", r.Signal)
		}
		if len(r.Match.Comm) > 15 {
			bad("match.comm %q is longer than the kernel's 15-character limit", r.Match.Comm)
		}
		if r.Signal == signals.ProcessExit && r.Match.Comm == "" {
			bad("process_exit rules need match.comm (it is filtered in the kernel)")
		}
		if r.Match.Dest != "" {
			if _, err := netip.ParseAddrPort(r.Match.Dest); err != nil {
				bad("match.dest must be ip:port: %v", err)
			}
		}

		switch r.Action.Type {
		case ActionRestartSystemd:
			if r.Action.Unit == "" {
				bad("restart_systemd needs action.unit")
			}
		case ActionExec:
			if len(r.Action.Command) == 0 {
				bad("exec needs action.command")
			}
		case ActionWebhook:
			if r.Action.URL == "" {
				bad("webhook needs action.url")
			}
		case ActionKillProcess:
			if r.Signal == signals.TCPRetransmit {
				bad("kill_process needs a PID, which tcp_retransmit events do not carry")
			}
		case ActionCordonNode:
		default:
			bad("unknown action.type %q", r.Action.Type)
		}

		if r.Verify != nil && r.Verify.HTTPGet == "" {
			bad("verify needs http_get")
		}
		if r.Escalate != nil && r.Escalate.Webhook == "" {
			bad("escalate needs webhook")
		}
	}
	return errors.Join(errs...)
}

// WatchedComms lists process names the kernel should report exits for.
func (c *Config) WatchedComms() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range c.Rules {
		if r.Signal == signals.ProcessExit && !seen[r.Match.Comm] {
			seen[r.Match.Comm] = true
			out = append(out, r.Match.Comm)
		}
	}
	return out
}
