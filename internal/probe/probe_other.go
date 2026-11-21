//go:build !linux

package probe

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/mohsinkhanshaik/ebpf-self-healing-agent/internal/signals"
)

// ErrUnsupported is returned on non-Linux systems. Use -replay there.
var ErrUnsupported = errors.New("eBPF probes require Linux; use -replay to try the engine on this OS")

// Probe is unavailable on this platform.
type Probe struct{}

// Load always fails on non-Linux systems.
func Load([]string, *slog.Logger) (*Probe, error) { return nil, ErrUnsupported }

// Attached returns nothing.
func (p *Probe) Attached() []string { return nil }

// Run always fails.
func (p *Probe) Run(context.Context, chan<- signals.Event, time.Duration) error {
	return ErrUnsupported
}

// Close is a no-op.
func (p *Probe) Close() error { return nil }
