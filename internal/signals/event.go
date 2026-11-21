// Package signals defines the health signals the agent reacts to.
package signals

import "time"

// Kind is the type of signal.
type Kind string

const (
	OOMKill       Kind = "oom_kill"
	CrashSignal   Kind = "crash_signal"
	ProcessExit   Kind = "process_exit"
	TCPRetransmit Kind = "tcp_retransmit"
)

// Valid reports whether k is a known signal kind.
func (k Kind) Valid() bool {
	switch k {
	case OOMKill, CrashSignal, ProcessExit, TCPRetransmit:
		return true
	}
	return false
}

// Event is one observation from the kernel (or a replay file).
type Event struct {
	Kind       Kind      `json:"kind"`
	Time       time.Time `json:"time,omitempty"`
	PID        uint32    `json:"pid,omitempty"`
	Comm       string    `json:"comm,omitempty"`
	Signal     int       `json:"signal,omitempty"`      // crash signal, or the signal that ended a process
	ExitStatus int       `json:"exit_status,omitempty"` // exit status for process_exit
	Dest       string    `json:"dest,omitempty"`        // ip:port for tcp_retransmit
	Count      uint64    `json:"count,omitempty"`       // weight; retransmits per poll interval
}

// Failed reports whether a process_exit event was abnormal.
func (e Event) Failed() bool {
	return e.Signal != 0 || e.ExitStatus != 0
}

// Weight is the amount the event adds to a rule's window.
func (e Event) Weight() uint64 {
	if e.Count == 0 {
		return 1
	}
	return e.Count
}
