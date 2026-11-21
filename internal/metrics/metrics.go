// Package metrics is a tiny dependency-free Prometheus counter registry.
package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
)

// Registry holds counters. A nil *Registry is valid and discards updates.
type Registry struct {
	mu     sync.Mutex
	series map[string]*series
	help   map[string]string
}

type series struct {
	name   string
	labels string
	value  float64
}

// New returns an empty registry.
func New() *Registry {
	return &Registry{series: map[string]*series{}, help: map[string]string{}}
}

// Describe sets the HELP text for a metric.
func (r *Registry) Describe(name, help string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.help[name] = help
	r.mu.Unlock()
}

// Inc adds 1 to a counter. labels are key, value pairs.
func (r *Registry) Inc(name string, labels ...string) {
	r.Add(name, 1, labels...)
}

// Add adds v to a counter.
func (r *Registry) Add(name string, v float64, labels ...string) {
	if r == nil {
		return
	}
	ls := formatLabels(labels)
	key := name + ls
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.series[key]
	if !ok {
		s = &series{name: name, labels: ls}
		r.series[key] = s
	}
	s.value += v
}

// Value returns a counter's current value (for tests).
func (r *Registry) Value(name string, labels ...string) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.series[name+formatLabels(labels)]; ok {
		return s.value
	}
	return 0
}

func formatLabels(kv []string) string {
	if len(kv) == 0 {
		return ""
	}
	type pair struct{ k, v string }
	var ps []pair
	for i := 0; i+1 < len(kv); i += 2 {
		ps = append(ps, pair{kv[i], kv[i+1]})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].k < ps[j].k })
	esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	var b strings.Builder
	b.WriteByte('{')
	for i, p := range ps {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `%s="%s"`, p.k, esc.Replace(p.v))
	}
	b.WriteByte('}')
	return b.String()
}

// ServeHTTP writes the Prometheus text exposition format.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	all := make([]*series, 0, len(r.series))
	for _, s := range r.series {
		cp := *s
		all = append(all, &cp)
	}
	help := make(map[string]string, len(r.help))
	for k, v := range r.help {
		help[k] = v
	}
	r.mu.Unlock()

	sort.Slice(all, func(i, j int) bool {
		if all[i].name != all[j].name {
			return all[i].name < all[j].name
		}
		return all[i].labels < all[j].labels
	})

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	last := ""
	for _, s := range all {
		if s.name != last {
			if h, ok := help[s.name]; ok {
				fmt.Fprintf(w, "# HELP %s %s\n", s.name, h)
			}
			fmt.Fprintf(w, "# TYPE %s counter\n", s.name)
			last = s.name
		}
		fmt.Fprintf(w, "%s%s %g\n", s.name, s.labels, s.value)
	}
}
