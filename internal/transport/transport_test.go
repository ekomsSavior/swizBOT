package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

type fakeLayer struct {
	name  string
	pri   int
	pollF func(context.Context) (Frame, error)
	pushF func(context.Context, []byte) error
}

func (f *fakeLayer) Name() string  { return f.name }
func (f *fakeLayer) Priority() int { return f.pri }
func (f *fakeLayer) Poll(ctx context.Context) (Frame, error) {
	if f.pollF == nil {
		return Frame{}, ErrUnsupported
	}
	return f.pollF(ctx)
}
func (f *fakeLayer) Push(ctx context.Context, b []byte) error {
	if f.pushF == nil {
		return ErrUnsupported
	}
	return f.pushF(ctx, b)
}

func errLayer(name string, pri int) *fakeLayer {
	return &fakeLayer{name: name, pri: pri, pollF: func(context.Context) (Frame, error) {
		return Frame{}, errors.New("down")
	}, pushF: func(context.Context, []byte) error { return errors.New("down") }}
}

func okLayer(name string, pri int, body string, sealed bool) *fakeLayer {
	return &fakeLayer{name: name, pri: pri, pollF: func(context.Context) (Frame, error) {
		return Frame{Body: []byte(body), Sealed: sealed}, nil
	}, pushF: func(context.Context, []byte) error { return nil }}
}

func TestOrderingByPriority(t *testing.T) {
	m := New([]Layer{errLayer("c", 30), errLayer("a", 10), errLayer("b", 20)})
	got := m.Names()
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %v, want %v", got, want)
		}
	}
}

func TestPollFailover(t *testing.T) {
	m := New([]Layer{errLayer("https", 10), okLayer("dns", 20, "frame", true)})
	f, via, err := m.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if via != "dns" || string(f.Body) != "frame" || !f.Sealed {
		t.Fatalf("got via=%q body=%q sealed=%v", via, f.Body, f.Sealed)
	}
}

func TestPollStopsAtFirstHealthy(t *testing.T) {
	empty := &fakeLayer{name: "https", pri: 10, pollF: func(context.Context) (Frame, error) {
		return Frame{}, nil // healthy, nothing queued
	}}
	m := New([]Layer{empty, okLayer("dns", 20, "should-not-win", true)})
	f, via, err := m.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	if via != "https" || len(f.Body) != 0 {
		t.Fatalf("expected to stop at https with empty frame, got via=%q body=%q", via, f.Body)
	}
}

func TestProbationThenSkip(t *testing.T) {
	clk := &clock{t: time.Unix(1000, 0)}
	l1 := errLayer("https", 10)
	l2 := okLayer("dns", 20, "ok", true)
	m := New([]Layer{l1, l2}, WithClock(clk.now), WithProbation(2, 10*time.Second))

	// two failed polls trip probation on l1
	for i := 0; i < 2; i++ {
		if _, via, err := m.Poll(context.Background()); err != nil || via != "dns" {
			t.Fatalf("poll %d: via=%q err=%v", i, via, err)
		}
	}
	st := m.Status()[0]
	if st.Failures != 2 || !st.ProbationTill.After(clk.now()) {
		t.Fatalf("l1 should be in probation after 2 failures: %+v", st)
	}
	// third poll must skip l1 entirely (no new failures recorded)
	if _, via, err := m.Poll(context.Background()); err != nil || via != "dns" {
		t.Fatalf("poll 3: via=%q err=%v", via, err)
	}
	if got := m.Status()[0].Failures; got != 2 {
		t.Fatalf("l1 should not be retried during probation, failures=%d", got)
	}
}

func TestRecoveryAfterProbation(t *testing.T) {
	clk := &clock{t: time.Unix(2000, 0)}
	recovered := false
	l1 := &fakeLayer{name: "https", pri: 10, pollF: func(context.Context) (Frame, error) {
		if !recovered {
			return Frame{}, errors.New("down")
		}
		return Frame{Body: []byte("back"), Sealed: true}, nil
	}, pushF: func(context.Context, []byte) error { return nil }}
	l2 := okLayer("dns", 20, "fallback", true)
	m := New([]Layer{l1, l2}, WithClock(clk.now), WithProbation(1, 10*time.Second))

	// one failure -> probation
	if _, via, _ := m.Poll(context.Background()); via != "dns" {
		t.Fatalf("expected fallback, got %q", via)
	}
	// still in probation -> skipped even though l1 would succeed now
	recovered = true
	if _, via, _ := m.Poll(context.Background()); via != "dns" {
		t.Fatalf("expected probation skip, got %q", via)
	}
	// after the window, l1 is retried and wins
	clk.advance(11 * time.Second)
	f, via, err := m.Poll(context.Background())
	if err != nil || via != "https" || string(f.Body) != "back" {
		t.Fatalf("expected https recovery, got via=%q body=%q err=%v", via, f.Body, err)
	}
	if st := m.Status()[0]; !st.Healthy || st.Consecutive != 0 {
		t.Fatalf("l1 should be healthy after recovery: %+v", st)
	}
}

func TestPushFirstSuccess(t *testing.T) {
	m := New([]Layer{errLayer("https", 10), okLayer("dns", 20, "", true)})
	via, err := m.Push(context.Background(), []byte("x"))
	if err != nil || via != "dns" {
		t.Fatalf("push via=%q err=%v", via, err)
	}
}

func TestUnsupportedSkipped(t *testing.T) {
	// poll-side unsupported (no pollF) must not count as a failure
	ro := &fakeLayer{name: "dns", pri: 10, pushF: func(context.Context, []byte) error { return nil }}
	m := New([]Layer{ro, okLayer("https", 20, "ok", true)})
	if _, via, err := m.Poll(context.Background()); err != nil || via != "https" {
		t.Fatalf("poll via=%q err=%v", via, err)
	}
	if st := m.Status()[0]; st.Failures != 0 {
		t.Fatalf("unsupported poll must not count as failure: %+v", st)
	}
	// push direction: the https layer is poll-only? no - it pushes fine. use a poll-only first layer
	pollOnly := &fakeLayer{name: "recv", pri: 10, pollF: func(context.Context) (Frame, error) { return Frame{}, nil }}
	m2 := New([]Layer{pollOnly, okLayer("https", 20, "", true)})
	if via, err := m2.Push(context.Background(), []byte("x")); err != nil || via != "https" {
		t.Fatalf("push via=%q err=%v", via, err)
	}
	if st := m2.Status()[0]; st.Failures != 0 {
		t.Fatalf("unsupported push must not count as failure: %+v", st)
	}
}

func TestAllFailed(t *testing.T) {
	m := New([]Layer{errLayer("a", 10), errLayer("b", 20)})
	if _, _, err := m.Poll(context.Background()); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("want ErrAllFailed, got %v", err)
	}
	if _, err := m.Push(context.Background(), nil); !errors.Is(err, ErrAllFailed) {
		t.Fatalf("push want ErrAllFailed, got %v", err)
	}
}

func TestNoLayers(t *testing.T) {
	m := New(nil)
	if _, _, err := m.Poll(context.Background()); !errors.Is(err, ErrNoLayers) {
		t.Fatalf("want ErrNoLayers, got %v", err)
	}
	if _, err := m.Push(context.Background(), nil); !errors.Is(err, ErrNoLayers) {
		t.Fatalf("push want ErrNoLayers, got %v", err)
	}
}

func TestProbationBackoffCaps(t *testing.T) {
	clk := &clock{t: time.Unix(3000, 0)}
	l1 := errLayer("https", 10)
	l2 := okLayer("dns", 20, "ok", true)
	m := New([]Layer{l1, l2}, WithClock(clk.now), WithProbation(1, time.Minute), WithMaxProbation(5*time.Minute))

	// drive many failures, advancing past each probation window so l1 retries
	for i := 0; i < 40; i++ {
		_, _, _ = m.Poll(context.Background())
		clk.advance(6 * time.Minute)
	}
	st := m.Status()[0]
	// probation window must be capped
	if d := st.ProbationTill.Sub(clk.now()); d > 5*time.Minute+time.Second {
		t.Fatalf("probation window %s exceeds cap", d)
	}
}
