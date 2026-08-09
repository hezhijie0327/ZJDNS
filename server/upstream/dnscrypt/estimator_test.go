package dnscrypt

import (
	"context"
	"math"
	"net"
	"sync"
	"testing"
	"time"
	"zjdns/config"

	"codeberg.org/miekg/dns"
)

// toggleHandler switches from big (40 A records, forces TC) to small
// (1 A record) responses; the test flips it between phases.
type toggleHandler struct {
	mu  sync.Mutex
	big bool
}

// newTestState returns a State with the production initial estimator values.
func newTestState() *State {
	s := &State{}
	s.minQueryLen.Store(int32(config.DefaultDNSCryptMinQueryLen))
	s.ewmaQuerySize.Store(math.Float64bits(float64(config.DefaultDNSCryptMinQueryLen)))
	return s
}

// TestStateEstimator_BlindAdjust verifies the TC escalation chain: doubling
// from the 512 initial up to the 4096 cap, EWMA reset on each step, and the
// no-escalation report at the cap (TCP fallback).
func TestStateEstimator_BlindAdjust(t *testing.T) {
	s := newTestState()
	for _, want := range []int{1024, 2048, 4096} {
		if !s.blindAdjust() {
			t.Fatalf("blindAdjust at min=%d must escalate", want/2)
		}
		if got := int(s.minQueryLen.Load()); got != want {
			t.Fatalf("want minQueryLen %d, got %d", want, got)
		}
		if got := math.Float64frombits(s.ewmaQuerySize.Load()); got != float64(want) {
			t.Fatalf("EWMA must be reset to %d after escalation, got %v", want, got)
		}
	}
	if s.blindAdjust() {
		t.Fatal("blindAdjust at the 4096 cap must report no escalation")
	}
}

// TestStateEstimator_AdjustShrink verifies the decrease branch: small
// responses pull the EWMA below half the budget and minQueryLen halves once,
// then hysteresis keeps it there (1024/2=512 would need EWMA in (512, 512)).
func TestStateEstimator_AdjustShrink(t *testing.T) {
	s := &State{}
	s.minQueryLen.Store(2048)
	s.ewmaQuerySize.Store(math.Float64bits(2048))
	for range 60 {
		s.adjustQuerySize(180) // ~180-byte wire responses
	}
	if got := int(s.minQueryLen.Load()); got != 1024 {
		t.Fatalf("want minQueryLen 1024 after shrink, got %d", got)
	}
	for range 60 {
		s.adjustQuerySize(180)
	}
	if got := int(s.minQueryLen.Load()); got != 1024 {
		t.Fatalf("minQueryLen must stay 1024 under hysteresis, got %d", got)
	}
}

// TestStateEstimator_AdjustNoShrinkBelowHalf verifies that an EWMA above half
// the budget never shrinks it: min=1024 with ~800-byte responses converges
// below 1024 but stays above 1024/2, so the budget is preserved.
func TestStateEstimator_AdjustNoShrinkBelowHalf(t *testing.T) {
	s := &State{}
	s.minQueryLen.Store(1024)
	s.ewmaQuerySize.Store(math.Float64bits(1024))
	for range 60 {
		s.adjustQuerySize(800)
	}
	if got := int(s.minQueryLen.Load()); got != 1024 {
		t.Fatalf("minQueryLen must not shrink while EWMA stays above half, got %d", got)
	}
}

// TestStateEstimator_BlindAdjustResetsEWMA verifies the shrink-vs-growth
// interplay: after a long run of small responses the EWMA is ~650; one TC
// doubles the budget to 4096 and resets the EWMA, so the next small response
// must NOT immediately undo the escalation (EWMA would otherwise be < 4096/2).
func TestStateEstimator_BlindAdjustResetsEWMA(t *testing.T) {
	s := &State{}
	s.minQueryLen.Store(2048)
	s.ewmaQuerySize.Store(math.Float64bits(650)) // long run of small responses
	if !s.blindAdjust() {
		t.Fatal("blindAdjust must escalate from 2048")
	}
	if got := int(s.minQueryLen.Load()); got != 4096 {
		t.Fatalf("want minQueryLen 4096 after escalation, got %d", got)
	}
	s.adjustQuerySize(180)
	if got := int(s.minQueryLen.Load()); got != 4096 {
		t.Fatalf("EWMA reset must prevent immediate shrink after escalation, got %d", got)
	}
}

// TestStateEstimator_EWMAConverges sanity-checks the decay math: the average
// must converge toward the observed wire size.
func TestStateEstimator_EWMAConverges(t *testing.T) {
	s := &State{}
	s.minQueryLen.Store(1024)
	s.ewmaQuerySize.Store(math.Float64bits(1024))
	for range 200 {
		s.adjustQuerySize(180)
	}
	if got := math.Float64frombits(s.ewmaQuerySize.Load()); math.Abs(got-180) > 1 {
		t.Fatalf("EWMA should converge to ~180, got %v", got)
	}
}

// TestStateEstimator_Concurrent exercises the lock-free CAS loop under
// contention; run with -race to verify no data races on the estimator fields.
func TestStateEstimator_Concurrent(t *testing.T) {
	s := newTestState()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 200 {
				s.adjustQuerySize(200)
				s.blindAdjust()
			}
		})
	}
	wg.Wait()
	if cur := int(s.minQueryLen.Load()); cur < 512 || cur > 4096 {
		t.Fatalf("minQueryLen %d out of [512, 4096]", cur)
	}
}

// cachedState returns the single cached State (one upstream in these tests).
func cachedState(t *testing.T, c *Client) *State {
	t.Helper()
	var st *State
	c.cache.Range(func(_ string, v *State) bool {
		st = v
		return false
	})
	if st == nil {
		t.Fatal("state should be cached after a query")
	}
	return st
}

func (h *toggleHandler) ServeDNS(req *dns.Msg, _ net.IP, _ bool, _ string) *dns.Msg {
	h.mu.Lock()
	big := h.big
	h.mu.Unlock()
	if big {
		return (&bigResponseHandler{n: 40}).ServeDNS(req, nil, false, "")
	}
	return (&testDNSHandler{}).ServeDNS(req, nil, false, "")
}

// TestDNSCrypt_EstimatorShrink_E2E drives the full client pipeline through
// both estimator branches: a big response escalates the budget via TC
// (512→1024→2048), then a run of small responses shrinks it back to 1024.
func TestDNSCrypt_EstimatorShrink_E2E(t *testing.T) {
	handler := &toggleHandler{big: true}
	_, stamp := startTestDNSCryptServerWithHandler(t, handler)

	c := New(nil)
	pqFalse := false
	server := &config.UpstreamServer{Address: stamp, Protocol: config.ProtoDNSCrypt, PQDNSCrypt: &pqFalse}

	// Phase 1: big response → TC escalation until the budget fits.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	resp, err := c.Execute(ctx, newQuery("big.example.com."), server, false)
	cancel()
	if err != nil {
		t.Fatalf("big query: %v", err)
	}
	if len(resp.Answer) != 40 {
		t.Fatalf("want 40 answers, got %d", len(resp.Answer))
	}
	st := cachedState(t, c)
	if got := int(st.minQueryLen.Load()); got != 2048 {
		t.Fatalf("want minQueryLen 2048 after TC escalation, got %d", got)
	}

	// Phase 2: small responses → EWMA drops below half → shrink to 1024.
	handler.mu.Lock()
	handler.big = false
	handler.mu.Unlock()
	for range 60 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := c.Execute(ctx, newQuery("small.example.com."), server, false)
		cancel()
		if err != nil {
			t.Fatalf("small query: %v", err)
		}
	}
	if got := int(st.minQueryLen.Load()); got != 1024 {
		t.Fatalf("want minQueryLen 1024 after shrink, got %d", got)
	}
}
