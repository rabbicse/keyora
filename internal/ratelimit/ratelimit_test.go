package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(60, 3) // one per second, burst of three
	l.SetClock(func() time.Time { return now })

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatalf("request %d inside the burst was refused", i+1)
		}
	}
	ok, wait := l.Allow("ip")
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("ok=%v wait=%v, want a refusal with a wait of up to 1s", ok, wait)
	}
	if ok, _ := l.Allow("other-ip"); !ok {
		t.Fatal("keys must be limited independently")
	}
	now = now.Add(time.Second)
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("token was not refilled after one second")
	}
	if ok, _ := l.Allow("ip"); ok {
		t.Fatal("more than one token refilled in one second")
	}

	// Idle buckets are swept so memory does not grow without bound.
	now = now.Add(10 * time.Minute)
	l.Allow("fresh")
	if len(l.buckets) != 1 {
		t.Fatalf("%d buckets remain after sweep, want 1", len(l.buckets))
	}
}

func TestDisabledLimiter(t *testing.T) {
	var none *Limiter
	for _, l := range []*Limiter{none, New(0, 0)} {
		for i := 0; i < 100; i++ {
			if ok, _ := l.Allow("ip"); !ok {
				t.Fatal("disabled limiter refused a request")
			}
		}
	}
}
