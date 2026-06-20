package core

import (
	"math/rand"
	"sync"
	"time"
)

// Scheduler manages beacon intervals with jitter and kill date enforcement.
type Scheduler struct {
	mu       sync.Mutex
	sleep    time.Duration
	jitter   float64 // 0.0 to 1.0
	killDate time.Time
	killed   bool
}

func NewScheduler(sleep time.Duration, jitter float64, killDate string) *Scheduler {
	s := &Scheduler{
		sleep:  sleep,
		jitter: jitter,
	}
	if killDate != "" {
		if t, err := time.Parse("2006-01-02", killDate); err == nil {
			s.killDate = t.UTC()
		}
	}
	return s
}

// Wait sleeps for the configured interval plus random jitter.
// Returns false if the kill date has passed.
func (s *Scheduler) Wait() bool {
	s.mu.Lock()
	if s.killed {
		s.mu.Unlock()
		return false
	}

	// Kill date check
	if !s.killDate.IsZero() && time.Now().UTC().After(s.killDate) {
		s.killed = true
		s.mu.Unlock()
		return false
	}

	base := s.sleep
	jitterRange := time.Duration(float64(base) * s.jitter)
	delay := base
	if jitterRange > 0 {
		delay += time.Duration(rand.Int63n(int64(jitterRange)))
	}
	s.mu.Unlock()

	time.Sleep(delay)
	return true
}

// UpdateConfig allows the C2 to adjust beacon timing.
func (s *Scheduler) UpdateConfig(sleep time.Duration, jitter float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sleep > 0 {
		s.sleep = sleep
	}
	if jitter >= 0 && jitter <= 1.0 {
		s.jitter = jitter
	}
}

// Kill signals the agent to stop beaconing.
func (s *Scheduler) Kill() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.killed = true
}
