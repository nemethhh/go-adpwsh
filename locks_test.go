package adpwsh

import (
	"sync"
	"testing"
	"time"
)

// Run with -race. Without serialization the counter races and the test fails
// under the detector even when the arithmetic happens to come out right.
func TestKeyedMutexSerializesSameKey(t *testing.T) {
	km := newKeyedMutex()
	var (
		counter  int
		maxSeen  int
		inFlight int
		mu       sync.Mutex
		wg       sync.WaitGroup
	)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock := km.lock("same-guid")
			defer unlock()

			mu.Lock()
			inFlight++
			if inFlight > maxSeen {
				maxSeen = inFlight
			}
			mu.Unlock()

			counter++ // deliberately unguarded: the keyed mutex is the guard
			time.Sleep(time.Millisecond)

			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
	}
	wg.Wait()
	if counter != 50 {
		t.Errorf("counter = %d, want 50", counter)
	}
	if maxSeen != 1 {
		t.Errorf("saw %d concurrent holders of one key, want 1", maxSeen)
	}
}

func TestKeyedMutexAllowsDifferentKeys(t *testing.T) {
	km := newKeyedMutex()
	first := km.lock("a")
	done := make(chan struct{})
	go func() {
		unlock := km.lock("b")
		unlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a lock on key b blocked behind key a")
	}
	first()
}

// The map must not grow for the lifetime of a long-running provider.
func TestKeyedMutexReleasesEntries(t *testing.T) {
	km := newKeyedMutex()
	for i := 0; i < 100; i++ {
		km.lock("transient")()
	}
	if n := km.size(); n != 0 {
		t.Errorf("keyedMutex retained %d entries after release", n)
	}
}
