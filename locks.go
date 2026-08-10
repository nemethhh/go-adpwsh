package adpwsh

import "sync"

// keyedMutex serializes writes to one target. Two writers naming different
// objects proceed concurrently, which is what keeps Terraform's parallel graph
// walk useful.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedEntry
}

type keyedEntry struct {
	mu   sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{m: make(map[string]*keyedEntry)}
}

// lock blocks until key is available and returns the release function.
func (k *keyedMutex) lock(key string) (unlock func()) {
	k.mu.Lock()
	e, ok := k.m[key]
	if !ok {
		e = &keyedEntry{}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()

	e.mu.Lock()

	var once sync.Once
	return func() {
		once.Do(func() {
			e.mu.Unlock()
			k.mu.Lock()
			e.refs--
			if e.refs == 0 {
				delete(k.m, key)
			}
			k.mu.Unlock()
		})
	}
}

// size reports how many keys are currently held or waited on. Test support.
func (k *keyedMutex) size() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}
