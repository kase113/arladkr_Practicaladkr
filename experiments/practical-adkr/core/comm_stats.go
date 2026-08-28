package core

import "sync"

var practicalCommStats struct {
	mu      sync.Mutex
	enabled bool
	sent    uint64
	recv    uint64
	phase   string
	phases  map[string]phaseCommStat
}

type phaseCommStat struct {
	sent uint64
	recv uint64
}

func resetCommStats(enabled bool) {
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	practicalCommStats.enabled = enabled
	practicalCommStats.sent = 0
	practicalCommStats.recv = 0
	practicalCommStats.phase = ""
	practicalCommStats.phases = make(map[string]phaseCommStat)
}

func setCommPhase(name string) {
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	practicalCommStats.phase = name
}

func recordSentBytes(n int) {
	if n <= 0 {
		return
	}
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	if !practicalCommStats.enabled {
		return
	}
	practicalCommStats.sent += uint64(n)
	if practicalCommStats.phase != "" {
		ps := practicalCommStats.phases[practicalCommStats.phase]
		ps.sent += uint64(n)
		practicalCommStats.phases[practicalCommStats.phase] = ps
	}
}

func recordRecvBytes(n int) {
	if n <= 0 {
		return
	}
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	if !practicalCommStats.enabled {
		return
	}
	practicalCommStats.recv += uint64(n)
	if practicalCommStats.phase != "" {
		ps := practicalCommStats.phases[practicalCommStats.phase]
		ps.recv += uint64(n)
		practicalCommStats.phases[practicalCommStats.phase] = ps
	}
}

func commStats() (uint64, uint64) {
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	return practicalCommStats.sent, practicalCommStats.recv
}

func phaseCommStats() map[string]phaseCommStat {
	practicalCommStats.mu.Lock()
	defer practicalCommStats.mu.Unlock()
	out := make(map[string]phaseCommStat, len(practicalCommStats.phases))
	for k, v := range practicalCommStats.phases {
		out[k] = v
	}
	return out
}
