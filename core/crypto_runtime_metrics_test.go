package core

import "testing"

func TestRuntimeNamedBytesDoNotChangeTotals(t *testing.T) {
	runtime := newRuntimeCommMetrics(true)
	runtime.recordSentBytes(11)
	runtime.recordRecvBytes(12)
	runtime.recordNamedSentBytes("mvba_pd_data", 7)
	runtime.recordNamedRecvBytes("mvba_pd_data", 8)

	sent, recv := runtime.commStats()
	if sent != 11 || recv != 12 {
		t.Fatalf("named metrics changed totals: sent=%d recv=%d", sent, recv)
	}
	phaseSent, phaseRecv := runtime.phaseCommStats()
	if phaseSent["mvba_pd_data"] != 7 || phaseRecv["mvba_pd_data"] != 8 {
		t.Fatalf("named metrics missing: sent=%v recv=%v", phaseSent, phaseRecv)
	}
}
