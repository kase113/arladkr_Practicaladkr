package main

import (
	"testing"
	"time"
)

func TestDefaultPracticalBenchTimeoutScalesWithCommittee(t *testing.T) {
	tests := []struct {
		n    int
		want time.Duration
	}{
		{n: 10, want: 90 * time.Second},
		{n: 32, want: 5 * time.Minute},
		{n: 64, want: 10 * time.Minute},
		{n: 100, want: 15 * time.Minute},
		{n: 128, want: 20 * time.Minute},
		{n: 256, want: 30 * time.Minute},
	}
	for _, test := range tests {
		if got := defaultPracticalBenchTimeout(test.n); got != test.want {
			t.Fatalf("n=%d timeout=%s want=%s", test.n, got, test.want)
		}
	}
}
