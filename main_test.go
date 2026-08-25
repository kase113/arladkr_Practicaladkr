package main

import "testing"

func TestGreeting(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{name: "", want: "Hello, World!"},
		{name: "ADKR", want: "Hello, ADKR!"},
	}

	for _, tt := range tests {
		if got := greeting(tt.name); got != tt.want {
			t.Errorf("greeting(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}
