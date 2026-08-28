package core

import "testing"

func TestAPVSSCapabilitiesAreCVOnly(t *testing.T) {
	got := CurrentAPVSSCapabilities()
	if got.OutputKind != APVSSOutputScalar ||
		!got.VerifiesReceivedTranscript ||
		!got.AggregatesReceivedInputs ||
		!got.ProducesVerifiableShares ||
		!got.SupportsThresholdKeyOutput {
		t.Fatalf("unexpected CV-sAPVSS capabilities: %+v", got)
	}
	if got.SecurityProfile != "static-cv-sapvss-phase1-materialized" {
		t.Fatalf("unexpected CV-sAPVSS security profile: %q", got.SecurityProfile)
	}
}
