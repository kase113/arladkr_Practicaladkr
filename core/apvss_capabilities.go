package core

type APVSSOutputKind string

const (
	APVSSOutputScalar APVSSOutputKind = "scalar"
)

type APVSSCapabilities struct {
	OutputKind                 APVSSOutputKind
	VerifiesReceivedTranscript bool
	AggregatesReceivedInputs   bool
	ProducesVerifiableShares   bool
	UsesProductionRandomness   bool
	SupportsThresholdKeyOutput bool
	SecurityProfile            string
}

func CurrentAPVSSCapabilities() APVSSCapabilities {
	return APVSSCapabilities{
		OutputKind:                 APVSSOutputScalar,
		VerifiesReceivedTranscript: true,
		AggregatesReceivedInputs:   true,
		ProducesVerifiableShares:   true,
		SupportsThresholdKeyOutput: true,
		SecurityProfile:            "static-cv-sapvss-phase1-materialized",
	}
}
