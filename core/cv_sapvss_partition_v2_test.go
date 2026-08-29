package core

import "testing"

func TestCVEvidencePartitionV2CanonicalCoverageAndCodec(t *testing.T) {
	context, _, _ := cvCoreProofV2Fixture(t)
	partition := &cvEvidencePartitionV2{
		ACKReceiverIndices: []int{1, 2, 4}, FallbackReceiverIndices: []int{3},
	}
	if err := cvValidateEvidencePartitionV2(context, partition); err != nil {
		t.Fatal(err)
	}
	wire, err := cvEvidencePartitionV2CanonicalBytes(context, partition)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeEvidencePartitionV2(wire, context)
	if err != nil || !equalInts(decoded.ACKReceiverIndices, partition.ACKReceiverIndices) ||
		!equalInts(decoded.FallbackReceiverIndices, partition.FallbackReceiverIndices) {
		t.Fatalf("V2 evidence partition round trip: %v", err)
	}
	if _, err := cvDecodeEvidencePartitionV2(append(append([]byte(nil), wire...), 0), context); err == nil {
		t.Fatal("accepted V2 evidence partition with trailing bytes")
	}
}

func TestCVEvidencePartitionV2RejectsOverlapGapsOrderAndExcessFallback(t *testing.T) {
	context, _, _ := cvCoreProofV2Fixture(t)
	tests := []struct {
		name      string
		acks      []int
		fallbacks []int
	}{
		{name: "overlap", acks: []int{1, 2, 3, 4}, fallbacks: []int{3}},
		{name: "gap", acks: []int{1, 2}, fallbacks: []int{4}},
		{name: "unordered ACK", acks: []int{2, 1, 4}, fallbacks: []int{3}},
		{name: "duplicate ACK", acks: []int{1, 1, 4}, fallbacks: []int{2}},
		{name: "out of range", acks: []int{1, 2, 5}, fallbacks: []int{3}},
		{name: "too many fallback", acks: []int{1, 4}, fallbacks: []int{2, 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			partition := &cvEvidencePartitionV2{
				ACKReceiverIndices: test.acks, FallbackReceiverIndices: test.fallbacks,
			}
			if err := cvValidateEvidencePartitionV2(context, partition); err == nil {
				t.Fatal("accepted invalid V2 ACK/fallback partition")
			}
		})
	}
}
