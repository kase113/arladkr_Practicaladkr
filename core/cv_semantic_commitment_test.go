package core

import (
	"bytes"
	"testing"
)

func TestCVLeafSemanticCommitmentBindsCanonicalWireAndLength(t *testing.T) {
	inputs := [][]byte{
		{1},
		bytes.Repeat([]byte{2}, 30),
		bytes.Repeat([]byte{3}, 31),
		bytes.Repeat([]byte{4}, 32),
		bytes.Repeat([]byte{5}, 62),
		bytes.Repeat([]byte{6}, 63),
	}
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		commitment, err := cvLeafSemanticCommitment(input)
		if err != nil {
			t.Fatal(err)
		}
		repeated, err := cvLeafSemanticCommitment(append([]byte(nil), input...))
		if err != nil || !bytes.Equal(repeated, commitment) {
			t.Fatalf("semantic commitment is not deterministic: %v", err)
		}
		if !cvValidLeafSemanticCommitment(commitment) {
			t.Fatal("generated a non-canonical semantic commitment")
		}
		if _, duplicate := seen[string(commitment)]; duplicate {
			t.Fatal("distinct test wires produced the same semantic commitment")
		}
		seen[string(commitment)] = struct{}{}
		mutated := append([]byte(nil), input...)
		mutated[len(mutated)-1] ^= 1
		mutatedCommitment, err := cvLeafSemanticCommitment(mutated)
		if err != nil || bytes.Equal(mutatedCommitment, commitment) {
			t.Fatalf("wire mutation was not bound: %v", err)
		}
	}
	one, err := cvLeafSemanticCommitment([]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	leadingZero, err := cvLeafSemanticCommitment([]byte{0, 1})
	if err != nil || bytes.Equal(one, leadingZero) {
		t.Fatalf("semantic commitment did not bind wire length: %v", err)
	}
}

func TestCVLeafSemanticCommitmentRejectsInvalidInputAndFieldEncoding(t *testing.T) {
	if _, err := cvLeafSemanticCommitment(nil); err == nil {
		t.Fatal("accepted empty semantic commitment input")
	}
	if cvValidLeafSemanticCommitment(bytes.Repeat([]byte{0xff}, 32)) {
		t.Fatal("accepted non-canonical BN254 semantic commitment")
	}
	if cvValidLeafSemanticCommitment(make([]byte, 31)) {
		t.Fatal("accepted short semantic commitment")
	}
}

func TestCVComponentRecoveryChecksSemanticCommitment(t *testing.T) {
	payload := bytes.Repeat([]byte("semantic-commitment-payload"), 4)
	dispersal, shards, err := cvDisperseComponent(payload, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	wantCommitment, err := cvLeafSemanticCommitment(payload)
	if err != nil || !bytes.Equal(dispersal.semanticCommitment, wantCommitment) {
		t.Fatalf("component dispersal commitment mismatch: %v", err)
	}
	available := map[int]cvComponentShard{0: shards[0], 1: shards[1]}
	recovered, err := cvRecoverComponentWire(dispersal, 4, available)
	if err != nil || !bytes.Equal(recovered, payload) {
		t.Fatalf("recover component with semantic commitment: %v", err)
	}

	tampered := *dispersal
	tampered.semanticCommitment = make([]byte, 32)
	if bytes.Equal(tampered.semanticCommitment, dispersal.semanticCommitment) {
		tampered.semanticCommitment[31] = 1
	}
	if _, err := cvRecoverComponentWire(&tampered, 4, available); err == nil {
		t.Fatal("component recovery accepted wrong semantic commitment")
	}
}
