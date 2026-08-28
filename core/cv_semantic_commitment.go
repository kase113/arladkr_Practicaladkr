package core

import (
	"encoding/binary"
	"fmt"

	bnfr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

const (
	cvSemanticCommitmentDomain     = "ARL-CV-sAPVSS/leaf-semantic-commitment/v1"
	cvSemanticCommitmentChunkBytes = 31
)

// cvLeafSemanticCommitment maps the complete canonical leaf wire to one BN254
// field element using Poseidon2. Length is absorbed explicitly, and each data
// block is at most 248 bits, so its field encoding is injective. This is a
// proof-friendly witness binding; it does not by itself prove APVSS validity.
func cvLeafSemanticCommitment(leafWire []byte) ([]byte, error) {
	if len(leafWire) == 0 || len(leafWire) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid leaf wire for semantic commitment")
	}
	return cvPoseidon2BytesCommitment(
		cvSemanticCommitmentDomain, leafWire, cvMaxLeafWireBytes,
	)
}

// cvPoseidon2BytesCommitment injectively packs bytes into BN254 field
// elements before applying the native Poseidon2 Merkle-Damgard construction.
// The domain and exact byte length are part of the commitment.
func cvPoseidon2BytesCommitment(domain string, value []byte, maximumBytes int) ([]byte, error) {
	if domain == "" || len(value) == 0 || maximumBytes <= 0 || len(value) > maximumBytes {
		return nil, fmt.Errorf("invalid Poseidon2 byte commitment input")
	}
	hasher := poseidon2.NewMerkleDamgardHasher()
	writeElement := func(encoded []byte) error {
		if len(encoded) != bnfr.Bytes {
			return fmt.Errorf("invalid Poseidon2 commitment field element")
		}
		if _, err := hasher.Write(encoded); err != nil {
			return fmt.Errorf("absorb Poseidon2 commitment field element: %w", err)
		}
		return nil
	}

	var domainElement bnfr.Element
	domainElement.SetBytes(hashBytes([]byte(domain)))
	domainBlock := domainElement.Bytes()
	if err := writeElement(domainBlock[:]); err != nil {
		return nil, err
	}
	var lengthBlock [bnfr.Bytes]byte
	binary.BigEndian.PutUint64(lengthBlock[bnfr.Bytes-8:], uint64(len(value)))
	if err := writeElement(lengthBlock[:]); err != nil {
		return nil, err
	}
	for offset := 0; offset < len(value); offset += cvSemanticCommitmentChunkBytes {
		end := offset + cvSemanticCommitmentChunkBytes
		if end > len(value) {
			end = len(value)
		}
		var block [bnfr.Bytes]byte
		copy(block[bnfr.Bytes-(end-offset):], value[offset:end])
		if err := writeElement(block[:]); err != nil {
			return nil, err
		}
	}
	commitment := hasher.Sum(nil)
	if !cvValidBN254Commitment(commitment) {
		return nil, fmt.Errorf("invalid generated Poseidon2 commitment")
	}
	return append([]byte(nil), commitment...), nil
}

func cvValidLeafSemanticCommitment(commitment []byte) bool {
	return cvValidBN254Commitment(commitment)
}

func cvValidBN254Commitment(commitment []byte) bool {
	if len(commitment) != bnfr.Bytes {
		return false
	}
	var element bnfr.Element
	return element.SetBytesCanonical(commitment) == nil
}
