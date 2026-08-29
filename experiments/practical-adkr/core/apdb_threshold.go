package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	dmvba "dumbomvba_go/core"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const apdbThresholdDomain = "PRACTICAL_ADKR_APDB_LOCK_V1"

// apdbThresholdDigest binds the compact proof to exactly the same APDB
// commitment metadata used to validate receipts.
func apdbThresholdDigest(cert APDBCertificate) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-APDB-THRESHOLD-LOCK-V1"))
	var numbers [24]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(cert.Sender))
	binary.BigEndian.PutUint64(numbers[8:16], uint64(cert.DataShards))
	binary.BigEndian.PutUint64(numbers[16:], uint64(cert.TotalShards))
	h.Write(numbers[:])
	h.Write(cert.Root)
	h.Write(cert.ValueDigest)
	h.Write(cert.MerkleRoot)
	return h.Sum(nil)
}

func apdbThresholdShare(keys *thresholdCoinKeySet, holder int, cert APDBCertificate) ([]byte, error) {
	if keys == nil {
		return nil, fmt.Errorf("APDB threshold keys unavailable")
	}
	signer, err := keys.signer(holder)
	if err != nil {
		return nil, err
	}
	return signer.Sign(apdbThresholdDomain, apdbThresholdDigest(cert))
}

func recoverAPDBThresholdSignature(keys *thresholdCoinKeySet, cert APDBCertificate, receipts []APDBReceipt) ([]byte, error) {
	if keys == nil {
		return nil, fmt.Errorf("APDB threshold keys unavailable")
	}
	shares := make(map[int][]byte, len(receipts))
	for _, receipt := range receipts {
		if len(receipt.ThresholdShare) == 0 {
			continue
		}
		index, ok := keys.nodeIndex[receipt.NodeID]
		if !ok {
			continue
		}
		shares[index] = receipt.ThresholdShare
	}
	signer, err := keys.signer(cert.Sender)
	if err != nil {
		return nil, err
	}
	return signer.Recover(apdbThresholdDomain, apdbThresholdDigest(cert), shares)
}

func verifyAPDBThresholdCertificate(cert APDBCertificate, f int, trustedPublic []byte) bool {
	if len(cert.Root) != sha256.Size || len(cert.ValueDigest) != sha256.Size || len(cert.MerkleRoot) != sha256.Size ||
		len(cert.ThresholdSignature) == 0 || len(trustedPublic) == 0 ||
		(len(cert.ThresholdPublic) > 0 && !equalBytes(cert.ThresholdPublic, trustedPublic)) ||
		cert.TotalShards <= 0 || f < 0 || cert.TotalShards < 3*f+1 ||
		cert.DataShards != cert.TotalShards-2*f || !equalBytes(cert.Root, apdbCommitmentRoot(cert.Sender, cert.ValueDigest, cert.MerkleRoot, cert.DataShards, cert.TotalShards)) {
		return false
	}
	var group bls12381.G2Affine
	if err := group.Unmarshal(trustedPublic); err != nil {
		return false
	}
	var zero fr.Element
	threshold := cert.TotalShards - f
	verifier := dmvba.NewBLS12381Signer(0, zero, group, nil, cert.TotalShards, threshold)
	return verifier.VerifyRecovered(apdbThresholdDomain, apdbThresholdDigest(cert), cert.ThresholdSignature)
}

func trustedAPDBThresholdPublic(keys *thresholdCoinKeySet) []byte {
	if keys == nil {
		return nil
	}
	return keys.groupPublic.Marshal()
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
