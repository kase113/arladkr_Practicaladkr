package core

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestAPDBThresholdCertificateRoundTrip(t *testing.T) {
	old := []int{0, 1, 2, 3, 4, 5, 6}
	keys, err := generateThresholdCoinKeys(old, 2)
	if err != nil {
		t.Fatal(err)
	}
	cert := APDBCertificate{
		Sender: 1, Root: make([]byte, 32), ValueDigest: make([]byte, 32),
		MerkleRoot: make([]byte, 32), DataShards: 3, TotalShards: 7,
	}
	cert.Root = apdbCommitmentRoot(cert.Sender, cert.ValueDigest, cert.MerkleRoot, cert.DataShards, cert.TotalShards)
	receipts := make([]APDBReceipt, 0, keys.threshold)
	for _, holder := range old[:keys.threshold] {
		share, signErr := apdbThresholdShare(keys, holder, cert)
		if signErr != nil {
			t.Fatal(signErr)
		}
		receipts = append(receipts, APDBReceipt{NodeID: holder, Sender: cert.Sender, ThresholdShare: share})
	}
	// A strict multiprocess dealer has only its own private share. Threshold
	// recovery must not assume that node 0's private share is locally loaded.
	localDealerKeys := *keys
	localDealerKeys.privateShare = map[int]fr.Element{cert.Sender: keys.privateShare[cert.Sender]}
	sig, err := recoverAPDBThresholdSignature(&localDealerKeys, cert, receipts)
	if err != nil {
		t.Fatal(err)
	}
	cert.ThresholdSignature = sig
	if !verifyAPDBThresholdCertificate(cert, 2, keys.groupPublic.Marshal()) {
		t.Fatal("compact APDB certificate without repeated setup key did not verify")
	}
	cert.ThresholdPublic = keys.groupPublic.Marshal()
	if !verifyAPDBThresholdCertificate(cert, 2, keys.groupPublic.Marshal()) {
		t.Fatal("legacy compact APDB certificate with matching setup key did not verify")
	}
	otherKeys, err := generateThresholdCoinKeys(old, 2)
	if err != nil {
		t.Fatal(err)
	}
	if verifyAPDBThresholdCertificate(cert, 2, otherKeys.groupPublic.Marshal()) {
		t.Fatal("compact APDB certificate verified under an untrusted setup key")
	}
	if verifyAPDBCertificate(cert, nil, 2) {
		t.Fatal("generic certificate verifier trusted a self-supplied threshold key")
	}
	cert.Root[0] ^= 1
	if verifyAPDBThresholdCertificate(cert, 2, keys.groupPublic.Marshal()) {
		t.Fatal("mutated compact APDB certificate verified")
	}
}
