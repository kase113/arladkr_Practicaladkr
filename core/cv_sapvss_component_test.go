package core

import (
	"bytes"
	"testing"
)

func TestCVComponentDescriptorCodecIsCertificateOnly(t *testing.T) {
	dispersal, _, err := cvDisperseComponent([]byte("component-codec"), 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := &cvComponentDescriptor{
		dealer:      1,
		leafDigest:  bytes.Repeat([]byte{0x11}, 32),
		dispersal:   *dispersal,
		certificate: []byte{0xcc},
	}
	wire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeComponentDescriptor(wire, []int{0, 1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if decoded.dealer != descriptor.dealer || !bytes.Equal(decoded.leafDigest, descriptor.leafDigest) ||
		!bytes.Equal(decoded.certificate, descriptor.certificate) {
		t.Fatal("compact component descriptor changed the recovered certificate")
	}
	decodedLeaf := append([]byte(nil), decoded.leafDigest...)
	decodedCertificate := append([]byte(nil), decoded.certificate...)
	for i := range wire {
		wire[i] ^= 0xff
	}
	if !bytes.Equal(decoded.leafDigest, decodedLeaf) || !bytes.Equal(decoded.certificate, decodedCertificate) {
		t.Fatal("decoded component descriptor aliases the input wire")
	}
	wire, err = cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("invalid dealer", func(t *testing.T) {
		bad := *descriptor
		bad.dealer = -1
		if _, err := cvComponentDescriptorCanonicalBytes(&bad); err == nil {
			t.Fatal("encoded a descriptor with an invalid dealer")
		}
	})
	t.Run("dealer outside roster", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptor(wire, []int{0, 2, 3}); err == nil {
			t.Fatal("accepted a descriptor dealer outside the old roster")
		}
	})
	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeComponentDescriptor(append(wire, 0), []int{0, 1, 2, 3}); err == nil {
			t.Fatal("accepted a descriptor with trailing bytes")
		}
	})
}

func TestCVComponentCodewordFingerprintRejectsCommittedNonCodewordShard(t *testing.T) {
	const totalShards, dataShards = 7, 3
	dispersal, shards, err := cvDisperseComponent(
		bytes.Repeat([]byte("component-codeword-"), 80), totalShards, dataShards,
	)
	if err != nil {
		t.Fatal(err)
	}
	for i := range shards {
		if err := cvVerifyComponentShard(dispersal, totalShards, &shards[i]); err != nil {
			t.Fatalf("valid shard %d rejected: %v", i, err)
		}
	}

	payloads := make([][]byte, totalShards)
	for i := range shards {
		payloads[i] = append([]byte(nil), shards[i].payload...)
	}
	payloads[dataShards][0] ^= 1
	root, branches := cvBuildComponentMerkle(dispersal.nonce, payloads)
	proof, err := cvBuildComponentCodewordProof(root, payloads, dataShards)
	if err != nil {
		t.Fatal(err)
	}
	badDispersal := *dispersal
	badDispersal.root = root
	badDispersal.dataFingerprints = proof
	badShard := cvComponentShard{
		index: dataShards, payload: payloads[dataShards], siblings: branches[dataShards],
	}
	if err := cvVerifyComponentShard(&badDispersal, totalShards, &badShard); err == nil {
		t.Fatal("accepted a Merkle-committed shard outside the declared RS codeword")
	}
	dataShard := cvComponentShard{index: 0, payload: payloads[0], siblings: branches[0]}
	if err := cvVerifyComponentShard(&badDispersal, totalShards, &dataShard); err != nil {
		t.Fatalf("codeword proof did not preserve an unchanged data shard: %v", err)
	}
}

func TestCVComponentDescriptorValidation(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	makeDescriptor := func(dealer int, fill byte) *cvComponentDescriptor {
		digest := bytes.Repeat([]byte{fill}, 32)
		dispersal, _, err := cvDisperseComponent([]byte{fill, fill, fill}, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := cvComponentStatementDigest(dealer, digest, dispersal)
		if err != nil {
			t.Fatal(err)
		}
		holders := append([]int(nil), cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.FOld]...)
		shares := make(map[int][]byte, len(holders))
		for _, holder := range holders {
			shares[holder], err = cfg.runtime.lockSigner.SignShare(
				holder, cvComponentLockSignatureDomain, statement,
			)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, err := cfg.runtime.lockSigner.Recover(
			cvComponentLockSignatureDomain, statement, shares,
		)
		if err != nil {
			t.Fatal(err)
		}
		return &cvComponentDescriptor{dealer: dealer, leafDigest: digest, dispersal: *dispersal, certificate: certificate}
	}

	descriptors := []*cvComponentDescriptor{
		makeDescriptor(0, 0x10),
		makeDescriptor(1, 0x11),
		makeDescriptor(2, 0x12),
	}
	for i, descriptor := range descriptors {
		if err := cvValidateComponentDescriptor(cfg, descriptor); err != nil {
			t.Fatalf("valid descriptor %d rejected: %v", i, err)
		}
	}
	compactWire, err := cvComponentDescriptorCanonicalBytes(descriptors[0])
	if err != nil {
		t.Fatal(err)
	}
	compact, err := cvDecodeComponentDescriptor(compactWire, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(compact.certificate, descriptors[0].certificate) {
		t.Fatal("compact descriptor changed recovered certificate")
	}
	t.Run("tampered recovered certificate", func(t *testing.T) {
		bad := *descriptors[0]
		bad.certificate = append([]byte(nil), bad.certificate...)
		bad.certificate[0] ^= 1
		if err := cvValidateComponentDescriptor(cfg, &bad); err == nil {
			t.Fatal("accepted a component descriptor with a bad certificate")
		}
	})
}
