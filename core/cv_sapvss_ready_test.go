package core

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

type cvFailingFreshArtifactStore struct{}

func TestCVPrimaryMaterializerRotatesByEpoch(t *testing.T) {
	cfg := Config{OldCommittee: []int{7, 3, 11}}
	want := []int{3, 7, 11, 3}
	for epoch, expected := range want {
		cfg.Epoch = epoch + 1
		if got := cvPrimaryMaterializer(cfg); got != expected {
			t.Fatalf("epoch %d primary=%d, want %d", cfg.Epoch, got, expected)
		}
	}
}

func (cvFailingFreshArtifactStore) Put(string, int, []byte, int, []byte) error {
	return errors.New("injected fresh-store failure")
}

func (cvFailingFreshArtifactStore) Read(string, int, []byte, int) ([]byte, error) {
	return nil, errors.New("injected fresh-store failure")
}

func TestCVComponentReadyCertificateCodecAndThreshold(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	descriptors := make([]*cvComponentDescriptor, len(cfg.OldCommittee)-cfg.FOld)
	for i := range descriptors {
		digest := bytes.Repeat([]byte{byte(i + 1)}, 32)
		dispersal, _, err := cvDisperseComponent([]byte{byte(i + 1)}, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := cvComponentStatementDigest(i, digest, dispersal)
		if err != nil {
			t.Fatal(err)
		}
		holders := append([]int(nil), cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.FOld]...)
		shares := make(map[int][]byte, len(holders))
		for _, holder := range holders {
			shares[holder], err = cfg.runtime.lockSigner.SignShare(holder, cvComponentLockSignatureDomain, statement)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, err := cfg.runtime.lockSigner.Recover(cvComponentLockSignatureDomain, statement, shares)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptor{dealer: i, leafDigest: digest, dispersal: *dispersal, certificate: certificate}
	}
	certificate, err := cvBuildComponentReadyCertificate(0, descriptors)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := cvComponentReadyCertificateCanonicalBytes(certificate)
	if err != nil {
		t.Fatal(err)
	}
	cachedWires := make([][]byte, len(certificate.references))
	for i := range certificate.references {
		cachedWires[i] = certificate.references[i].descriptorWire
	}
	fastCertificate, fastWire, err := cvBuildComponentReadyCertificateWireFromValidatedWires(0, descriptors, cachedWires)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fastCertificate.root, certificate.root) || !bytes.Equal(fastWire, wire) {
		t.Fatal("cached ReadyCert builder changed canonical output")
	}
	decoded, err := cvDecodeComponentReadyCertificate(wire, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.proposer != certificate.proposer || !bytes.Equal(decoded.root, certificate.root) || len(decoded.references) != len(descriptors) {
		t.Fatal("ReadyCert did not round-trip canonically")
	}

	t.Run("trailing bytes", func(t *testing.T) {
		if _, err := cvDecodeComponentReadyCertificate(append(wire, 0), cfg); err == nil {
			t.Fatal("accepted ReadyCert with trailing bytes")
		}
	})
	t.Run("root mutation", func(t *testing.T) {
		bad := append([]byte(nil), wire...)
		bad[len(bad)-1] ^= 1
		if _, err := cvDecodeComponentReadyCertificate(bad, cfg); err == nil {
			t.Fatal("accepted ReadyCert with a mutated root")
		}
	})
	t.Run("below n-f", func(t *testing.T) {
		short, err := cvBuildComponentReadyCertificate(0, descriptors[:len(descriptors)-1])
		if err != nil {
			t.Fatal(err)
		}
		shortWire, err := cvComponentReadyCertificateCanonicalBytes(short)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cvDecodeComponentReadyCertificate(shortWire, cfg); err == nil {
			t.Fatal("accepted ReadyCert below n-f references")
		}
	})
	t.Run("duplicate dealer", func(t *testing.T) {
		duplicate := append([]*cvComponentDescriptor(nil), descriptors...)
		duplicate[1] = duplicate[0]
		if _, err := cvBuildComponentReadyCertificate(0, duplicate); err == nil {
			t.Fatal("built ReadyCert with duplicate dealers")
		}
	})
	t.Run("invalid embedded component certificate", func(t *testing.T) {
		mutated := append([]*cvComponentDescriptor(nil), descriptors...)
		copyDescriptor := *descriptors[0]
		copyDescriptor.certificate = append([]byte(nil), descriptors[0].certificate...)
		copyDescriptor.certificate[0] ^= 1
		mutated[0] = &copyDescriptor
		badCertificate, err := cvBuildComponentReadyCertificate(0, mutated)
		if err != nil {
			t.Fatal(err)
		}
		badWire, err := cvComponentReadyCertificateCanonicalBytes(badCertificate)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := cvDecodeComponentReadyCertificate(badWire, cfg); err == nil {
			t.Fatal("accepted ReadyCert with an invalid embedded component certificate")
		}
	})
}

func TestCVComponentStatementClaimRejectsEquivocation(t *testing.T) {
	service := &cvComponentService{componentStatementByDealer: make(map[int][]byte)}
	first := bytes.Repeat([]byte{0x11}, 32)
	second := bytes.Repeat([]byte{0x22}, 32)
	if !service.claimComponentStatement(3, first) || !service.claimComponentStatement(3, first) {
		t.Fatal("idempotent component statement claim failed")
	}
	if service.claimComponentStatement(3, second) {
		t.Fatal("accepted conflicting component statement for one dealer")
	}
}

func TestCVReadyPoolMustMatchCurrentCanonicalPrefix(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	descriptors := make([]*cvComponentDescriptor, len(cfg.OldCommittee))
	for i := range descriptors {
		digest := bytes.Repeat([]byte{byte(i + 1)}, 32)
		dispersal, _, err := cvDisperseComponent([]byte{byte(i + 1)}, len(cfg.OldCommittee), len(cfg.OldCommittee)-2*cfg.FOld)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := cvComponentStatementDigest(i, digest, dispersal)
		if err != nil {
			t.Fatal(err)
		}
		shares := make(map[int][]byte)
		for _, holder := range cfg.runtime.oldOrder[:len(cfg.OldCommittee)-cfg.FOld] {
			shares[holder], err = cfg.runtime.lockSigner.SignShare(holder, cvComponentLockSignatureDomain, statement)
			if err != nil {
				t.Fatal(err)
			}
		}
		certificate, err := cfg.runtime.lockSigner.Recover(cvComponentLockSignatureDomain, statement, shares)
		if err != nil {
			t.Fatal(err)
		}
		descriptors[i] = &cvComponentDescriptor{dealer: i, leafDigest: digest, dispersal: *dispersal, certificate: certificate}
	}
	service := &cvComponentService{cfg: cfg, componentDescriptors: make(map[int]*cvComponentDescriptor)}
	for _, descriptor := range descriptors {
		service.componentDescriptors[descriptor.dealer] = descriptor
	}
	ready := len(cfg.OldCommittee) - cfg.FOld
	if !service.isCanonicalReadyPool(descriptors[:ready]) {
		t.Fatal("rejected the current canonical ReadyCert prefix")
	}
	if service.isCanonicalReadyPool(descriptors[1:]) {
		t.Fatal("accepted a non-canonical ReadyCert combination")
	}
}

func TestCVLocalARCShareIsReusedPerHeader(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	service := &cvComponentService{
		cfg:                     cfg,
		localNode:               cfg.OldCommittee[0],
		localARCShareByHeader:   make(map[string][]byte),
		persistedFreshArtifacts: make(map[string]struct{}),
	}
	digest := bytes.Repeat([]byte{0x44}, 32)
	service.persistedFreshArtifacts[fmt.Sprintf("%x/%d", digest, service.localNode)] = struct{}{}
	first, err := service.localARCShare(digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.localARCShare(digest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || len(service.localARCShareByHeader) != 1 {
		t.Fatal("ARC share was not reused for the same header")
	}
	otherDigest := bytes.Repeat([]byte{0x55}, 32)
	service.persistedFreshArtifacts[fmt.Sprintf("%x/%d", otherDigest, service.localNode)] = struct{}{}
	other, err := service.localARCShare(otherDigest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, other) || len(service.localARCShareByHeader) != 2 {
		t.Fatal("service did not independently sign two distinct valid headers")
	}
}

func TestCVLocalARCShareRequiresSuccessfulPersistence(t *testing.T) {
	cfg, _, _, _ := cvM4Fixture(t)
	if err := ensureRuntime(&cfg); err != nil {
		t.Fatal(err)
	}
	service := &cvComponentService{
		cfg: cfg, localNode: cfg.OldCommittee[0], freshStore: cvFailingFreshArtifactStore{},
		localARCShareByHeader: make(map[string][]byte), persistedFreshArtifacts: make(map[string]struct{}),
	}
	digest := bytes.Repeat([]byte{0x66}, 32)
	if _, err := service.localARCShare(digest); err == nil {
		t.Fatal("signed an ARC share without a persisted fresh artifact")
	}
	if err := service.persistFreshArtifact(digest, []byte("fresh artifact")); err == nil {
		t.Fatal("injected fresh-store failure was ignored")
	}
	if _, err := service.localARCShare(digest); err == nil {
		t.Fatal("signed an ARC share after failed fresh-artifact persistence")
	}
	if len(service.localARCShareByHeader) != 0 || len(service.persistedFreshArtifacts) != 0 {
		t.Fatal("failed persistence left an ARC share or persisted token")
	}
}
