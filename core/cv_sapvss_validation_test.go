package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func cvValidationTestMaterial(t *testing.T) (*cvValidatorKeyMaterialV2, Config) {
	t.Helper()
	cfg := cvV2ParamsTestConfig()
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateValidatorRegistryV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatalf("generate V2 validator registry: %v", err)
	}
	material, err := cvLoadValidatorRegistryV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatalf("load V2 validator registry: %v", err)
	}
	return material, cfg
}

func cvValidationTestHeader(t *testing.T) *cvAggregateHeaderV2 {
	t.Helper()
	context := hashBytes([]byte("validation context"))
	pool := hashBytes([]byte("validation pool"))
	selection := hashBytes([]byte("validation selection"))
	instance, err := cvAggregateInstanceDigestV2(context, 3, pool, selection)
	if err != nil {
		t.Fatal(err)
	}
	return &cvAggregateHeaderV2{ContextDigest: context, ProposerID: 3, PoolDigest: pool, SelectionDigest: selection,
		AggregateDigest: hashBytes([]byte("aggregate object")), PayloadDigest: hashBytes([]byte("aggregate payload")),
		APDBInstance: instance, APDBRoot: hashBytes([]byte("aggregate root"))}
}

func TestCVValidatorRegistryV2BindsPoPAndLocalSecrets(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateValidatorRegistryV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	material, err := cvLoadValidatorRegistryV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, []int{0, 6})
	if err != nil {
		t.Fatalf("load V2 validator registry: %v", err)
	}
	if len(material.registryHash) != 32 || len(material.publicKeys) != len(cfg.OldCommittee) || len(material.localSecrets) != 2 {
		t.Fatal("invalid loaded V2 validator material")
	}
	for _, member := range []int{0, 6} {
		info, statErr := os.Stat(cvValidatorV2SecretPath(secretDir, member))
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("validator secret permissions = %v / %v", info, statErr)
		}
	}
	path := filepath.Join(publicDir, cvValidatorRegistryV2Filename)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var registry cvValidatorRegistryV2
	if err := json.Unmarshal(raw, &registry); err != nil {
		t.Fatal(err)
	}
	proof, err := hex.DecodeString(registry.Validators[0].ProofOfPossess)
	if err != nil || len(proof) == 0 {
		t.Fatal("invalid generated PoP")
	}
	proof[len(proof)-1] ^= 1
	registry.Validators[0].ProofOfPossess = hex.EncodeToString(proof)
	mutated, err := json.MarshalIndent(registry, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(mutated, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := cvLoadValidatorRegistryV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, []int{0}); err == nil {
		t.Fatal("accepted a validator registry with a mutated PoP")
	}
}

func TestCVValidationCertificateV2UsesSampleBitmapAndAggregateBLS(t *testing.T) {
	material, _ := cvValidationTestMaterial(t)
	header := cvValidationTestHeader(t)
	sample := []int{5, 1, 6} // sampler order, deliberately not roster order
	signatures := make(map[int][]byte, 2)
	for _, member := range []int{5, 6} {
		signature, err := cvSignValidationV2(member, header, sample, material)
		if err != nil {
			t.Fatalf("sign validation vote: %v", err)
		}
		signatures[member] = signature
	}
	certificate, err := cvBuildValidationCertificateV2(header, sample, 2, signatures, material)
	if err != nil {
		t.Fatalf("build V2 validation certificate: %v", err)
	}
	if !bytes.Equal(certificate.SignerBitmap, []byte{0x05}) {
		t.Fatalf("sample-indexed signer bitmap = %08b, want 00000101", certificate.SignerBitmap)
	}
	if err := cvVerifyValidationCertificateV2(certificate, header, sample, 2, material); err != nil {
		t.Fatalf("verify V2 validation certificate: %v", err)
	}
	wire, err := cvValidationCertificateV2CanonicalBytes(certificate, sample)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeValidationCertificateV2(wire, sample)
	if err != nil || !bytes.Equal(decoded.AggregateSignature, certificate.AggregateSignature) {
		t.Fatalf("V2 validation certificate codec: %v", err)
	}
}

func TestCVValidationCertificateV2RejectsInvalidSampleAndCertificateMutations(t *testing.T) {
	material, _ := cvValidationTestMaterial(t)
	header := cvValidationTestHeader(t)
	sample := []int{4, 2, 0}
	signatures := make(map[int][]byte, 2)
	for _, member := range []int{4, 2} {
		signature, err := cvSignValidationV2(member, header, sample, material)
		if err != nil {
			t.Fatal(err)
		}
		signatures[member] = signature
	}
	certificate, err := cvBuildValidationCertificateV2(header, sample, 2, signatures, material)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*cvValidationCertificateV2){
		func(c *cvValidationCertificateV2) {
			c.SignerBitmap = append([]byte(nil), c.SignerBitmap...)
			c.SignerBitmap[0] |= 0x80
		},
		func(c *cvValidationCertificateV2) {
			c.AggregateSignature = append([]byte(nil), c.AggregateSignature...)
			c.AggregateSignature[0] ^= 1
		},
	} {
		bad := *certificate
		mutate(&bad)
		if err := cvVerifyValidationCertificateV2(&bad, header, sample, 2, material); err == nil {
			t.Fatal("accepted mutated V2 validation certificate")
		}
	}
	statement, err := cvValidationStatementV2(sample, header)
	if err != nil {
		t.Fatal(err)
	}
	nonSampleSignature, err := cvSignValidatorV2(material.localSecrets[3], cvValidationCertificateV2Domain, statement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvBuildValidationCertificateV2(header, sample, 2, map[int][]byte{4: signatures[4], 3: nonSampleSignature}, material); err == nil {
		t.Fatal("accepted a non-sample validator signature")
	}
	if err := cvVerifyValidationCertificateV2(certificate, header, []int{4, 4, 0}, 2, material); err == nil {
		t.Fatal("accepted a duplicate validator sample")
	}
	mutatedHeader := *header
	mutatedHeader.AggregateDigest = append([]byte(nil), header.AggregateDigest...)
	mutatedHeader.AggregateDigest[0] ^= 1
	if err := cvVerifyValidationCertificateV2(certificate, &mutatedHeader, sample, 2, material); err == nil {
		t.Fatal("accepted a VCert for a different aggregate header")
	}
}
