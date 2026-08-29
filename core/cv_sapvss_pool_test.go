package core

import (
	"bytes"
	"path/filepath"
	"testing"
)

func cvPoolScalarTestComponents(t *testing.T, contextDigest []byte, params cvScalarParams) []cvComponentRefScalar {
	t.Helper()
	components := make([]cvComponentRefScalar, params.poolSize)
	for dealer := range components {
		instance, err := cvComponentInstanceDigestScalar(contextDigest, dealer)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte(dealer + 1), 7, 9}
		encoded, err := cvAPDBEncodeScalar(instance, payload, params.recoveryThreshold, 7, 1024)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := cvNewAPDBLockScalar(encoded, []byte("component certificate"))
		if err != nil {
			t.Fatal(err)
		}
		components[dealer] = cvComponentRefScalar{Header: cvComponentHeaderScalar{
			ContextDigest: append([]byte(nil), contextDigest...), DealerID: dealer,
			PayloadDigest: hashBytes([]byte("payload"), payload), Instance: instance, Root: append([]byte(nil), encoded.root...),
		}, Lock: *lock}
	}
	return components
}

func TestCVPoolScalarFreezesFirstPoolAndVerifiesControlCertificate(t *testing.T) {
	cfg := cvScalarParamsTestConfig()
	params, err := cvDeriveScalarParams(cfg)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest := hashBytes([]byte("pool context"))
	pool, err := cvBuildPoolScalar(contextDigest, 0, cvPoolScalarTestComponents(t, contextDigest, params), params)
	if err != nil {
		t.Fatalf("build V2 pool: %v", err)
	}
	if _, err := cvPoolScalarCanonicalBytes(pool, params); err != nil {
		t.Fatalf("canonical V2 pool: %v", err)
	}
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateOldCommitteeKeyBundleScalar(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleScalar(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newTBLSThresholdSignerFromScalarMaterial(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvPoolCertificateStatementScalar(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[int][]byte, control.Threshold())
	for _, member := range cfg.OldCommittee[:control.Threshold()] {
		share, signErr := control.SignShare(member, cvPoolCertScalarDomain, statement)
		if signErr != nil {
			t.Fatal(signErr)
		}
		shares[member] = share
	}
	recovered, err := control.Recover(cvPoolCertScalarDomain, statement, shares)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &cvPoolCertificateScalar{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: recovered}
	if err := cvVerifyPoolCertificateScalar(pool, certificate, control); err != nil {
		t.Fatalf("verify V2 pool certificate: %v", err)
	}
	shareWire, err := cvPoolCertificateShareScalarCanonicalBytes(&cvPoolCertificateShareScalar{
		ProposerID: pool.ProposerID, PoolDigest: pool.Digest, Signature: shares[cfg.OldCommittee[0]],
	})
	if err != nil {
		t.Fatal(err)
	}
	decodedShare, err := cvDecodePoolCertificateShareScalar(shareWire)
	if err != nil || decodedShare.ProposerID != pool.ProposerID || !bytes.Equal(decodedShare.PoolDigest, pool.Digest) {
		t.Fatalf("round-trip V2 pool certificate share: %v", err)
	}
	if _, err := cvDecodePoolCertificateShareScalar(append(append([]byte(nil), shareWire...), 0)); err == nil {
		t.Fatal("accepted trailing V2 pool certificate share bytes")
	}

	var slot cvPoolSlotStateScalar
	if err := slot.observePool(pool); err != nil || slot.observePool(pool) != nil {
		t.Fatalf("observe matching V2 pool: %v", err)
	}
	if err := slot.markSigned(pool.Digest); err != nil {
		t.Fatal(err)
	}
	if err := slot.observeCertificate(certificate); err != nil || !slot.certSeen {
		t.Fatalf("observe matching V2 pool certificate: %v", err)
	}
	conflicting := *pool
	conflicting.Digest = append([]byte(nil), pool.Digest...)
	conflicting.Digest[0] ^= 1
	if err := slot.observePool(&conflicting); err == nil {
		t.Fatal("accepted a conflicting V2 pool after first pool freeze")
	}
	if bytes.Equal(pool.Digest, conflicting.Digest) {
		t.Fatal("pool mutation did not apply")
	}
}

func TestCVPoolScalarRejectsDuplicateDealer(t *testing.T) {
	params, err := cvDeriveScalarParams(cvScalarParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	contextDigest := hashBytes([]byte("pool duplicate dealer context"))
	components := cvPoolScalarTestComponents(t, contextDigest, params)
	components[1].Header.DealerID = components[0].Header.DealerID
	if _, err := cvBuildPoolScalar(contextDigest, 0, components, params); err == nil {
		t.Fatal("built a V2 pool with duplicate dealers")
	}
}
