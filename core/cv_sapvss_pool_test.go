package core

import (
	"bytes"
	"path/filepath"
	"testing"
)

func cvPoolV2TestComponents(t *testing.T, contextDigest []byte, params cvV2Params) []cvComponentRefV2 {
	t.Helper()
	components := make([]cvComponentRefV2, params.poolSize)
	for dealer := range components {
		instance, err := cvComponentInstanceDigestV2(contextDigest, dealer)
		if err != nil {
			t.Fatal(err)
		}
		payload := []byte{byte(dealer + 1), 7, 9}
		encoded, err := cvAPDBEncodeV2(instance, payload, params.recoveryThreshold, 7, 1024)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := cvNewAPDBLockV2(encoded, []byte("component certificate"))
		if err != nil {
			t.Fatal(err)
		}
		components[dealer] = cvComponentRefV2{Header: cvComponentHeaderV2{
			ContextDigest: append([]byte(nil), contextDigest...), DealerID: dealer,
			PayloadDigest: hashBytes([]byte("payload"), payload), Instance: instance, Root: append([]byte(nil), encoded.root...),
		}, Lock: *lock}
	}
	return components
}

func TestCVPoolV2FreezesFirstPoolAndVerifiesControlCertificate(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
	}
	contextDigest := hashBytes([]byte("pool context"))
	pool, err := cvBuildPoolV2(contextDigest, 0, cvPoolV2TestComponents(t, contextDigest, params), params)
	if err != nil {
		t.Fatalf("build V2 pool: %v", err)
	}
	if _, err := cvPoolV2CanonicalBytes(pool, params); err != nil {
		t.Fatalf("canonical V2 pool: %v", err)
	}
	publicDir := filepath.Join(t.TempDir(), "public")
	secretDir := filepath.Join(t.TempDir(), "secret")
	if err := cvGenerateOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, params); err != nil {
		t.Fatal(err)
	}
	bundle, err := cvLoadOldCommitteeKeyBundleV2(publicDir, secretDir, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee, params)
	if err != nil {
		t.Fatal(err)
	}
	control, err := newTBLSThresholdSignerFromV2Material(bundle.control)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		t.Fatal(err)
	}
	shares := make(map[int][]byte, control.Threshold())
	for _, member := range cfg.OldCommittee[:control.Threshold()] {
		share, signErr := control.SignShare(member, cvPoolCertV2Domain, statement)
		if signErr != nil {
			t.Fatal(signErr)
		}
		shares[member] = share
	}
	recovered, err := control.Recover(cvPoolCertV2Domain, statement, shares)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &cvPoolCertificateV2{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: recovered}
	if err := cvVerifyPoolCertificateV2(pool, certificate, control); err != nil {
		t.Fatalf("verify V2 pool certificate: %v", err)
	}
	shareWire, err := cvPoolCertificateShareV2CanonicalBytes(&cvPoolCertificateShareV2{
		ProposerID: pool.ProposerID, PoolDigest: pool.Digest, Signature: shares[cfg.OldCommittee[0]],
	})
	if err != nil {
		t.Fatal(err)
	}
	decodedShare, err := cvDecodePoolCertificateShareV2(shareWire)
	if err != nil || decodedShare.ProposerID != pool.ProposerID || !bytes.Equal(decodedShare.PoolDigest, pool.Digest) {
		t.Fatalf("round-trip V2 pool certificate share: %v", err)
	}
	if _, err := cvDecodePoolCertificateShareV2(append(append([]byte(nil), shareWire...), 0)); err == nil {
		t.Fatal("accepted trailing V2 pool certificate share bytes")
	}

	var slot cvPoolSlotStateV2
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

func TestCVPoolV2RejectsDuplicateDealer(t *testing.T) {
	params, err := cvDeriveV2Params(cvV2ParamsTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	contextDigest := hashBytes([]byte("pool duplicate dealer context"))
	components := cvPoolV2TestComponents(t, contextDigest, params)
	components[1].Header.DealerID = components[0].Header.DealerID
	if _, err := cvBuildPoolV2(contextDigest, 0, components, params); err == nil {
		t.Fatal("built a V2 pool with duplicate dealers")
	}
}
