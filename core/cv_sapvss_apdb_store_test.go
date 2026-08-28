package core

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestCVAPDBHolderStoreV2PersistsBeforeStoredShareAndRejectsRootConflict(t *testing.T) {
	cfg := cvV2ParamsTestConfig()
	params, err := cvDeriveV2Params(cfg)
	if err != nil {
		t.Fatal(err)
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
	signer, err := newTBLSThresholdSignerFromV2Material(bundle.apdb)
	if err != nil {
		t.Fatal(err)
	}
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("holder persistence"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, []byte("first immutable APDB payload"), params.recoveryThreshold, len(cfg.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	store, err := newCVAPDBHolderStoreV2(root)
	if err != nil {
		t.Fatal(err)
	}
	holder := cfg.OldCommittee[2]
	share, err := store.StoreAndSignOnce(cfg.SID, uint64(cfg.Epoch), holder, cfg.OldCommittee, &encoded.stores[2], len(cfg.OldCommittee), encoded.shardBytes, signer)
	if err != nil {
		t.Fatalf("persist and sign APDB store: %v", err)
	}
	statement, _ := cvAPDBStoredStatementV2(instance, encoded.root)
	if !signer.VerifyShare(holder, cvAPDBStoredDomain, statement, share) {
		t.Fatal("invalid APDB share released after persistence")
	}
	persisted, err := store.Read(cfg.SID, uint64(cfg.Epoch), holder, instance, encoded.root, len(cfg.OldCommittee), encoded.shardBytes)
	if err != nil || persisted.Index != 2 {
		t.Fatalf("read persisted APDB store: %v", err)
	}
	restarted, err := newCVAPDBHolderStoreV2(root)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.StoreAndSignOnce(cfg.SID, uint64(cfg.Epoch), holder, cfg.OldCommittee, &encoded.stores[2], len(cfg.OldCommittee), encoded.shardBytes, signer)
	if err != nil || !bytes.Equal(replayed, share) {
		t.Fatalf("matching APDB store was not restart-idempotent: %v", err)
	}
	conflicting, err := cvAPDBEncodeV2(instance, []byte("conflicting APDB payload"), params.recoveryThreshold, len(cfg.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.StoreAndSignOnce(cfg.SID, uint64(cfg.Epoch), holder, cfg.OldCommittee, &conflicting.stores[2], len(cfg.OldCommittee), conflicting.shardBytes, signer); err == nil {
		t.Fatal("persisted and signed a conflicting root for one APDB instance")
	}
	wrongIndex := encoded.stores[1]
	if _, err := restarted.StoreAndSignOnce(cfg.SID, uint64(cfg.Epoch), holder, cfg.OldCommittee, &wrongIndex, len(cfg.OldCommittee), encoded.shardBytes, signer); err == nil {
		t.Fatal("signed an APDB store at another holder's roster index")
	}
}

func TestCVAPDBHolderStoreV2AuthorizedAggregateReadBindsHandoffLock(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	context := public.ContextDigest
	poolDigest := hashBytes([]byte("authorized APDB pool"))
	selectionDigest := hashBytes([]byte("authorized APDB selection"))
	proposer := public.OldCommittee[0]
	instance, err := cvAggregateInstanceDigestV2(context, proposer, poolDigest, selectionDigest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, []byte("decision-authorized aggregate payload"), public.Params.recoveryThreshold, len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	header := cvAggregateHeaderV2{ContextDigest: context, ProposerID: proposer, PoolDigest: poolDigest, SelectionDigest: selectionDigest,
		AggregateDigest: hashBytes([]byte("authorized aggregate")), PayloadDigest: hashBytes([]byte("authorized payload")),
		APDBInstance: instance, APDBRoot: encoded.root}
	storedStatement, err := cvAPDBStoredStatementV2(instance, encoded.root)
	if err != nil {
		t.Fatal(err)
	}
	arc := cvAPDBLockV2{InstanceDigest: instance, Root: encoded.root,
		Certificate: cvRecoverThresholdCertificateV2ForTest(t, public.APDBSigner, public.OldCommittee, cvAPDBStoredDomain, storedStatement)}
	decisionStatement, err := cvDecisionStatementV2(context, &header, &arc)
	if err != nil {
		t.Fatal(err)
	}
	handoff := cvHandoffV2{ContextDigest: context, Header: header, ARC: arc,
		DecCert: cvRecoverThresholdCertificateV2ForTest(t, public.ControlSigner, public.OldCommittee, cvDecisionCertificateV2Domain, decisionStatement)}
	requestWire, err := cvAggregateRecoveryRequestV2CanonicalBytes(&cvAggregateRecoveryRequestV2{Handoff: handoff})
	if err != nil {
		t.Fatal(err)
	}
	holder := public.OldCommittee[3]
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := holderStore.StoreAndSignOnce(public.SID, public.Epoch, holder, public.OldCommittee, &encoded.stores[3], len(public.OldCommittee), encoded.shardBytes, public.APDBSigner); err != nil {
		t.Fatal(err)
	}
	got, err := holderStore.ReadAuthorizedAggregate(public.SID, public.Epoch, holder, requestWire, context,
		len(public.OldCommittee), encoded.shardBytes, public.APDBSigner, public.ControlSigner)
	if err != nil || got.Index != 3 || !bytes.Equal(got.Root, encoded.root) {
		t.Fatalf("authorized aggregate store read: %v", err)
	}
	wrongContext := append([]byte(nil), context...)
	wrongContext[0] ^= 1
	if _, err := holderStore.ReadAuthorizedAggregate(public.SID, public.Epoch, holder, requestWire, wrongContext,
		len(public.OldCommittee), encoded.shardBytes, public.APDBSigner, public.ControlSigner); err == nil {
		t.Fatal("served aggregate APDB store under the wrong handoff context")
	}
}
