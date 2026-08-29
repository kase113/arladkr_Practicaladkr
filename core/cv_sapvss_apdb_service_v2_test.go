package core

import (
	"bytes"
	"testing"
)

func TestCVAPDBServiceV2LockPDAndComponentRecovery(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	payload := []byte("network-service APDB LockPD and validated recovery")
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("service round trip"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, payload, public.Params.recoveryThreshold, len(public.OldCommittee), 2048)
	if err != nil {
		t.Fatal(err)
	}
	lockCollector, err := newCVAPDBLockCollectorV2(encoded, public.OldCommittee, public.APDBSigner)
	if err != nil {
		t.Fatal(err)
	}
	if !equalInts(lockCollector.StoreRecipients(), public.OldCommittee) {
		t.Fatal("LockPD did not target every old holder")
	}
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proposer := public.OldCommittee[0]
	for index, holder := range public.OldCommittee[:public.APDBSigner.Threshold()] {
		offer, err := lockCollector.StoreOffer(holder)
		if err != nil {
			t.Fatal(err)
		}
		response, err := cvHandleAPDBStoreOfferV2(public.SID, public.Epoch, proposer, holder, public.OldCommittee,
			offer, len(public.OldCommittee), encoded.shardBytes, holderStore, public.APDBSigner)
		if err != nil {
			t.Fatalf("holder %d store handler: %v", holder, err)
		}
		complete, err := lockCollector.AddStoredShare(holder, response)
		if err != nil || complete != (index+1 == public.APDBSigner.Threshold()) {
			t.Fatalf("collect holder %d share: complete=%v err=%v", holder, complete, err)
		}
		if index == 0 {
			if _, err := lockCollector.AddStoredShare(holder, response); err != nil {
				t.Fatalf("matching STORED share was not idempotent: %v", err)
			}
		}
	}
	lock, err := lockCollector.RecoverLock()
	if err != nil || cvVerifyAPDBLockV2(lock, public.APDBSigner) != nil {
		t.Fatalf("recover APDB lock: %v", err)
	}
	request, err := cvAPDBLockV2CanonicalBytes(lock)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := newCVAPDBRecoveryCollectorV2(lock, public.OldCommittee, public.Params.recoveryThreshold,
		encoded.shardBytes, 2048, public.APDBSigner, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index, holder := range public.OldCommittee[:public.Params.recoveryThreshold] {
		response, err := cvHandleAPDBRecoveryRequestV2(public.SID, public.Epoch, proposer, holder,
			public.OldCommittee, request, len(public.OldCommittee), encoded.shardBytes, holderStore, public.APDBSigner)
		if err != nil {
			t.Fatalf("holder %d recovery handler: %v", holder, err)
		}
		complete, err := recovery.AddStore(holder, response)
		if err != nil || complete != (index+1 == public.Params.recoveryThreshold) {
			t.Fatalf("collect holder %d store: complete=%v err=%v", holder, complete, err)
		}
	}
	recovered, err := recovery.Recover()
	if err != nil || !bytes.Equal(recovered, payload) {
		t.Fatalf("recover component APDB payload: %v", err)
	}
}

func TestCVAPDBServiceV2RejectsShareReplayAndUnauthorizedParticipants(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("service mutations"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, []byte("service mutation payload"), public.Params.recoveryThreshold,
		len(public.OldCommittee), 1024)
	if err != nil {
		t.Fatal(err)
	}
	collector, err := newCVAPDBLockCollectorV2(encoded, public.OldCommittee, public.APDBSigner)
	if err != nil {
		t.Fatal(err)
	}
	holderStore, err := newCVAPDBHolderStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	holder := public.OldCommittee[0]
	offer, err := collector.StoreOffer(holder)
	if err != nil {
		t.Fatal(err)
	}
	response, err := cvHandleAPDBStoreOfferV2(public.SID, public.Epoch, public.OldCommittee[1], holder,
		public.OldCommittee, offer, len(public.OldCommittee), encoded.shardBytes, holderStore, public.APDBSigner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.AddStoredShare(public.OldCommittee[1], response); err == nil {
		t.Fatal("accepted a holder signature share replayed as another member")
	}
	if _, err := collector.AddStoredShare(holder, append(append([]byte(nil), response...), 0)); err == nil {
		t.Fatal("accepted a STORED share with trailing bytes")
	}
	if _, err := cvHandleAPDBStoreOfferV2(public.SID, public.Epoch, 9999, holder, public.OldCommittee,
		offer, len(public.OldCommittee), encoded.shardBytes, holderStore, public.APDBSigner); err == nil {
		t.Fatal("accepted APDB store offer from outside the old roster")
	}
	if _, err := cvHandleAPDBRecoveryRequestV2(public.SID, public.Epoch, 9999, holder, public.OldCommittee,
		[]byte("invalid"), len(public.OldCommittee), encoded.shardBytes, holderStore, public.APDBSigner); err == nil {
		t.Fatal("accepted component APDB recovery from outside the old roster")
	}
}
