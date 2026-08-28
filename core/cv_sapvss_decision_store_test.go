package core

import (
	"bytes"
	"os"
	"sync"
	"testing"
)

func TestCVDecisionSignStoreV2PersistsBeforeOneShotSignature(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	root := t.TempDir()
	store, err := newCVDecisionSignStoreV2(root)
	if err != nil {
		t.Fatal(err)
	}
	member := public.OldCommittee[0]
	share, err := store.SignHandoffOnce(public.SID, public.Epoch, member, public.ContextDigest, &object.Header, &object.ARC, public.ControlSigner)
	if err != nil {
		t.Fatalf("persist and sign V2 decision: %v", err)
	}
	statement, err := cvDecisionStatementV2(public.ContextDigest, &object.Header, &object.ARC)
	if err != nil || !public.ControlSigner.VerifyShare(member, cvDecisionCertificateV2Domain, statement, share) {
		t.Fatalf("invalid persisted V2 decision share: %v", err)
	}
	record, err := store.Read(public.SID, public.Epoch, member)
	if err != nil || len(record) == 0 {
		t.Fatalf("read persisted V2 decision record: %v", err)
	}
	path, err := store.path(public.SID, public.Epoch, member)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("decision record permissions = %v / %v", info, err)
	}

	// Reconstructing the store models a process restart. The exact decision is
	// idempotent and returns the same deterministic BLS share.
	restarted, err := newCVDecisionSignStoreV2(root)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.SignHandoffOnce(public.SID, public.Epoch, member, public.ContextDigest, &object.Header, &object.ARC, public.ControlSigner)
	if err != nil || !bytes.Equal(replayed, share) {
		t.Fatalf("restart changed matching decision share: %v", err)
	}

	conflictingHeader := object.Header
	conflictingHeader.AggregateDigest = append([]byte(nil), object.Header.AggregateDigest...)
	conflictingHeader.AggregateDigest[0] ^= 1
	if _, err := restarted.SignHandoffOnce(public.SID, public.Epoch, member, public.ContextDigest, &conflictingHeader, &object.ARC, public.ControlSigner); err == nil {
		t.Fatal("signed a conflicting V2 decision after restart")
	}
	unchanged, err := restarted.Read(public.SID, public.Epoch, member)
	if err != nil || !bytes.Equal(unchanged, record) {
		t.Fatalf("conflicting decision changed persisted record: %v", err)
	}
}

func TestCVDecisionSignStoreV2ConcurrentConflictHasOneWinner(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	store, err := newCVDecisionSignStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	member := public.OldCommittee[0]
	first := object.Header
	second := object.Header
	second.AggregateDigest = append([]byte(nil), first.AggregateDigest...)
	second.AggregateDigest[0] ^= 1
	headers := []*cvAggregateHeaderV2{&first, &second}
	errors := make(chan error, len(headers))
	var wait sync.WaitGroup
	for _, header := range headers {
		wait.Add(1)
		go func(candidate *cvAggregateHeaderV2) {
			defer wait.Done()
			_, signErr := store.SignHandoffOnce(public.SID, public.Epoch, member, public.ContextDigest, candidate, &object.ARC, public.ControlSigner)
			errors <- signErr
		}(header)
	}
	wait.Wait()
	close(errors)
	successes := 0
	for err := range errors {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent conflicting decisions produced %d successful signatures, want 1", successes)
	}
}

func TestCVDecisionSignStoreV2RejectsNonLocalSignerWithoutRecord(t *testing.T) {
	object, public := cvAgreementObjectV2Fixture(t)
	store, err := newCVDecisionSignStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	public.ControlSigner.restrictSigningTo([]int{public.OldCommittee[0]})
	nonLocal := public.OldCommittee[1]
	if _, err := store.SignHandoffOnce(public.SID, public.Epoch, nonLocal, public.ContextDigest, &object.Header, &object.ARC, public.ControlSigner); err == nil {
		t.Fatal("non-local control member signed a V2 decision")
	}
	if _, err := store.Read(public.SID, public.Epoch, nonLocal); !os.IsNotExist(err) {
		t.Fatalf("failed signing attempt persisted a decision record: %v", err)
	}
}

func TestCVDecisionShareV2StrictCodec(t *testing.T) {
	share := &cvDecisionShareV2{Statement: hashBytes([]byte("decision statement")), Signature: []byte{1, 2, 3}}
	wire, err := cvDecisionShareV2CanonicalBytes(share)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeDecisionShareV2(wire)
	if err != nil || !bytes.Equal(decoded.Statement, share.Statement) || !bytes.Equal(decoded.Signature, share.Signature) {
		t.Fatalf("round-trip CV V2 decision share: %v", err)
	}
	if _, err := cvDecodeDecisionShareV2(append(append([]byte(nil), wire...), 0)); err == nil {
		t.Fatal("accepted trailing CV V2 decision share bytes")
	}
}
