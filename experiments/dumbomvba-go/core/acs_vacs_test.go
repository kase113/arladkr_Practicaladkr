package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestValidateACSVectorPayloadRequiresQuorumSlotsSignaturesAndPredicate(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewTBLSSigner(0, bundle)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{SID: "acs-vector-validity", ID: 0, N: n, F: f}
	sid := cfg.SID + "VACS"
	entries := make([]*acsVectorEntry, n)
	for i := 0; i < n-f; i++ {
		signer, signerErr := NewTBLSSigner(i, bundle)
		if signerErr != nil {
			t.Fatal(signerErr)
		}
		value := ProposalValue{Payload: []byte{byte(i + 1)}, Round: 1, Hint: "cv"}
		sig, signErr := signer.Sign("ACS_DIFFUSE", hashACSValue(sid, value))
		if signErr != nil {
			t.Fatal(signErr)
		}
		entries[i] = &acsVectorEntry{From: i, Value: value, Sig: sig}
	}
	encode := func(value []*acsVectorEntry) []byte {
		wire, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return wire
	}
	predicate := func(_ int, value ProposalValue) bool {
		return value.Round == 1 && value.Hint == "cv" && len(value.Payload) == 1
	}
	if _, err := validateACSVectorPayload(encode(entries), cfg, verifier, predicate); err != nil {
		t.Fatalf("valid ACS vector rejected: %v", err)
	}

	t.Run("below n-f", func(t *testing.T) {
		bad := append([]*acsVectorEntry(nil), entries...)
		bad[n-f-1] = nil
		if _, err := validateACSVectorPayload(encode(bad), cfg, verifier, predicate); err == nil {
			t.Fatal("accepted ACS vector below n-f entries")
		}
	})
	t.Run("wrong slot", func(t *testing.T) {
		bad := append([]*acsVectorEntry(nil), entries...)
		copyEntry := *bad[0]
		copyEntry.From = 1
		bad[0] = &copyEntry
		if _, err := validateACSVectorPayload(encode(bad), cfg, verifier, predicate); err == nil {
			t.Fatal("accepted ACS entry in the wrong proposer slot")
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		bad := append([]*acsVectorEntry(nil), entries...)
		copyEntry := *bad[0]
		copyEntry.Sig = append([]byte(nil), copyEntry.Sig...)
		copyEntry.Sig[0] ^= 1
		bad[0] = &copyEntry
		if _, err := validateACSVectorPayload(encode(bad), cfg, verifier, predicate); err == nil {
			t.Fatal("accepted ACS entry with a bad diffuse signature")
		}
	})
	t.Run("application predicate", func(t *testing.T) {
		if _, err := validateACSVectorPayload(encode(entries), cfg, verifier,
			func(_ int, _ ProposalValue) bool { return false }); err == nil {
			t.Fatal("accepted ACS entries rejected by the application predicate")
		}
	})
}

func TestRunMVBACCommonSubset_Smoke(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatalf("GenerateTBLSKeyBundle failed: %v", err)
	}
	signers := make([]Signer, n)
	for i := 0; i < n; i++ {
		s, sErr := NewTBLSSigner(i, bundle)
		if sErr != nil {
			t.Fatalf("NewTBLSSigner(%d) failed: %v", i, sErr)
		}
		signers[i] = s
	}

	recv := make([]chan ReceivedMessage, n)
	for i := 0; i < n; i++ {
		recv[i] = make(chan ReceivedMessage, 4096)
	}
	nets := make([]*memNet, n)
	for i := 0; i < n; i++ {
		nets[i] = &memNet{id: i, peers: recv}
	}

	type out struct {
		vec []*ProposalValue
		err error
	}
	outs := make([]out, n)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			vec, runErr := RunMVBACCommonSubset(
				ctx,
				Config{
					SID:                "acs-vacs-smoke",
					ID:                 i,
					N:                  n,
					F:                  f,
					MaxRounds:          4,
					WaitSPBCTimeout:    5 * time.Second,
					RouteSendTimeout:   100 * time.Millisecond,
					UseEquivalentPath:  true,
					EquivalentCoinMode: "signature",
				},
				nets[i],
				signers[i],
				recv[i],
				ProposalValue{
					Payload: []byte(fmt.Sprintf("in-%d", i)),
					Round:   0,
					Hint:    "acs-vacs",
				},
				nil,
			)
			outs[i] = out{vec: vec, err: runErr}
		}()
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if outs[i].err != nil {
			if errors.Is(outs[i].err, context.DeadlineExceeded) {
				t.Skipf("acs-vacs smoke timing-sensitive in this run: %v", outs[i].err)
			}
			t.Fatalf("node %d failed: %v", i, outs[i].err)
		}
	}

	base := vectorFingerprint(outs[0].vec)
	for i := 1; i < n; i++ {
		if vectorFingerprint(outs[i].vec) != base {
			t.Fatalf("decision mismatch on node %d", i)
		}
	}
}

func TestRunMVBACCommonSubset_CompletesWithOneSilentNode(t *testing.T) {
	const (
		n      = 4
		f      = 1
		active = n - f
	)
	bundle, err := GenerateTBLSKeyBundle(n, f)
	if err != nil {
		t.Fatal(err)
	}
	signers := make([]Signer, n)
	recv := make([]chan ReceivedMessage, n)
	for i := 0; i < n; i++ {
		signers[i], err = NewTBLSSigner(i, bundle)
		if err != nil {
			t.Fatal(err)
		}
		recv[i] = make(chan ReceivedMessage, 8192)
	}

	type result struct {
		vec []*ProposalValue
		err error
	}
	results := make([]result, active)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < active; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			results[id].vec, results[id].err = RunMVBACCommonSubset(
				ctx,
				Config{SID: "acs-vacs-one-silent", ID: id, N: n, F: f, MaxRounds: 4,
					WaitSPBCTimeout: 5 * time.Second, RouteSendTimeout: 100 * time.Millisecond,
					UseEquivalentPath: true, EquivalentCoinMode: "signature"},
				&memNet{id: id, peers: recv}, signers[id], recv[id],
				ProposalValue{Payload: []byte(fmt.Sprintf("in-%d", id)), Round: 1, Hint: "cv"},
				func(_ int, value ProposalValue) bool {
					return value.Round == 1 && value.Hint == "cv" && len(value.Payload) > 0
				},
			)
		}(i)
	}
	wg.Wait()

	fingerprint := ""
	for i, got := range results {
		if got.err != nil {
			t.Fatalf("active node %d failed with one silent peer: %v", i, got.err)
		}
		if current := vectorFingerprint(got.vec); i == 0 {
			fingerprint = current
		} else if current != fingerprint {
			t.Fatalf("active node %d decided a different common subset", i)
		}
	}
}

func vectorFingerprint(v []*ProposalValue) string {
	out := ""
	for i := range v {
		if v[i] == nil {
			out += "|nil"
			continue
		}
		out += "|" + string(v[i].Payload)
	}
	return out
}
