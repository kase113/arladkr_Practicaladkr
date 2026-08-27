package core

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"
)

func cvNetworkAuthV2Fixture(t *testing.T) (*cvNetworkAuthenticatorV2, *cvValidatorKeyMaterialV2, *cvReceiverKeyMaterialV2, Config) {
	t.Helper()
	cfg := cvV2ParamsTestConfig()
	validatorPublic := filepath.Join(t.TempDir(), "validator-public")
	validatorSecret := filepath.Join(t.TempDir(), "validator-secret")
	if err := cvGenerateValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee); err != nil {
		t.Fatal(err)
	}
	validators, err := cvLoadValidatorRegistryV2(validatorPublic, validatorSecret, cfg.SID, uint64(cfg.Epoch), cfg.OldCommittee, cfg.OldCommittee)
	if err != nil {
		t.Fatal(err)
	}
	receiverPublic := filepath.Join(t.TempDir(), "receiver-public")
	receiverSecret := filepath.Join(t.TempDir(), "receiver-secret")
	if err := cvGenerateReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee); err != nil {
		t.Fatal(err)
	}
	receivers, err := cvLoadReceiverRegistryV2(receiverPublic, receiverSecret, cfg.SID, uint64(cfg.Epoch), cfg.NewCommittee, cfg.NewCommittee)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := newCVNetworkAuthenticatorV2(validators, receivers)
	if err != nil {
		t.Fatal(err)
	}
	return auth, validators, receivers, cfg
}

func TestCVNetworkAuthenticationV2SeparatesBLSAndEd25519Roles(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	envelope, err := cvEncodeNetworkEnvelope(cfg.SID, cfg.Epoch, []byte("authenticated V2 payload"))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		from int
		to   int
		tag  string
	}{
		{from: cfg.OldCommittee[0], to: cfg.NewCommittee[0], tag: cvTagHandoffV2},
		{from: cfg.OldCommittee[1], to: cfg.NewCommittee[0], tag: cvTagAggregateRecoverStoreV2},
		{from: cfg.OldCommittee[1], to: cfg.NewCommittee[0], tag: cvTagAggregatePayloadV2},
		{from: cfg.NewCommittee[0], to: cfg.OldCommittee[0], tag: cvTagAggregateRecoverGetV2},
		{from: cfg.NewCommittee[0], to: cfg.OldCommittee[0], tag: cvTagAggregateRecoverCancelV2},
		{from: cfg.NewCommittee[0], to: cfg.OldCommittee[0], tag: cvTagAggregatePayloadGetV2},
		{from: cfg.NewCommittee[1], to: cfg.OldCommittee[0], tag: apvssTagLaneACK},
	}
	for _, test := range tests {
		wire, err := auth.seal(test.from, test.to, test.tag, envelope)
		if err != nil {
			t.Fatalf("seal V2 tag %s: %v", test.tag, err)
		}
		opened, err := auth.open(test.from, test.to, test.tag, wire)
		if err != nil || !bytes.Equal(opened, envelope) {
			t.Fatalf("open V2 tag %s: %v", test.tag, err)
		}
		cachedWire, err := auth.seal(test.from, test.to, test.tag, envelope)
		if err != nil || !bytes.Equal(cachedWire, wire) {
			t.Fatalf("cached seal V2 tag %s changed the authenticated wire: %v", test.tag, err)
		}
		if cachedOpened, openErr := auth.open(test.from, test.to, test.tag, cachedWire); openErr != nil ||
			!bytes.Equal(cachedOpened, envelope) {
			t.Fatalf("cached open V2 tag %s: %v", test.tag, openErr)
		}
		for name, open := range map[string]func() error{
			"from": func() error { _, openErr := auth.open(test.from+1, test.to, test.tag, wire); return openErr },
			"to":   func() error { _, openErr := auth.open(test.from, test.to+1, test.tag, wire); return openErr },
			"tag":  func() error { _, openErr := auth.open(test.from, test.to, cvTagComponentGet, wire); return openErr },
		} {
			if err := open(); err == nil {
				t.Fatalf("V2 %s signature did not bind %s", test.tag, name)
			}
		}
		mutated := append([]byte(nil), wire...)
		mutated[8] ^= 1
		if _, err := auth.open(test.from, test.to, test.tag, mutated); err == nil {
			t.Fatalf("V2 %s authenticated a mutated envelope", test.tag)
		}
		mutatedSignature := append([]byte(nil), wire...)
		mutatedSignature[len(mutatedSignature)-1] ^= 1
		if _, err := auth.open(test.from, test.to, test.tag, mutatedSignature); err == nil {
			t.Fatalf("V2 %s cache authenticated a mutated signature", test.tag)
		}
	}
}

func TestCVNetworkAuthenticationV2DoesNotUseReceiverEncryptionSecret(t *testing.T) {
	_, validators, receivers, cfg := cvNetworkAuthV2Fixture(t)
	withoutIdentity := *receivers
	withoutIdentity.localIdentitySecrets = nil
	auth, err := newCVNetworkAuthenticatorV2(validators, &withoutIdentity)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := cvEncodeNetworkEnvelope(cfg.SID, cfg.Epoch, []byte("receiver request"))
	if err != nil {
		t.Fatal(err)
	}
	receiver := cfg.NewCommittee[0]
	if _, present := receivers.localEncryptionSecrets[receiver]; !present {
		t.Fatal("test fixture has no receiver encryption secret")
	}
	if _, err := auth.seal(receiver, cfg.OldCommittee[0], cvTagAggregateRecoverGetV2, envelope); err == nil {
		t.Fatal("receiver encryption secret authenticated a V2 recovery request")
	}
}

func TestCVSAPVSSRouterAuthenticatesV2HandoffAndRecovery(t *testing.T) {
	auth, _, _, cfg := cvNetworkAuthV2Fixture(t)
	nodes := sortedUnique(append(append([]int(nil), cfg.OldCommittee...), cfg.NewCommittee...))
	transport := newCVRouterTestTransport(nodes, 16)
	oldNode := cfg.OldCommittee[0]
	newNode := cfg.NewCommittee[0]
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, cfg.SID, cfg.Epoch,
		cfg.OldCommittee, cfg.NewCommittee, []int{oldNode, newNode}, 8, auth,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	oldInbox, _ := router.Receive(oldNode)
	newInbox, _ := router.Receive(newNode)
	envelope, err := cvEncodeNetworkEnvelope(cfg.SID, cfg.Epoch, []byte("authenticated route"))
	if err != nil {
		t.Fatal(err)
	}
	handoffWire, err := auth.seal(oldNode, newNode, cvTagHandoffV2, envelope)
	if err != nil {
		t.Fatal(err)
	}
	requestWire, err := auth.seal(newNode, oldNode, cvTagAggregateRecoverGetV2, envelope)
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(newNode, Message{From: oldNode, To: newNode, Tag: cvTagHandoffV2, Body: handoffWire})
	transport.inject(oldNode, Message{From: newNode, To: oldNode, Tag: cvTagAggregateRecoverGetV2, Body: requestWire})
	transport.inject(newNode, Message{From: oldNode, To: newNode, Tag: cvTagHandoffV2, Body: envelope})
	for name, inbox := range map[string]<-chan Message{"old": oldInbox, "new": newInbox} {
		select {
		case msg := <-inbox:
			if !bytes.Equal(msg.Body, []byte("authenticated route")) {
				t.Fatalf("%s received wrong authenticated payload", name)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not receive authenticated V2 message", name)
		}
	}
	select {
	case extra := <-newInbox:
		t.Fatalf("unsigned V2 message reached receiver: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}
