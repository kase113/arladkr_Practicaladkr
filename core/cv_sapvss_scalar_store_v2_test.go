package core

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func TestCVScalarStoreV2PersistsCanonicalShareOnce(t *testing.T) {
	aggregate, context, params, receivers := cvAggregateForShareV2Fixture(t)
	receiverID := context.NewRoster[0]
	scalar, output, err := cvDecryptAggregateShareV2(aggregate, context, params, receiverID, 1,
		&receivers.encryptionPublicKeys[0], receivers.localEncryptionSecrets[receiverID])
	if err != nil {
		t.Fatal(err)
	}
	store, err := newCVScalarStoreV2(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistOnce(context.SID, context.Epoch, receiverID, aggregate.Digest, scalar, output); err != nil {
		t.Fatal(err)
	}
	state, err := store.Read(context.SID, context.Epoch, receiverID)
	if err != nil || !bytes.Equal(state.AggregateDigest, aggregate.Digest) || len(state.Scalar) != fr.Bytes {
		t.Fatalf("read CV V2 scalar state: %v", err)
	}
	wrong := scalar
	wrong.Add(&wrong, new(fr.Element).SetOne())
	if err := store.PersistOnce(context.SID, context.Epoch, receiverID, aggregate.Digest, wrong, output); err == nil {
		t.Fatal("persisted a CV V2 scalar that does not match its public output")
	}
}
