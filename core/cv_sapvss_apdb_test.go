package core

import (
	"bytes"
	"testing"
)

func TestCVAPDBV2RecoversAnyThresholdSubsetAndReencodesRoot(t *testing.T) {
	instance, err := cvAPDBInstanceDigestV2("COMP", []byte("sid"), []byte("epoch=1"), []byte("dealer=7"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("canonical CV V2 APDB component payload")
	encoded, err := cvAPDBEncodeV2(instance, payload, 3, 7, 1024)
	if err != nil {
		t.Fatalf("encode APDB: %v", err)
	}
	lock, err := cvNewAPDBLockV2(encoded, []byte("recovered-threshold-certificate"))
	if err != nil {
		t.Fatal(err)
	}
	lockWire, err := cvAPDBLockV2CanonicalBytes(lock)
	if err != nil {
		t.Fatal(err)
	}
	decodedLock, err := cvDecodeAPDBLockV2(lockWire)
	if err != nil || !bytes.Equal(decodedLock.Root, lock.Root) {
		t.Fatalf("APDB lock codec: %v", err)
	}
	stores := []cvAPDBStoreV2{encoded.stores[0], encoded.stores[3], encoded.stores[6]}
	storeWire, err := cvAPDBStoreV2CanonicalBytes(&stores[1], 7, encoded.shardBytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cvDecodeAPDBStoreV2(storeWire, 7, encoded.shardBytes); err != nil {
		t.Fatalf("APDB store codec: %v", err)
	}
	recovered, err := cvRecoverAPDBV2(lock, stores, 3, 7, encoded.shardBytes, 1024, func(got []byte) error {
		if !bytes.Equal(got, payload) {
			t.Fatalf("binding check payload mismatch")
		}
		return nil
	})
	if err != nil || !bytes.Equal(recovered, payload) {
		t.Fatalf("recover APDB: %v", err)
	}
}

func TestCVAPDBV2RejectsMutatedOrDuplicateStores(t *testing.T) {
	instance, err := cvAPDBInstanceDigestV2("AGG", []byte("sid"), []byte("epoch=1"), []byte("proposer=3"))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := cvAPDBEncodeV2(instance, []byte("aggregate payload"), 2, 4, 1024)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := cvNewAPDBLockV2(encoded, []byte("certificate"))
	if err != nil {
		t.Fatal(err)
	}
	mutated := encoded.stores[0]
	mutated.Shard = append([]byte(nil), mutated.Shard...)
	mutated.Shard[0] ^= 1
	if _, err := cvRecoverAPDBV2(lock, []cvAPDBStoreV2{mutated, encoded.stores[2]}, 2, 4, encoded.shardBytes, 1024, nil); err == nil {
		t.Fatal("recovered from a mutated APDB store")
	}
	if _, err := cvRecoverAPDBV2(lock, []cvAPDBStoreV2{encoded.stores[0], encoded.stores[0]}, 2, 4, encoded.shardBytes, 1024, nil); err == nil {
		t.Fatal("recovered from duplicate APDB store indices")
	}
}
