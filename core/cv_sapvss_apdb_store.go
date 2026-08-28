package core

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

type cvAPDBHolderStoreV2 struct {
	root string
}

func newCVAPDBHolderStoreV2(root string) (*cvAPDBHolderStoreV2, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV V2 APDB holder store root")
	}
	store := &cvAPDBHolderStoreV2{root: filepath.Join(root, "apdb-v2-scalar-group")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *cvAPDBHolderStoreV2) StoreAndSignOnce(
	sid string, epoch uint64, holder int, oldRoster []int, store *cvAPDBStoreV2,
	totalShards, shardBytes int, apdbSigner *tblsThresholdSigner,
) ([]byte, error) {
	if s == nil || sid == "" || epoch == 0 || holder < 0 || !cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!cvThresholdSignerCanSignV2(apdbSigner, holder) || len(oldRoster) != totalShards ||
		!equalInts(oldRoster, sortedUnique(oldRoster)) || !equalInts(apdbSigner.memberOrder, oldRoster) {
		return nil, fmt.Errorf("invalid CV V2 APDB holder input")
	}
	holderIndex := -1
	for i, member := range oldRoster {
		if member == holder {
			holderIndex = i
			break
		}
	}
	if holderIndex < 0 || store == nil || store.Index != holderIndex {
		return nil, fmt.Errorf("CV V2 APDB store index does not match holder roster position")
	}
	wire, err := cvAPDBStoreV2CanonicalBytes(store, totalShards, shardBytes)
	if err != nil {
		return nil, err
	}
	path, err := s.path(sid, epoch, holder, store.InstanceDigest)
	if err != nil {
		return nil, err
	}
	if err := cvPutImmutableFile(path, wire); err != nil {
		return nil, fmt.Errorf("persist CV V2 APDB holder store: %w", err)
	}
	statement, err := cvAPDBStoredStatementV2(store.InstanceDigest, store.Root)
	if err != nil {
		return nil, err
	}
	share, err := apdbSigner.SignShare(holder, cvAPDBStoredDomain, statement)
	if err != nil {
		return nil, fmt.Errorf("sign persisted CV V2 APDB store: %w", err)
	}
	if !apdbSigner.VerifyShare(holder, cvAPDBStoredDomain, statement, share) {
		return nil, fmt.Errorf("invalid local CV V2 APDB stored share")
	}
	return share, nil
}

func (s *cvAPDBHolderStoreV2) Read(
	sid string, epoch uint64, holder int, expectedInstance, expectedRoot []byte,
	totalShards, shardBytes int,
) (*cvAPDBStoreV2, error) {
	if len(expectedInstance) != 32 || len(expectedRoot) != 32 || totalShards <= 0 || shardBytes <= 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB holder read input")
	}
	path, err := s.path(sid, epoch, holder, expectedInstance)
	if err != nil {
		return nil, err
	}
	wire, err := cvReadImmutableFile(path)
	if err != nil {
		return nil, err
	}
	store, err := cvDecodeAPDBStoreV2(wire, totalShards, shardBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(store.InstanceDigest, expectedInstance) || !bytes.Equal(store.Root, expectedRoot) {
		return nil, fmt.Errorf("persisted CV V2 APDB store does not match requested lock")
	}
	return store, nil
}

func (s *cvAPDBHolderStoreV2) ReadAuthorizedAggregate(
	sid string, epoch uint64, holder int, requestWire, expectedContext []byte,
	totalShards, shardBytes int, apdbSigner, controlSigner *tblsThresholdSigner,
) (*cvAPDBStoreV2, error) {
	handoff, err := cvAuthorizeAggregateRecoveryRequestV2(requestWire, expectedContext, apdbSigner, controlSigner)
	if err != nil {
		return nil, err
	}
	return s.Read(sid, epoch, holder, handoff.ARC.InstanceDigest, handoff.ARC.Root, totalShards, shardBytes)
}

func (s *cvAPDBHolderStoreV2) path(sid string, epoch uint64, holder int, instanceDigest []byte) (string, error) {
	if s == nil || sid == "" || epoch == 0 || epoch > uint64(^uint(0)>>1) || holder < 0 || len(instanceDigest) != 32 {
		return "", fmt.Errorf("invalid CV V2 APDB holder store key")
	}
	sidComponent, instance, err := cvStoreKeyParts(sid, int(epoch), holder, instanceDigest)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, sidComponent, fmt.Sprintf("epoch-%d", epoch), fmt.Sprintf("holder-%d", holder), instance+".store"), nil
}
