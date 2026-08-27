package core

import (
	"bytes"
	"fmt"
	"sync"
)

const cvAPDBStoredShareWireDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/apdb-stored-share"

type cvAPDBStoredShareV2 struct {
	InstanceDigest []byte
	Root           []byte
	Share          []byte
}

type cvAPDBLockCollectorV2 struct {
	mu          sync.Mutex
	encoded     *cvAPDBEncodedV2
	oldRoster   []int
	memberIndex map[int]int
	signer      *tblsThresholdSigner
	statement   []byte
	shares      map[int][]byte
	shareWires  map[int][]byte
}

func newCVAPDBLockCollectorV2(
	encoded *cvAPDBEncodedV2, oldRoster []int, apdbSigner *tblsThresholdSigner,
) (*cvAPDBLockCollectorV2, error) {
	if encoded == nil || len(encoded.instanceDigest) != 32 || len(encoded.root) != 32 ||
		len(encoded.stores) != len(oldRoster) || encoded.totalShards != len(oldRoster) ||
		encoded.dataShards <= 0 || encoded.dataShards > encoded.totalShards || encoded.shardBytes <= 0 ||
		!equalInts(oldRoster, sortedUnique(oldRoster)) || !cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!equalInts(apdbSigner.memberOrder, oldRoster) || apdbSigner.Threshold() <= 0 ||
		apdbSigner.Threshold() > len(oldRoster) {
		return nil, fmt.Errorf("invalid CV V2 APDB lock collector configuration")
	}
	memberIndex := make(map[int]int, len(oldRoster))
	encodedCopy := &cvAPDBEncodedV2{
		instanceDigest: append([]byte(nil), encoded.instanceDigest...),
		root:           append([]byte(nil), encoded.root...),
		dataShards:     encoded.dataShards,
		totalShards:    encoded.totalShards,
		shardBytes:     encoded.shardBytes,
		stores:         make([]cvAPDBStoreV2, len(encoded.stores)),
	}
	for index, member := range oldRoster {
		store := &encoded.stores[index]
		if member < 0 || store.Index != index || !bytes.Equal(store.InstanceDigest, encoded.instanceDigest) ||
			!bytes.Equal(store.Root, encoded.root) ||
			cvVerifyAPDBStoreV2(store, encoded.totalShards, encoded.shardBytes) != nil {
			return nil, fmt.Errorf("invalid CV V2 APDB lock collector roster")
		}
		memberIndex[member] = index
		encodedCopy.stores[index] = cvAPDBStoreV2{
			InstanceDigest: append([]byte(nil), store.InstanceDigest...),
			Root:           append([]byte(nil), store.Root...),
			Index:          store.Index,
			Shard:          append([]byte(nil), store.Shard...),
			Siblings:       cvCloneByteSlices(store.Siblings),
		}
	}
	statement, err := cvAPDBStoredStatementV2(encoded.instanceDigest, encoded.root)
	if err != nil {
		return nil, err
	}
	return &cvAPDBLockCollectorV2{
		encoded: encodedCopy, oldRoster: append([]int(nil), oldRoster...), memberIndex: memberIndex,
		signer: apdbSigner, statement: statement, shares: make(map[int][]byte, apdbSigner.Threshold()),
		shareWires: make(map[int][]byte, apdbSigner.Threshold()),
	}, nil
}

func (c *cvAPDBLockCollectorV2) StoreRecipients() []int {
	if c == nil {
		return nil
	}
	return append([]int(nil), c.oldRoster...)
}

func (c *cvAPDBLockCollectorV2) StoreOffer(holder int) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("nil CV V2 APDB lock collector")
	}
	index, ok := c.memberIndex[holder]
	if !ok {
		return nil, fmt.Errorf("CV V2 APDB store recipient is not a holder")
	}
	return cvAPDBStoreV2CanonicalBytes(&c.encoded.stores[index], c.encoded.totalShards, c.encoded.shardBytes)
}

func (c *cvAPDBLockCollectorV2) AddStoredShare(from int, wire []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("nil CV V2 APDB lock collector")
	}
	if _, ok := c.memberIndex[from]; !ok {
		return false, fmt.Errorf("CV V2 APDB stored share from non-holder")
	}
	response, err := cvDecodeAPDBStoredShareV2(wire)
	if err != nil {
		return false, err
	}
	return c.AddDecodedStoredShare(from, response, wire)
}

func (c *cvAPDBLockCollectorV2) AddDecodedStoredShare(from int, response *cvAPDBStoredShareV2, wire []byte) (bool, error) {
	if c == nil || response == nil || len(wire) == 0 {
		return false, fmt.Errorf("invalid CV V2 decoded APDB stored share")
	}
	if _, ok := c.memberIndex[from]; !ok {
		return false, fmt.Errorf("CV V2 APDB stored share from non-holder")
	}
	c.mu.Lock()
	if previous, exists := c.shareWires[from]; exists && bytes.Equal(previous, wire) {
		complete := len(c.shares) >= c.signer.Threshold()
		c.mu.Unlock()
		return complete, nil
	}
	c.mu.Unlock()
	if !bytes.Equal(response.InstanceDigest, c.encoded.instanceDigest) || !bytes.Equal(response.Root, c.encoded.root) ||
		!c.signer.VerifyShare(from, cvAPDBStoredDomain, c.statement, response.Share) {
		return false, fmt.Errorf("invalid CV V2 APDB stored share")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if previous, exists := c.shareWires[from]; exists {
		if !bytes.Equal(previous, wire) {
			return false, fmt.Errorf("conflicting CV V2 APDB stored share")
		}
		return len(c.shares) >= c.signer.Threshold(), nil
	}
	c.shares[from] = append([]byte(nil), response.Share...)
	c.shareWires[from] = append([]byte(nil), wire...)
	return len(c.shares) >= c.signer.Threshold(), nil
}

func (c *cvAPDBLockCollectorV2) RecoverLock() (*cvAPDBLockV2, error) {
	if c == nil {
		return nil, fmt.Errorf("nil CV V2 APDB lock collector")
	}
	c.mu.Lock()
	if len(c.shares) < c.signer.Threshold() {
		c.mu.Unlock()
		return nil, fmt.Errorf("insufficient CV V2 APDB stored shares")
	}
	shares := make(map[int][]byte, c.signer.Threshold())
	for _, member := range c.oldRoster {
		share, ok := c.shares[member]
		if !ok {
			continue
		}
		shares[member] = append([]byte(nil), share...)
		if len(shares) == c.signer.Threshold() {
			break
		}
	}
	c.mu.Unlock()
	certificate, err := c.signer.Recover(cvAPDBStoredDomain, c.statement, shares)
	if err != nil {
		return nil, fmt.Errorf("recover CV V2 APDB lock certificate: %w", err)
	}
	lock, err := cvNewAPDBLockV2(c.encoded, certificate)
	if err != nil {
		return nil, err
	}
	if err := cvVerifyAPDBLockV2(lock, c.signer); err != nil {
		return nil, err
	}
	return lock, nil
}

func cvHandleAPDBStoreOfferV2(
	sid string, epoch uint64, proposer, holder int, oldRoster []int, offerWire []byte,
	totalShards, shardBytes int, holderStore *cvAPDBHolderStoreV2, apdbSigner *tblsThresholdSigner,
) ([]byte, error) {
	if !equalInts(oldRoster, sortedUnique(oldRoster)) || !cvMemberInRosterV2(proposer, oldRoster) ||
		!cvMemberInRosterV2(holder, oldRoster) || holderStore == nil {
		return nil, fmt.Errorf("invalid CV V2 APDB store offer participants")
	}
	store, err := cvDecodeAPDBStoreV2(offerWire, totalShards, shardBytes)
	if err != nil {
		return nil, err
	}
	share, err := holderStore.StoreAndSignOnce(sid, epoch, holder, oldRoster, store, totalShards, shardBytes, apdbSigner)
	if err != nil {
		return nil, err
	}
	return cvAPDBStoredShareV2CanonicalBytes(&cvAPDBStoredShareV2{
		InstanceDigest: store.InstanceDigest, Root: store.Root, Share: share,
	})
}

func cvHandleAPDBRecoveryRequestV2(
	sid string, epoch uint64, requester, holder int, oldRoster []int, requestWire []byte,
	totalShards, shardBytes int, holderStore *cvAPDBHolderStoreV2, apdbSigner *tblsThresholdSigner,
) ([]byte, error) {
	if !equalInts(oldRoster, sortedUnique(oldRoster)) || !cvMemberInRosterV2(requester, oldRoster) ||
		!cvMemberInRosterV2(holder, oldRoster) || holderStore == nil {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery participants")
	}
	lock, err := cvDecodeAPDBLockV2(requestWire)
	if err != nil || cvVerifyAPDBLockV2(lock, apdbSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery lock")
	}
	return cvHandleAPDBRecoveryLockV2(sid, epoch, requester, holder, oldRoster, lock,
		totalShards, shardBytes, holderStore)
}

func cvHandleAPDBRecoveryLockV2(
	sid string, epoch uint64, requester, holder int, oldRoster []int, lock *cvAPDBLockV2,
	totalShards, shardBytes int, holderStore *cvAPDBHolderStoreV2,
) ([]byte, error) {
	if !equalInts(oldRoster, sortedUnique(oldRoster)) || !cvMemberInRosterV2(requester, oldRoster) ||
		!cvMemberInRosterV2(holder, oldRoster) || holderStore == nil || lock == nil {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery participants")
	}
	store, err := holderStore.Read(sid, epoch, holder, lock.InstanceDigest, lock.Root, totalShards, shardBytes)
	if err != nil {
		return nil, err
	}
	return cvAPDBStoreV2CanonicalBytes(store, totalShards, shardBytes)
}

func cvHandleAggregateRecoveryRequestV2(
	sid string, epoch uint64, receiver, holder int, oldRoster, newRoster []int, requestWire, expectedContext []byte,
	totalShards, shardBytes int, holderStore *cvAPDBHolderStoreV2, apdbSigner, controlSigner *tblsThresholdSigner,
) ([]byte, error) {
	if !equalInts(oldRoster, sortedUnique(oldRoster)) || !equalInts(newRoster, sortedUnique(newRoster)) ||
		!cvMemberInRosterV2(receiver, newRoster) || !cvMemberInRosterV2(holder, oldRoster) || holderStore == nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery participants")
	}
	store, err := holderStore.ReadAuthorizedAggregate(sid, epoch, holder, requestWire, expectedContext,
		totalShards, shardBytes, apdbSigner, controlSigner)
	if err != nil {
		return nil, err
	}
	return cvAPDBStoreV2CanonicalBytes(store, totalShards, shardBytes)
}

func cvAPDBStoredShareV2CanonicalBytes(response *cvAPDBStoredShareV2) ([]byte, error) {
	if response == nil || len(response.InstanceDigest) != 32 || len(response.Root) != 32 ||
		len(response.Share) == 0 || len(response.Share) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 APDB stored share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAPDBStoredShareWireDomainV2))
	_ = cvWriteBytes(&wire, response.InstanceDigest)
	_ = cvWriteBytes(&wire, response.Root)
	_ = cvWriteBytes(&wire, response.Share)
	return wire.Bytes(), nil
}

func cvDecodeAPDBStoredShareV2(wire []byte) (*cvAPDBStoredShareV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAPDBStoredShareWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAPDBStoredShareWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 APDB stored-share domain")
	}
	instance, err := r.bytes(32)
	if err != nil || len(instance) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB stored-share instance")
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 {
		return nil, fmt.Errorf("invalid CV V2 APDB stored-share root")
	}
	share, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(share) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 APDB stored-share signature")
	}
	response := &cvAPDBStoredShareV2{InstanceDigest: instance, Root: root, Share: share}
	canonical, err := cvAPDBStoredShareV2CanonicalBytes(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 APDB stored share")
	}
	return response, nil
}

func cvMemberInRosterV2(member int, roster []int) bool {
	for _, candidate := range roster {
		if member == candidate {
			return true
		}
	}
	return false
}
