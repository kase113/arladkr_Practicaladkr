package core

import (
	"bytes"
	"fmt"
	"sync"
)

// cvAPDBRecoveryCollectorScalar validates authenticated holder responses before
// passing a threshold set to the deterministic APDB reconstruction routine.
type cvAPDBRecoveryCollectorScalar struct {
	mu             sync.Mutex
	lock           cvAPDBLockScalar
	requestWire    []byte
	oldRoster      []int
	memberIndex    map[int]int
	dataShards     int
	totalShards    int
	shardBytes     int
	maximumPayload int
	bindingCheck   func([]byte) error
	stores         map[int]cvAPDBStoreScalar
	storeWires     map[int][]byte
	payload        []byte
	payloadHints   []byte
}

// complete reports whether the recovery threshold is already satisfied. It is
// intentionally a read-only fast path used to discard late network responses;
// the authenticated payload/store remains owned by the collector.
func (c *cvAPDBRecoveryCollectorScalar) complete() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payload != nil || len(c.stores) >= c.dataShards
}

func newCVAPDBRecoveryCollectorScalar(
	lock *cvAPDBLockScalar, oldRoster []int, dataShards, shardBytes, maximumPayload int,
	apdbSigner *tblsThresholdSigner, bindingCheck func([]byte) error,
) (*cvAPDBRecoveryCollectorScalar, error) {
	if len(oldRoster) == 0 || !equalInts(oldRoster, sortedUnique(oldRoster)) || dataShards <= 0 ||
		dataShards > len(oldRoster) || shardBytes <= 0 || maximumPayload <= 0 ||
		!cvScalarSignerHasRole(apdbSigner, cvScalarRoleAPDB) || !equalInts(apdbSigner.memberOrder, oldRoster) ||
		cvVerifyAPDBLockScalar(lock, apdbSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 APDB recovery collector configuration")
	}
	memberIndex := make(map[int]int, len(oldRoster))
	for index, member := range oldRoster {
		if member < 0 {
			return nil, fmt.Errorf("invalid CV V2 APDB recovery roster")
		}
		memberIndex[member] = index
	}
	return &cvAPDBRecoveryCollectorScalar{
		lock: cvAPDBLockScalar{
			InstanceDigest: append([]byte(nil), lock.InstanceDigest...),
			Root:           append([]byte(nil), lock.Root...),
			Certificate:    append([]byte(nil), lock.Certificate...),
		},
		oldRoster:      append([]int(nil), oldRoster...),
		memberIndex:    memberIndex,
		dataShards:     dataShards,
		totalShards:    len(oldRoster),
		shardBytes:     shardBytes,
		maximumPayload: maximumPayload,
		bindingCheck:   bindingCheck,
		stores:         make(map[int]cvAPDBStoreScalar, dataShards),
		storeWires:     make(map[int][]byte, dataShards),
	}, nil
}

func newCVAggregateRecoveryCollectorScalar(
	requestWire, expectedContext []byte, oldRoster []int, dataShards, shardBytes, maximumPayload int,
	apdbSigner, controlSigner *tblsThresholdSigner, bindingCheck func([]byte) error,
) (*cvAPDBRecoveryCollectorScalar, error) {
	handoff, err := cvAuthorizeAggregateRecoveryRequestScalar(requestWire, expectedContext, apdbSigner, controlSigner)
	if err != nil {
		return nil, err
	}
	collector, err := newCVAPDBRecoveryCollectorScalar(
		&handoff.ARC, oldRoster, dataShards, shardBytes, maximumPayload, apdbSigner, bindingCheck,
	)
	if err != nil {
		return nil, err
	}
	collector.requestWire = append([]byte(nil), requestWire...)
	return collector, nil
}

// RequestRecipients returns every holder because a compact APDB lock does not
// reveal which members contributed shares to its threshold certificate.
func (c *cvAPDBRecoveryCollectorScalar) RequestRecipients() []int {
	if c == nil {
		return nil
	}
	return append([]int(nil), c.oldRoster...)
}

func (c *cvAPDBRecoveryCollectorScalar) RequestWire() []byte {
	if c == nil {
		return nil
	}
	return append([]byte(nil), c.requestWire...)
}

func (c *cvAPDBRecoveryCollectorScalar) AddStore(from int, wire []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("nil CV V2 APDB recovery collector")
	}
	store, err := cvDecodeAPDBStoreScalar(wire, c.totalShards, c.shardBytes)
	if err != nil {
		return false, err
	}
	return c.AddDecodedStore(from, store, wire)
}

// AddDecodedStore records a store that has already passed the strict wire and
// Merkle verification performed by cvDecodeAPDBStoreScalar.
func (c *cvAPDBRecoveryCollectorScalar) AddDecodedStore(from int, store *cvAPDBStoreScalar, wire []byte) (bool, error) {
	if c == nil || store == nil || len(wire) == 0 {
		return false, fmt.Errorf("invalid CV V2 decoded APDB recovery store")
	}
	expectedIndex, member := c.memberIndex[from]
	if !member {
		return false, fmt.Errorf("CV V2 APDB recovery response from non-holder")
	}
	if store.Index != expectedIndex || !bytes.Equal(store.InstanceDigest, c.lock.InstanceDigest) ||
		!bytes.Equal(store.Root, c.lock.Root) {
		return false, fmt.Errorf("CV V2 APDB recovery response does not match holder or lock")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if previous, exists := c.storeWires[expectedIndex]; exists {
		if !bytes.Equal(previous, wire) {
			return false, fmt.Errorf("conflicting CV V2 APDB recovery response")
		}
		return len(c.stores) >= c.dataShards, nil
	}
	c.stores[expectedIndex] = cvAPDBStoreScalar{
		InstanceDigest: append([]byte(nil), store.InstanceDigest...),
		Root:           append([]byte(nil), store.Root...),
		Index:          store.Index,
		Shard:          append([]byte(nil), store.Shard...),
		Siblings:       cvCloneByteSlices(store.Siblings),
	}
	c.storeWires[expectedIndex] = append([]byte(nil), wire...)
	return len(c.stores) >= c.dataShards, nil
}

// AddPayload accepts a full payload only when it reproduces the locked root.
// Optional point hints remain bound by canonical recompression.
func (c *cvAPDBRecoveryCollectorScalar) AddPayload(_ int, wire []byte) (bool, error) {
	if c == nil {
		return false, fmt.Errorf("nil CV V2 APDB recovery collector")
	}
	response, err := cvDecodeAPDBPayloadResponseScalar(wire, c.maximumPayload)
	if err != nil {
		return false, err
	}
	return c.addDecodedPayload(response)
}

// addDecodedPayload reuses bounded transport decoding; the collector still
// verifies the root and payload binding.
func (c *cvAPDBRecoveryCollectorScalar) addDecodedPayload(response *cvAPDBPayloadResponseScalar) (bool, error) {
	return c.addDecodedPayloadMode(response, false)
}

// addDecodedPayloadOwned transfers payload/hints from the bounded transport
// decoder. The decoder returns independent slices, so no second full-payload
// copy is needed on the authenticated network path.
func (c *cvAPDBRecoveryCollectorScalar) addDecodedPayloadOwned(response *cvAPDBPayloadResponseScalar) (bool, error) {
	return c.addDecodedPayloadMode(response, true)
}

func (c *cvAPDBRecoveryCollectorScalar) addDecodedPayloadMode(response *cvAPDBPayloadResponseScalar, takeOwnership bool) (bool, error) {
	if c == nil || response == nil {
		return false, fmt.Errorf("nil CV V2 APDB recovery payload")
	}
	if !bytes.Equal(response.InstanceDigest, c.lock.InstanceDigest) {
		return false, fmt.Errorf("CV V2 APDB payload response does not match lock")
	}
	// Authenticated retransmissions are compared by bytes without recomputing RS.
	c.mu.Lock()
	if c.payload != nil {
		if !bytes.Equal(c.payload, response.Payload) {
			c.mu.Unlock()
			return false, fmt.Errorf("conflicting CV V2 APDB payload response")
		}
		c.mu.Unlock()
		return true, nil
	}
	c.mu.Unlock()
	reencoded, err := cvAPDBEncodeSizedScalar(
		c.lock.InstanceDigest, response.Payload, c.dataShards, c.totalShards, c.shardBytes, c.maximumPayload,
	)
	if err != nil || !bytes.Equal(reencoded.root, c.lock.Root) {
		return false, fmt.Errorf("CV V2 APDB payload response root mismatch")
	}
	hints := response.Hints
	if !cvPayloadHintsEnabledScalar() {
		hints = nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Another worker may have accepted a response while this one was doing
	// the root check. Preserve the first authenticated payload and reject any
	// conflicting result.
	if c.payload != nil {
		if !bytes.Equal(c.payload, response.Payload) {
			return false, fmt.Errorf("conflicting CV V2 APDB payload response")
		}
		return true, nil
	}
	if c.payloadHints == nil && len(hints) > 0 {
		if takeOwnership {
			c.payloadHints = hints
		} else {
			c.payloadHints = append([]byte(nil), hints...)
		}
	}
	if takeOwnership {
		c.payload = response.Payload
	} else {
		c.payload = append([]byte(nil), response.Payload...)
	}
	return true, nil
}

// RecoveredHints returns the retained uncompressed-point sidecar, if any
// authenticated payload response carried one.
func (c *cvAPDBRecoveryCollectorScalar) RecoveredHints() []byte {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.payloadHints
}

func (c *cvAPDBRecoveryCollectorScalar) Recover() ([]byte, error) {
	payload, _, err := c.recoverWithSource()
	return payload, err
}

// recoverWithSource reports whether the authenticated full-payload fast path
// supplied the bytes actually returned to the caller.
func (c *cvAPDBRecoveryCollectorScalar) recoverWithSource() ([]byte, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("nil CV V2 APDB recovery collector")
	}
	c.mu.Lock()
	payload := c.payload
	c.mu.Unlock()
	if payload != nil {
		if c.bindingCheck != nil {
			if err := c.bindingCheck(payload); err != nil {
				return nil, true, fmt.Errorf("CV V2 APDB binding check: %w", err)
			}
		}
		return payload, true, nil
	}
	c.mu.Lock()
	if len(c.stores) < c.dataShards {
		c.mu.Unlock()
		return nil, false, fmt.Errorf("insufficient CV V2 APDB recovery responses")
	}
	stores := make([]cvAPDBStoreScalar, 0, len(c.stores))
	for index := 0; index < c.totalShards; index++ {
		if store, ok := c.stores[index]; ok {
			stores = append(stores, store)
		}
	}
	c.mu.Unlock()
	recovered, err := cvRecoverAPDBScalar(
		&c.lock, stores, c.dataShards, c.totalShards, c.shardBytes, c.maximumPayload, c.bindingCheck,
	)
	return recovered, false, err
}
