package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/klauspost/reedsolomon"
)

const (
	cvAggregatePayloadDomain    = "ARL-CV-sAPVSS/aggregate-payload"
	cvAggregateShardDomain      = "ARL-CV-sAPVSS/aggregate-shard"
	cvAggregateNodeDomain       = "ARL-CV-sAPVSS/aggregate-shard-node"
	cvAggregateFreshNonceDomain = "ARL-CV-sAPVSS/fresh-nonce"
	cvMaxCanonicalFieldBytes    = 1 << 24
)

type cvAggregateShard struct {
	index    int
	payload  []byte
	siblings [][]byte
}

type cvAggregateDispersal struct {
	nonce         []byte
	dataShards    int
	payloadDigest []byte
	root          []byte
	shards        []cvAggregateShard
}

type cvRSEncoderKey struct {
	dataShards   int
	parityShards int
	workers      int
}

type cvRSEncoderEntry struct {
	mu      sync.Mutex
	encoder reedsolomon.Encoder
}

var cvRSEncoderCache sync.Map

func cvCachedRSEncoder(dataShards, totalShards int) (*cvRSEncoderEntry, error) {
	if dataShards <= 0 || totalShards < dataShards {
		return nil, fmt.Errorf("invalid CV-sAPVSS erasure-code dimensions")
	}
	key := cvRSEncoderKey{
		dataShards: dataShards, parityShards: totalShards - dataShards,
		workers: cvRSWorkers(totalShards),
	}
	if cached, ok := cvRSEncoderCache.Load(key); ok {
		return cached.(*cvRSEncoderEntry), nil
	}
	encoder, err := reedsolomon.New(
		key.dataShards,
		key.parityShards,
		reedsolomon.WithMaxGoroutines(key.workers),
	)
	if err != nil {
		return nil, err
	}
	entry := &cvRSEncoderEntry{encoder: encoder}
	actual, _ := cvRSEncoderCache.LoadOrStore(key, entry)
	return actual.(*cvRSEncoderEntry), nil
}

type cvMaterializedAggregate struct {
	rlo       *AggRLO
	aggregate *cvAggregateTranscript
	dispersal *cvAggregateDispersal
	metrics   cvAggregateMaterializeMetrics
}

type cvAggregateMaterializeMetrics struct {
	gateWait    time.Duration
	leafLoad    time.Duration
	aggregate   time.Duration
	rsDisperse  time.Duration
	headerToken time.Duration
	offerSend   time.Duration
	arcWait     time.Duration
	certificate time.Duration
}

func cvMaterializeAndLockAggregate(
	cfg Config,
	leafContext *cvLeafContext,
	leaves []*cvLeaf,
) (*cvMaterializedAggregate, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if leafContext == nil || string(leafContext.sessionID) != c.SID || int(leafContext.epoch) != c.Epoch {
		return nil, fmt.Errorf("CV-sAPVSS M4 context does not match ARL session")
	}
	if c.Kappa != c.FOld+1 || len(leaves) != c.Kappa {
		return nil, fmt.Errorf("CV-sAPVSS M4 requires K=f_o+1 leaves")
	}
	leafDealerIDs := make([]uint64, len(leaves))
	for i, leaf := range leaves {
		if leaf == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS aggregate leaf")
		}
		leafDealerIDs[i] = leaf.dealerID
	}
	dealers, err := cvDealerIDsToInts(leafDealerIDs)
	if err != nil {
		return nil, err
	}
	if _, err := validateFinalDealerSet(c, dealers); err != nil {
		return nil, fmt.Errorf("CV-sAPVSS M4 dealer set: %w", err)
	}
	agg, err := cvAgg(leafContext, leaves)
	if err != nil {
		return nil, err
	}
	dispersal, err := cvDisperseAggregate(agg, len(c.OldCommittee), len(c.OldCommittee)-2*c.FOld)
	if err != nil {
		return nil, err
	}
	return cvBuildMaterializedAggRLOFromVerifiedAggregate(c, agg, dispersal)
}

func cvBuildMaterializedAggRLO(
	cfg Config,
	leafContext *cvLeafContext,
	leaves []*cvLeaf,
	agg *cvAggregateTranscript,
	dispersal *cvAggregateDispersal,
) (*cvMaterializedAggregate, error) {
	if err := cvAVer(leafContext, agg, leaves); err != nil {
		return nil, err
	}
	return cvBuildMaterializedAggRLOFromVerifiedAggregate(cfg, agg, dispersal)
}

func cvBuildMaterializedAggRLOFromVerifiedAggregate(
	cfg Config,
	agg *cvAggregateTranscript,
	dispersal *cvAggregateDispersal,
) (*cvMaterializedAggregate, error) {
	if dispersal == nil {
		return nil, fmt.Errorf("missing CV-sAPVSS aggregate materialization")
	}
	if err := cvValidateAggregateErasureDimensions(cfg, dispersal); err != nil {
		return nil, err
	}
	if err := cvVerifyAggregateDispersal(agg, dispersal); err != nil {
		return nil, err
	}
	dealers, err := cvDealerIDsToInts(agg.dealerIDs)
	if err != nil {
		return nil, err
	}
	providerAggregate := &APVSSAggregate{
		Provider:        "cv-sapvss",
		Dealers:         append([]int(nil), dealers...),
		AggregateDigest: append([]byte(nil), agg.digest...),
	}
	oldOrder := sortedUnique(cfg.OldCommittee)
	beforeSign := func(holder int) error {
		index := -1
		for i, id := range oldOrder {
			if id == holder {
				index = i
				break
			}
		}
		if index < 0 || index >= len(dispersal.shards) {
			return fmt.Errorf("holder has no aggregate shard")
		}
		return cvVerifyAggregateShard(dispersal, &dispersal.shards[index])
	}
	rlo, err := buildAggRLO(cfg, dealers, providerAggregate, &aggRLOMaterializedBinding{
		payloadDigest:  dispersal.payloadDigest,
		freshShardRoot: dispersal.root,
		beforeSign:     beforeSign,
	})
	if err != nil {
		return nil, err
	}
	return &cvMaterializedAggregate{rlo: rlo, aggregate: agg, dispersal: dispersal}, nil
}

func cvDealerIDsToInts(dealerIDs []uint64) ([]int, error) {
	dealers := make([]int, len(dealerIDs))
	maxInt := uint64(^uint(0) >> 1)
	for i, dealer := range dealerIDs {
		if dealer > maxInt {
			return nil, fmt.Errorf("CV-sAPVSS dealer ID exceeds int")
		}
		dealers[i] = int(dealer)
	}
	return dealers, nil
}

func cvRecoverMaterializedAggregate(
	cfg Config,
	materialized *cvMaterializedAggregate,
	agreedDigest []byte,
	available []int,
) (*cvAggregateTranscript, error) {
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if materialized == nil || materialized.rlo == nil || materialized.dispersal == nil {
		return nil, fmt.Errorf("missing CV-sAPVSS materialized aggregate")
	}
	rlo := materialized.rlo
	if _, err := validateAggRLOShape(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return nil, err
	}
	if len(agreedDigest) != 32 || !bytes.Equal(agreedDigest, rlo.Digest) {
		return nil, fmt.Errorf("CV-sAPVSS local aggregate does not match MVBA decision")
	}
	dispersal := materialized.dispersal
	if err := cvValidateAggregateErasureDimensions(c, dispersal); err != nil {
		return nil, err
	}
	if !bytes.Equal(rlo.Header.PayloadDigest, dispersal.payloadDigest) ||
		!bytes.Equal(rlo.Header.FreshShardRoot, dispersal.root) {
		return nil, fmt.Errorf("CV-sAPVSS materialization does not match ARC header")
	}
	wire, err := cvRecoverAggregateWire(dispersal, available)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(hashBytes([]byte(cvAggregatePayloadDomain), wire), rlo.Header.PayloadDigest) ||
		!bytes.Equal(hashBytes([]byte(cvAggregateDomain), wire), rlo.Header.AggregateDigest) {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate digest mismatch")
	}
	agg, err := cvDecodeAggregate(wire)
	if err != nil {
		return nil, err
	}
	if string(agg.context.sessionID) != c.SID || int(agg.context.epoch) != c.Epoch ||
		len(agg.dealerIDs) != len(rlo.Header.Dealers) {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate header mismatch")
	}
	for i, dealer := range agg.dealerIDs {
		if dealer != uint64(rlo.Header.Dealers[i]) {
			return nil, fmt.Errorf("recovered CV-sAPVSS dealer manifest mismatch")
		}
	}
	return agg, nil
}

func cvValidateAggregateErasureDimensions(cfg Config, dispersal *cvAggregateDispersal) error {
	totalShards := len(sortedUnique(cfg.OldCommittee))
	dataShards := totalShards - 2*cfg.FOld
	if dispersal == nil || totalShards <= 0 || dataShards <= 0 ||
		len(dispersal.shards) != totalShards || dispersal.dataShards != dataShards {
		return fmt.Errorf("CV-sAPVSS aggregate dispersal must use (n_o,n_o-2f_o) erasure dimensions")
	}
	return nil
}

func cvDisperseAggregate(agg *cvAggregateTranscript, totalShards, dataShards int) (*cvAggregateDispersal, error) {
	if totalShards <= 0 || dataShards <= 0 || dataShards > totalShards {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate dispersal parameters")
	}
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return nil, err
	}
	packed := make([]byte, 8+len(wire))
	binary.BigEndian.PutUint64(packed[:8], uint64(len(wire)))
	copy(packed[8:], wire)
	shards, err := cvErasureEncode(packed, dataShards, totalShards)
	if err != nil {
		return nil, err
	}
	nonce, err := cvAggregateFreshNonce(agg, wire)
	if err != nil {
		return nil, err
	}
	root, branches := cvBuildAggregateMerkle(nonce, shards)
	dispersal := &cvAggregateDispersal{
		nonce:         nonce,
		dataShards:    dataShards,
		payloadDigest: hashBytes([]byte(cvAggregatePayloadDomain), wire),
		root:          root,
		shards:        make([]cvAggregateShard, len(shards)),
	}
	for i := range shards {
		dispersal.shards[i] = cvAggregateShard{
			index:    i,
			payload:  append([]byte(nil), shards[i]...),
			siblings: branches[i],
		}
	}
	return dispersal, nil
}

func cvAggregateFreshNonce(agg *cvAggregateTranscript, aggregateWire []byte) ([]byte, error) {
	if agg == nil || len(aggregateWire) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate fresh nonce input")
	}
	aggregateDigest := hashBytes([]byte(cvAggregateDomain), aggregateWire)
	if len(agg.digest) != 32 || !bytes.Equal(agg.digest, aggregateDigest) ||
		!bytes.Equal(agg.digestWire, aggregateWire) {
		return nil, fmt.Errorf("CV-sAPVSS aggregate wire or digest mismatch")
	}
	contextWire, err := cvLeafContextCanonicalBytes(&agg.context)
	if err != nil {
		return nil, err
	}
	contextDigest := hashBytes([]byte("ARL-CV-sAPVSS/context-digest"), contextWire)
	return hashBytes(
		[]byte(cvAggregateFreshNonceDomain),
		contextDigest,
		aggregateDigest,
	), nil
}

func cvVerifyAggregateDispersal(agg *cvAggregateTranscript, dispersal *cvAggregateDispersal) error {
	if dispersal == nil || len(dispersal.nonce) != 32 || len(dispersal.root) != 32 ||
		len(dispersal.payloadDigest) != 32 || dispersal.dataShards <= 0 ||
		dispersal.dataShards > len(dispersal.shards) {
		return fmt.Errorf("invalid CV-sAPVSS aggregate dispersal")
	}
	for i := range dispersal.shards {
		if dispersal.shards[i].index != i {
			return fmt.Errorf("non-canonical CV-sAPVSS aggregate shard order")
		}
		if i > 0 && len(dispersal.shards[i].payload) != len(dispersal.shards[0].payload) {
			return fmt.Errorf("non-canonical CV-sAPVSS aggregate shard size")
		}
		if err := cvVerifyAggregateShard(dispersal, &dispersal.shards[i]); err != nil {
			return err
		}
	}
	if dispersal.dataShards < len(dispersal.shards) {
		payloads := make([][]byte, len(dispersal.shards))
		for i := range dispersal.shards {
			payloads[i] = dispersal.shards[i].payload
		}
		entry, err := cvCachedRSEncoder(dispersal.dataShards, len(dispersal.shards))
		if err != nil {
			return err
		}
		entry.mu.Lock()
		valid, err := entry.encoder.Verify(payloads)
		entry.mu.Unlock()
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("invalid CV-sAPVSS aggregate erasure codeword")
		}
	}
	available := make([]int, len(dispersal.shards))
	for i := range available {
		available[i] = i
	}
	wire, err := cvRecoverAggregateWire(dispersal, available)
	if err != nil {
		return err
	}
	expected, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		return err
	}
	if !bytes.Equal(agg.digestWire, expected) ||
		!bytes.Equal(agg.digest, hashBytes([]byte(cvAggregateDomain), expected)) {
		return fmt.Errorf("CV-sAPVSS Aggregate wire or digest mismatch")
	}
	expectedNonce, err := cvAggregateFreshNonce(agg, expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(dispersal.nonce, expectedNonce) {
		return fmt.Errorf("non-deterministic CV-sAPVSS aggregate dispersal nonce")
	}
	if !bytes.Equal(wire, expected) ||
		!bytes.Equal(dispersal.payloadDigest, hashBytes([]byte(cvAggregatePayloadDomain), wire)) {
		return fmt.Errorf("CV-sAPVSS aggregate dispersal payload mismatch")
	}
	payloads := make([][]byte, len(dispersal.shards))
	for i := range dispersal.shards {
		payloads[i] = dispersal.shards[i].payload
	}
	root, _ := cvBuildAggregateMerkle(dispersal.nonce, payloads)
	if !bytes.Equal(root, dispersal.root) {
		return fmt.Errorf("CV-sAPVSS aggregate Merkle root is not canonical")
	}
	return nil
}

func cvVerifyAggregateShard(dispersal *cvAggregateDispersal, shard *cvAggregateShard) error {
	if dispersal == nil || shard == nil || shard.index < 0 || shard.index >= len(dispersal.shards) ||
		len(shard.payload) == 0 {
		return fmt.Errorf("invalid CV-sAPVSS aggregate shard")
	}
	merkleDepth := 0
	levelWidth := len(dispersal.shards)
	for levelWidth > 1 {
		merkleDepth++
		levelWidth = (levelWidth + 1) / 2
	}
	if len(shard.siblings) != merkleDepth {
		return fmt.Errorf("non-canonical CV-sAPVSS aggregate shard branch count")
	}
	digest := cvAggregateShardHash(dispersal.nonce, shard.index, shard.payload)
	index := shard.index
	for _, sibling := range shard.siblings {
		if len(sibling) != 32 {
			return fmt.Errorf("invalid CV-sAPVSS aggregate shard branch")
		}
		if index%2 == 0 {
			digest = hashBytes([]byte(cvAggregateNodeDomain), digest, sibling)
		} else {
			digest = hashBytes([]byte(cvAggregateNodeDomain), sibling, digest)
		}
		index /= 2
	}
	if !bytes.Equal(digest, dispersal.root) {
		return fmt.Errorf("CV-sAPVSS aggregate shard root mismatch")
	}
	return nil
}

func cvRecoverAggregateWire(dispersal *cvAggregateDispersal, available []int) ([]byte, error) {
	if dispersal == nil || len(available) < dispersal.dataShards {
		return nil, fmt.Errorf("insufficient CV-sAPVSS aggregate shards")
	}
	shards := make([][]byte, len(dispersal.shards))
	seen := make(map[int]struct{}, len(available))
	for _, index := range available {
		if index < 0 || index >= len(dispersal.shards) {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate shard index")
		}
		if _, ok := seen[index]; ok {
			continue
		}
		seen[index] = struct{}{}
		shard := &dispersal.shards[index]
		if err := cvVerifyAggregateShard(dispersal, shard); err != nil {
			return nil, err
		}
		shards[index] = append([]byte(nil), shard.payload...)
	}
	if len(seen) < dispersal.dataShards {
		return nil, fmt.Errorf("insufficient distinct CV-sAPVSS aggregate shards")
	}
	packed, err := cvErasureDecode(shards, dispersal.dataShards)
	if err != nil {
		return nil, err
	}
	if len(packed) < 8 {
		return nil, fmt.Errorf("recovered CV-sAPVSS aggregate is truncated")
	}
	length := binary.BigEndian.Uint64(packed[:8])
	if length > uint64(len(packed)-8) || length > cvMaxCanonicalFieldBytes {
		return nil, fmt.Errorf("invalid recovered CV-sAPVSS aggregate length")
	}
	return append([]byte(nil), packed[8:8+int(length)]...), nil
}

func cvErasureEncode(payload []byte, dataShards, totalShards int) ([][]byte, error) {
	if dataShards == totalShards {
		shardSize := (len(payload) + dataShards - 1) / dataShards
		shards := make([][]byte, totalShards)
		for i := range shards {
			shards[i] = make([]byte, shardSize)
			start := i * shardSize
			if start < len(payload) {
				copy(shards[i], payload[start:min(start+shardSize, len(payload))])
			}
		}
		return shards, nil
	}
	entry, err := cvCachedRSEncoder(dataShards, totalShards)
	if err != nil {
		return nil, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	shards, err := entry.encoder.Split(payload)
	if err != nil {
		return nil, err
	}
	if err := entry.encoder.Encode(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func cvErasureDecode(shards [][]byte, dataShards int) ([]byte, error) {
	if dataShards == len(shards) {
		var out bytes.Buffer
		for _, shard := range shards {
			if shard == nil {
				return nil, fmt.Errorf("missing CV-sAPVSS data shard")
			}
			_, _ = out.Write(shard)
		}
		return out.Bytes(), nil
	}
	entry, err := cvCachedRSEncoder(dataShards, len(shards))
	if err != nil {
		return nil, err
	}
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if err := entry.encoder.Reconstruct(shards); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := entry.encoder.Join(&out, shards, len(shards[0])*dataShards); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func cvAggregateShardHash(nonce []byte, index int, payload []byte) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(index))
	return hashBytes([]byte(cvAggregateShardDomain), nonce, encoded[:], payload)
}

func cvBuildAggregateMerkle(nonce []byte, shards [][]byte) ([]byte, [][][]byte) {
	levels := make([][][]byte, 0)
	leaves := make([][]byte, len(shards))
	for i := range shards {
		leaves[i] = cvAggregateShardHash(nonce, i, shards[i])
	}
	levels = append(levels, leaves)
	for len(levels[len(levels)-1]) > 1 {
		level := levels[len(levels)-1]
		padded := level
		if len(level)%2 == 1 {
			padded = append(append([][]byte(nil), level...), level[len(level)-1])
		}
		next := make([][]byte, 0, len(padded)/2)
		for i := 0; i < len(padded); i += 2 {
			next = append(next, hashBytes([]byte(cvAggregateNodeDomain), padded[i], padded[i+1]))
		}
		levels = append(levels, next)
	}
	branches := make([][][]byte, len(shards))
	for i := range shards {
		index := i
		for depth := 0; depth < len(levels)-1; depth++ {
			level := levels[depth]
			sibling := index ^ 1
			if sibling >= len(level) {
				sibling = len(level) - 1
			}
			branches[i] = append(branches[i], append([]byte(nil), level[sibling]...))
			index /= 2
		}
	}
	return append([]byte(nil), levels[len(levels)-1][0]...), branches
}

type cvWireReader struct {
	reader *bytes.Reader
	// deferredPoints collects points decoded without the per-point subgroup
	// check; decode units flush them through one batch subgroup check via
	// assertDecodedSubgroup before returning trusted structures.
	deferredPoints []bls12381.G1Affine
	// scratch is reused for compressed-point reads; hot leaf decode paths
	// otherwise allocate per point and dominate garbage on large committees.
	scratch [96]byte
	// side shares one leaf decode's uncompressed-point sidechannel across
	// every nested reader that reads deferred points, keeping hint
	// consumption and recording in wire order. nil keeps legacy behavior.
	side *cvDecodeSidechannelV2
}

func newCVWireReader(wire []byte) *cvWireReader {
	return &cvWireReader{reader: bytes.NewReader(wire)}
}

func newCVWireReaderSide(wire []byte, side *cvDecodeSidechannelV2) *cvWireReader {
	r := newCVWireReader(wire)
	r.side = side
	return r
}

func (r *cvWireReader) uint32() (int, error) {
	var encoded [4]byte
	if _, err := io.ReadFull(r.reader, encoded[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint32(encoded[:])), nil
}

func (r *cvWireReader) uint64() (uint64, error) {
	var encoded [8]byte
	if _, err := io.ReadFull(r.reader, encoded[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(encoded[:]), nil
}

func (r *cvWireReader) bytes(maximum int) ([]byte, error) {
	length, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if length < 0 || length > maximum || length > r.reader.Len() {
		return nil, fmt.Errorf("invalid CV-sAPVSS canonical byte length")
	}
	out := make([]byte, length)
	_, err = io.ReadFull(r.reader, out)
	return out, err
}

func (r *cvWireReader) point() (bls12381.G1Affine, error) {
	encoded := r.scratch[:bls12381.SizeOfG1AffineCompressed]
	if _, err := io.ReadFull(r.reader, encoded); err != nil {
		return bls12381.G1Affine{}, err
	}
	var point bls12381.G1Affine
	consumed, err := point.SetBytes(encoded)
	if err != nil || consumed != len(encoded) {
		return bls12381.G1Affine{}, fmt.Errorf("invalid CV-sAPVSS canonical point")
	}
	return point, nil
}

func (r *cvWireReader) ciphertext() (cvElGamalCiphertext, error) {
	first, err := r.point()
	if err != nil {
		return cvElGamalCiphertext{}, err
	}
	second, err := r.point()
	if err != nil {
		return cvElGamalCiphertext{}, err
	}
	return cvElGamalCiphertext{r: first, c: second}, nil
}

func cvDecodeLeafContext(wire []byte) (cvLeafContext, error) {
	r := newCVWireReader(wire)
	for _, expected := range [][]byte{
		[]byte("ARL-CV-sAPVSS"), []byte(cvLeafGroupID), fr.Modulus().Bytes(),
	} {
		value, err := r.bytes(256)
		if err != nil || !bytes.Equal(value, expected) {
			return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS context domain")
		}
	}
	g, err := r.point()
	if err != nil || !g.Equal(&genG1) {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS context generator")
	}
	h, err := r.point()
	expectedH, hErr := cvPedersenBase()
	if err != nil || hErr != nil || !h.Equal(&expectedH) {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS context Pedersen base")
	}
	sessionID, err := r.bytes(1 << 20)
	if err != nil {
		return cvLeafContext{}, err
	}
	epoch, err := r.uint64()
	if err != nil {
		return cvLeafContext{}, err
	}
	previousStateDigest, err := r.bytes(32)
	if err != nil || len(previousStateDigest) != 32 {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS previous-state digest")
	}
	if bytes.Equal(previousStateDigest, make([]byte, 32)) {
		previousStateDigest = nil
	}
	params := make([]int, 6)
	for i := range params {
		params[i], err = r.uint32()
		if err != nil {
			return cvLeafContext{}, err
		}
	}
	registryDigest, err := r.bytes(32)
	if err != nil || len(registryDigest) != 32 {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS receiver registry digest")
	}
	receiverCount, err := r.uint32()
	if err != nil || receiverCount != params[0] {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS receiver count")
	}
	const receiverWireBytes = 4 + 2*bls12381.SizeOfG1AffineCompressed
	if receiverCount < 0 || receiverCount > r.reader.Len()/receiverWireBytes {
		return cvLeafContext{}, fmt.Errorf("CV-sAPVSS receiver count exceeds remaining wire")
	}
	keys := make([]bls12381.G1Affine, receiverCount)
	signingKeys := make([]bls12381.G1Affine, receiverCount)
	for i := range keys {
		index, indexErr := r.uint32()
		if indexErr != nil || index != i+1 {
			return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS receiver index")
		}
		keys[i], err = r.point()
		if err != nil {
			return cvLeafContext{}, err
		}
		signingKeys[i], err = r.point()
		if err != nil {
			return cvLeafContext{}, err
		}
	}
	dealerPolicy, err := r.bytes(1 << 20)
	if err != nil {
		return cvLeafContext{}, err
	}
	proofProfile, err := r.bytes(1 << 20)
	if err != nil || r.reader.Len() != 0 {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS context suffix")
	}
	context := cvLeafContext{
		sessionID:                 sessionID,
		epoch:                     epoch,
		previousStateDigest:       previousStateDigest,
		sharingDegree:             params[1],
		profile:                   cvChunkProfile{maxComponents: params[2], chunkBits: uint(params[3])},
		receiverPublicKeys:        keys,
		receiverSigningPublicKeys: signingKeys,
		dealerSetPolicy:           dealerPolicy,
		proofProfile:              string(proofProfile),
	}
	base, _, chunks, profileErr := cvProfile(context.profile)
	computedRegistry, registryErr := cvReceiverRegistryDigest(keys, signingKeys)
	if profileErr != nil || registryErr != nil || int(base) != params[4] || chunks != params[5] ||
		!bytes.Equal(computedRegistry, registryDigest) {
		return cvLeafContext{}, fmt.Errorf("inconsistent CV-sAPVSS context parameters")
	}
	if err := cvValidateLeafContext(&context); err != nil {
		return cvLeafContext{}, err
	}
	return context, nil
}

func cvDecodeAggregate(wire []byte) (*cvAggregateTranscript, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(256)
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate domain")
	}
	contextWire, err := r.bytes(cvMaxCanonicalFieldBytes)
	if err != nil {
		return nil, err
	}
	context, err := cvDecodeLeafContext(contextWire)
	if err != nil {
		return nil, err
	}
	contextDigest, err := r.bytes(32)
	if err != nil || !bytes.Equal(contextDigest, cvLeafContextDigest(&context)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate context digest")
	}
	dealerCount, err := r.uint32()
	if err != nil || dealerCount <= 0 || dealerCount > context.profile.maxComponents {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate dealer count")
	}
	const dealerWireBytes = 8 + 4 + 32
	if dealerCount < 0 || dealerCount > r.reader.Len()/dealerWireBytes {
		return nil, fmt.Errorf("aggregate dealer count exceeds remaining wire")
	}
	agg := &cvAggregateTranscript{
		context:     context,
		dealerIDs:   make([]uint64, dealerCount),
		leafDigests: make([][]byte, dealerCount),
	}
	for i := range agg.dealerIDs {
		agg.dealerIDs[i], err = r.uint64()
		if err != nil {
			return nil, err
		}
		agg.leafDigests[i], err = r.bytes(32)
		if err != nil || len(agg.leafDigests[i]) != 32 {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate leaf digest")
		}
	}
	commitmentCount, err := r.uint32()
	if err != nil || commitmentCount < 0 || commitmentCount != context.sharingDegree+1 {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate commitment count")
	}
	if commitmentCount > r.reader.Len()/bls12381.SizeOfG1AffineCompressed {
		return nil, fmt.Errorf("aggregate commitment count exceeds remaining wire")
	}
	agg.coefficientCommitments = make([]bls12381.G1Affine, commitmentCount)
	for i := range agg.coefficientCommitments {
		agg.coefficientCommitments[i], err = r.point()
		if err != nil {
			return nil, err
		}
	}
	receiverCount, err := r.uint32()
	if err != nil || receiverCount != len(context.receiverPublicKeys) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate receiver count")
	}
	_, _, chunks, err := cvProfile(context.profile)
	if err != nil {
		return nil, err
	}
	const ciphertextWireBytes = 2 * bls12381.SizeOfG1AffineCompressed
	receiverCiphertexts := chunks
	if context.proofProfile != cvLeafStructuralProofProfile {
		receiverCiphertexts++
	}
	receiverWireBytes := 4 + bls12381.SizeOfG1AffineCompressed + 4 + receiverCiphertexts*ciphertextWireBytes
	if receiverWireBytes <= 0 || receiverCount < 0 || receiverCount > r.reader.Len()/receiverWireBytes {
		return nil, fmt.Errorf("CV-sAPVSS aggregate receiver count exceeds remaining wire")
	}
	agg.receivers = make([]cvAggregateReceiver, receiverCount)
	for i := range agg.receivers {
		receiver := &agg.receivers[i]
		receiver.receiverIndex, err = r.uint32()
		if err != nil {
			return nil, err
		}
		receiver.receiverPublicKey, err = r.point()
		if err != nil {
			return nil, err
		}
		chunkCount, chunkErr := r.uint32()
		if chunkErr != nil || chunkCount != chunks {
			return nil, fmt.Errorf("invalid CV-sAPVSS aggregate chunk count")
		}
		receiver.scalarChunks = make([]cvElGamalCiphertext, chunkCount)
		for j := range receiver.scalarChunks {
			receiver.scalarChunks[j], err = r.ciphertext()
			if err != nil {
				return nil, err
			}
		}
		if context.proofProfile != cvLeafStructuralProofProfile {
			receiver.blinding, err = r.ciphertext()
			if err != nil {
				return nil, err
			}
		}
	}
	if r.reader.Len() != 0 {
		return nil, fmt.Errorf("trailing CV-sAPVSS aggregate bytes")
	}
	if _, err := cvFinalizeAggregate(agg); err != nil {
		return nil, err
	}
	if !bytes.Equal(agg.digestWire, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS aggregate encoding")
	}
	return agg, nil
}
