package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvLaneACKMessageV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/lane-ack-message"

type cvLaneACKMessageV2 struct {
	DealerID      int
	ReceiverID    int
	ReceiverIndex int
	OfferDigest   []byte
	Evidence      cvACKEvidenceV2
}

type cvPendingLaneACKsV2 struct {
	offers       []*cvReceiverLaneOfferV2
	offerDigests [][]byte
	witnesses    []*cvDealerReceiverWitnessV2
	acks         map[int]*cvACKEvidenceV2
	quorum       int
	frozen       bool
	ready        chan struct{}
	allReady     chan struct{}
}

func cvLaneACKMessageV2CanonicalBytes(message *cvLaneACKMessageV2, context *cvLeafContextV2) ([]byte, error) {
	if message == nil || message.DealerID < 0 || message.ReceiverID < 0 || message.ReceiverIndex <= 0 ||
		len(message.OfferDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK message")
	}
	evidence, err := cvACKEvidenceV2CanonicalBytes(&message.Evidence, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneACKMessageV2Domain))
	cvWriteUint64(&wire, uint64(message.DealerID))
	cvWriteUint64(&wire, uint64(message.ReceiverID))
	_ = cvWriteUint32(&wire, message.ReceiverIndex)
	_ = cvWriteBytes(&wire, message.OfferDigest)
	_ = cvWriteBytes(&wire, evidence)
	return wire.Bytes(), nil
}

func cvDecodeLaneACKMessageV2(wire []byte, context *cvLeafContextV2) (*cvLaneACKMessageV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLaneACKMessageV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneACKMessageV2Domain)) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK message domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK dealer")
	}
	receiver, err := r.uint64()
	if err != nil || receiver > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK receiver")
	}
	index, err := r.uint32()
	if err != nil || index <= 0 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK receiver index")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK offer digest")
	}
	evidenceWire, err := r.bytes(cvMaxLeafProofWireBytes)
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK evidence framing")
	}
	evidence, err := cvDecodeACKEvidenceV2(evidenceWire, context)
	if err != nil {
		return nil, err
	}
	message := &cvLaneACKMessageV2{DealerID: int(dealer), ReceiverID: int(receiver), ReceiverIndex: index,
		OfferDigest: digest, Evidence: *evidence}
	canonical, err := cvLaneACKMessageV2CanonicalBytes(message, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane ACK message")
	}
	return message, nil
}

func cvLaneOfferDigestV2(wire []byte) []byte {
	return hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/lane-offer-digest"), wire)
}

type cvBuiltLeafMaterialV2 struct {
	owner *cvAPDBNetworkServiceV2
	leaf  *cvLeafV2
	wire  []byte
}

func (s *cvAPDBNetworkServiceV2) BuildLeafV2(ctx context.Context) (*cvLeafV2, error) {
	material, err := s.BuildLeafMaterialV2(ctx)
	if err != nil {
		return nil, err
	}
	return material.leaf, nil
}

func (s *cvAPDBNetworkServiceV2) BuildLeafMaterialV2(ctx context.Context) (*cvBuiltLeafMaterialV2, error) {
	if s == nil || ctx == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 network leaf builder")
	}
	coefficientCount := s.cfg.LeafContext.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, coefficientCount)
	blindingCoefficients := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	commitments, coreProof, err := cvProveCoreV2(
		s.cfg.LeafContext, s.cfg.LocalNode, scalarCoefficients, blindingCoefficients,
	)
	if err != nil {
		return nil, err
	}
	quorum := len(s.cfg.NewRoster) - cvNewFaultBoundFromContextV2(s.cfg.LeafContext)
	if quorum <= 0 || quorum > len(s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK quorum")
	}
	pending := &cvPendingLaneACKsV2{
		offers:       make([]*cvReceiverLaneOfferV2, len(s.cfg.NewRoster)),
		offerDigests: make([][]byte, len(s.cfg.NewRoster)),
		witnesses:    make([]*cvDealerReceiverWitnessV2, len(s.cfg.NewRoster)),
		acks:         make(map[int]*cvACKEvidenceV2, quorum), quorum: quorum,
		ready: make(chan struct{}, 1), allReady: make(chan struct{}, 1),
	}
	offerWires := make([][]byte, len(s.cfg.NewRoster))
	buildErrs := make([]error, len(s.cfg.NewRoster))
	buildReceiverLane := func(i int) {
		receiverID := s.cfg.NewRoster[i]
		index := i + 1
		scalar := cvEvaluateScalarPolynomialV2(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialV2(blindingCoefficients, index)
		var err error
		pending.offers[i], pending.witnesses[i], err = cvEncryptReceiverLanesV2(
			s.cfg.LeafContext, s.cfg.LocalNode, receiverID, index,
			&s.cfg.Receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			buildErrs[i] = err
			return
		}
		offerWires[i], err = cvReceiverLaneOfferV2CanonicalBytesAfterValidation(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[i],
		)
		if err == nil {
			pending.offerDigests[i] = cvLaneOfferDigestV2(offerWires[i])
		}
		buildErrs[i] = err
	}
	if workers := cvLeafBuildWorkers(len(s.cfg.NewRoster)); workers > 1 {
		jobs := make(chan int, len(s.cfg.NewRoster))
		for i := range s.cfg.NewRoster {
			jobs <- i
		}
		close(jobs)
		var group sync.WaitGroup
		group.Add(workers)
		for worker := 0; worker < workers; worker++ {
			go func() {
				defer group.Done()
				for i := range jobs {
					buildReceiverLane(i)
				}
			}()
		}
		group.Wait()
	} else {
		for i := range s.cfg.NewRoster {
			buildReceiverLane(i)
		}
	}
	for i := range buildErrs {
		if buildErrs[i] != nil {
			return nil, buildErrs[i]
		}
	}
	s.mu.Lock()
	shardBytes := s.cfg.ShardBytes
	s.mu.Unlock()
	if shardBytes == 0 {
		shardBytes, err = cvEpochShardBytesUpperBoundV2(
			s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers, s.cfg.Validators, s.cfg.DataShards,
		)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		if s.cfg.ShardBytes == 0 {
			s.cfg.ShardBytes = shardBytes
		} else if s.cfg.ShardBytes != shardBytes {
			s.mu.Unlock()
			return nil, fmt.Errorf("CV V2 epoch shard size mismatch")
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	if s.pendingLaneACKsV2 != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 lane ACK collection already active")
	}
	s.pendingLaneACKsV2 = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingLaneACKsV2 == pending {
			s.pendingLaneACKsV2 = nil
		}
		s.mu.Unlock()
	}()
	sentOffers := 0
	var lastSendErr error
	offersByReceiver := make(map[int][]byte, len(s.cfg.NewRoster))
	for i, receiver := range s.cfg.NewRoster {
		offersByReceiver[receiver] = offerWires[i]
	}
	for _, result := range s.sendRecipientPayloadFanoutMeasuredV2(
		s.cfg.NewRoster, cvTagLaneOfferV2, offersByReceiver,
	) {
		if result.err != nil {
			lastSendErr = result.err
			continue
		}
		sentOffers++
	}
	if sentOffers < quorum {
		return nil, fmt.Errorf("CV V2 lane offer delivery incomplete: sent=%d quorum=%d: %w", sentOffers, quorum, lastSendErr)
	}
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("CV V2 lane ACK quorum incomplete: %w", ctx.Err())
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
	}
	if grace := cvACKSettleGraceV2(); grace > 0 {
		timer := time.NewTimer(grace)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-s.ctx.Done():
			timer.Stop()
			return nil, s.ctx.Err()
		case <-pending.allReady:
			timer.Stop()
		case <-timer.C:
		}
	}
	acks := make([]*cvACKEvidenceV2, len(s.cfg.NewRoster))
	partition := &cvEvidencePartitionV2{}
	fallbackOffers := make([]*cvReceiverLaneOfferV2, 0, len(s.cfg.NewRoster)-quorum)
	fallbackKeys := make([]bls12381.G1Affine, 0, len(s.cfg.NewRoster)-quorum)
	fallbackWitnesses := make([]*cvDealerReceiverWitnessV2, 0, len(s.cfg.NewRoster)-quorum)
	s.mu.Lock()
	pending.frozen = true
	for index := 1; index <= len(s.cfg.NewRoster); index++ {
		if ack, ok := pending.acks[index]; ok {
			acks[index-1] = ack
			partition.ACKReceiverIndices = append(partition.ACKReceiverIndices, index)
			continue
		}
		partition.FallbackReceiverIndices = append(partition.FallbackReceiverIndices, index)
		fallbackOffers = append(fallbackOffers, pending.offers[index-1])
		fallbackKeys = append(fallbackKeys, s.cfg.Receivers.encryptionPublicKeys[index-1])
		fallbackWitnesses = append(fallbackWitnesses, pending.witnesses[index-1])
	}
	s.mu.Unlock()
	var fallback *cvFallbackEvidenceV2
	if len(fallbackOffers) > 0 {
		fallback, err = cvBuildFallbackEvidenceV2(
			s.cfg.LeafContext, s.cfg.LocalNode, fallbackOffers, fallbackKeys, fallbackWitnesses,
		)
		if err != nil {
			return nil, err
		}
	}
	leaf, wire, err := cvBuildLeafMaterialAfterValidationV2(
		s.cfg.LeafContext, s.cfg.LocalNode, commitments, coreProof, pending.offers, acks, partition, fallback,
		s.cfg.Receivers, s.cfg.Validators,
	)
	if err != nil {
		return nil, err
	}
	return &cvBuiltLeafMaterialV2{owner: s, leaf: leaf, wire: wire}, nil
}

func cvEpochShardBytesUpperBoundV2(
	context *cvLeafContextV2, params cvV2Params, receivers *cvReceiverKeyMaterialV2,
	validators *cvValidatorKeyMaterialV2, dataShards int,
) (int, error) {
	if context == nil || receivers == nil || validators == nil || dataShards <= 0 || len(context.OldRoster) == 0 ||
		params.componentCount <= 0 || params.componentCount > len(context.OldRoster) ||
		params.newFaults != cvNewFaultBoundFromContextV2(context) || params.newShareDegree != context.SharingDegree {
		return 0, fmt.Errorf("invalid CV V2 epoch shard sizing input")
	}
	if err := cvValidateReceiverMaterialForLeafV2(context, receivers); err != nil {
		return 0, err
	}
	if err := cvValidateValidatorMaterialForLeafV2(context, validators); err != nil {
		return 0, err
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return 0, err
	}
	maxWireBytes := 0
	newFaults := cvNewFaultBoundFromContextV2(context)
	for fallbackCount := 0; fallbackCount <= newFaults; fallbackCount++ {
		wireBytes, err := cvLeafWireSizeV2(context, chunks, fallbackCount)
		if err != nil {
			return 0, err
		}
		if wireBytes > maxWireBytes {
			maxWireBytes = wireBytes
		}
	}
	aggregateWireBytes := cvAggregateWireSizeV2(context, params, chunks)
	if aggregateWireBytes > maxWireBytes {
		maxWireBytes = aggregateWireBytes
	}
	return (8 + maxWireBytes + dataShards - 1) / dataShards, nil
}

func cvLeafWireSizeV2(context *cvLeafContextV2, chunks, fallbackCount int) (int, error) {
	if context == nil || chunks <= 0 || fallbackCount < 0 || fallbackCount > cvNewFaultBoundFromContextV2(context) {
		return 0, fmt.Errorf("invalid CV V2 leaf sizing input")
	}
	contextWire, err := cvLeafContextV2CanonicalBytes(context)
	if err != nil {
		return 0, err
	}
	receivers := len(context.NewRoster)
	coefficients := context.SharingDegree + 1
	ackCount := receivers - fallbackCount
	pointBytes := bls12381.SizeOfG1AffineCompressed
	ciphertextBytes := 2 * pointBytes

	coreProofBytes := cvFramedWireSizeV2(len(cvCoreProofWireDomainV2)) +
		cvPointVectorWireSizeV2(coefficients) + 2*cvScalarVectorWireSizeV2(coefficients)
	ownershipProofBytes := cvFramedWireSizeV2(len(cvOwnershipProofWireDomainV2)) +
		2*cvPointVectorWireSizeV2(chunks) + 3*pointBytes +
		2*cvScalarVectorWireSizeV2(chunks) + 2*fr.Bytes
	fallbackLaneBytes := cvLaneWireSizeV2(len(cvFallbackLaneWireDomainV2), chunks, ciphertextBytes)
	ackLaneBytes := cvLaneWireSizeV2(len(cvLaneOfferWireDomainV2), chunks, ciphertextBytes) +
		cvFramedWireSizeV2(ownershipProofBytes)
	ackEvidenceBytes := cvFramedWireSizeV2(len(cvACKWireDomainV2)) +
		cvFramedWireSizeV2(ownershipProofBytes) + cvFramedWireSizeV2(ed25519.SignatureSize)
	partitionBytes := cvFramedWireSizeV2(len(cvEvidencePartitionWireDomainV2)) +
		cvFramedWireSizeV2(32) + 2*4 + receivers*4

	unsignedBytes := cvFramedWireSizeV2(len(cvLeafUnsignedWireDomainV2)) +
		cvFramedWireSizeV2(len(contextWire)) + 8 + cvPointVectorWireSizeV2(coefficients) +
		cvFramedWireSizeV2(coreProofBytes) + cvFramedWireSizeV2(partitionBytes) + 4
	unsignedBytes += fallbackCount * (4 + cvFramedWireSizeV2(fallbackLaneBytes))
	unsignedBytes += ackCount * (4 + cvFramedWireSizeV2(ackLaneBytes) + cvFramedWireSizeV2(ackEvidenceBytes))
	if fallbackCount == 0 {
		unsignedBytes += cvFramedWireSizeV2(0)
	} else {
		fallbackBytes, err := cvFallbackEvidenceWireSizeV2(context, chunks, fallbackCount)
		if err != nil {
			return 0, err
		}
		unsignedBytes += cvFramedWireSizeV2(fallbackBytes)
	}
	return cvFramedWireSizeV2(len(cvLeafWireDomainV2)) + cvFramedWireSizeV2(unsignedBytes) +
		cvFramedWireSizeV2(bls12381.SizeOfG1AffineCompressed), nil
}

func cvLaneWireSizeV2(domainBytes, chunks, ciphertextBytes int) int {
	return cvFramedWireSizeV2(domainBytes) + cvFramedWireSizeV2(32) + 8 + 8 + 4 +
		bls12381.SizeOfG1AffineCompressed + 4 + chunks*ciphertextBytes + ciphertextBytes
}

func cvFallbackEvidenceWireSizeV2(context *cvLeafContextV2, chunks, fallbackCount int) (int, error) {
	total := chunks * fallbackCount
	pointBytes := bls12381.SizeOfG1AffineCompressed
	linkBytes := cvFramedWireSizeV2(len(cvFallbackLinkWireDomainV2)) + 7*4 +
		(4*total+3*fallbackCount)*pointBytes + 5*4 + (3*total+2*fallbackCount)*fr.Bytes
	_, vectorSize, err := apvssCompactRangeDimensions(total, int(context.Profile.chunkBits))
	if err != nil {
		return 0, err
	}
	rounds := 0
	for size := vectorSize; size > 1; size >>= 1 {
		rounds++
	}
	compactRangeBytes := 2*4 + 4*pointBytes + 3*fr.Bytes + 4 +
		2*rounds*pointBytes + 2*fr.Bytes
	rangeBytes := cvFramedWireSizeV2(len(cvFallbackRangeWireDomainV2)) +
		cvFramedWireSizeV2(len(cvFallbackRangeBackendV2)) + cvFramedWireSizeV2(compactRangeBytes)
	return cvFramedWireSizeV2(len(cvFallbackEvidenceWireDomainV2)) + (4 + fallbackCount*4) +
		cvFramedWireSizeV2(linkBytes) + cvFramedWireSizeV2(rangeBytes), nil
}

func cvAggregateWireSizeV2(context *cvLeafContextV2, params cvV2Params, chunks int) int {
	pointBytes := bls12381.SizeOfG1AffineCompressed
	ciphertextBytes := 2 * pointBytes
	unsignedBytes := cvFramedWireSizeV2(len(cvAggregateWireV2Domain)) + cvFramedWireSizeV2(32) + 4 +
		params.componentCount*(8+cvFramedWireSizeV2(32)) +
		cvPointVectorWireSizeV2(context.SharingDegree+1) + 4 +
		len(context.NewRoster)*(8+8+pointBytes+4+(chunks+1)*ciphertextBytes)
	return cvFramedWireSizeV2(unsignedBytes) + cvFramedWireSizeV2(32)
}

func cvFramedWireSizeV2(payloadBytes int) int {
	return 4 + payloadBytes
}

func cvPointVectorWireSizeV2(points int) int {
	return 4 + points*bls12381.SizeOfG1AffineCompressed
}

func cvScalarVectorWireSizeV2(scalars int) int {
	return 4 + scalars*fr.Bytes
}
