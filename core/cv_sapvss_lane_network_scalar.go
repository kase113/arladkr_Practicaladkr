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

const cvLaneACKMessageScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/lane-ack-message"

type cvLaneACKMessageScalar struct {
	DealerID      int
	ReceiverID    int
	ReceiverIndex int
	OfferDigest   []byte
	Evidence      cvACKEvidenceScalar
}

type cvPendingLaneACKsScalar struct {
	offers       []*cvReceiverLaneOfferScalar
	offerDigests [][]byte
	witnesses    []*cvDealerReceiverWitnessScalar
	acks         map[int]*cvACKEvidenceScalar
	quorum       int
	frozen       bool
	ready        chan struct{}
	allReady     chan struct{}
}

func cvLaneACKMessageScalarCanonicalBytes(message *cvLaneACKMessageScalar, context *cvLeafContextScalar) ([]byte, error) {
	if message == nil || message.DealerID < 0 || message.ReceiverID < 0 || message.ReceiverIndex <= 0 ||
		len(message.OfferDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 lane ACK message")
	}
	evidence, err := cvACKEvidenceScalarCanonicalBytes(&message.Evidence, context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvLaneACKMessageScalarDomain))
	cvWriteUint64(&wire, uint64(message.DealerID))
	cvWriteUint64(&wire, uint64(message.ReceiverID))
	_ = cvWriteUint32(&wire, message.ReceiverIndex)
	_ = cvWriteBytes(&wire, message.OfferDigest)
	_ = cvWriteBytes(&wire, evidence)
	return wire.Bytes(), nil
}

func cvDecodeLaneACKMessageScalar(wire []byte, context *cvLeafContextScalar) (*cvLaneACKMessageScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvLaneACKMessageScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvLaneACKMessageScalarDomain)) {
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
	evidence, err := cvDecodeACKEvidenceScalar(evidenceWire, context)
	if err != nil {
		return nil, err
	}
	message := &cvLaneACKMessageScalar{DealerID: int(dealer), ReceiverID: int(receiver), ReceiverIndex: index,
		OfferDigest: digest, Evidence: *evidence}
	canonical, err := cvLaneACKMessageScalarCanonicalBytes(message, context)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 lane ACK message")
	}
	return message, nil
}

func cvLaneOfferDigestScalar(wire []byte) []byte {
	return hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/lane-offer-digest"), wire)
}

type cvBuiltLeafMaterialScalar struct {
	owner *cvAPDBNetworkServiceScalar
	leaf  *cvLeafScalar
	wire  []byte
}

func (s *cvAPDBNetworkServiceScalar) BuildLeafScalar(ctx context.Context) (*cvLeafScalar, error) {
	material, err := s.BuildLeafMaterialScalar(ctx)
	if err != nil {
		return nil, err
	}
	return material.leaf, nil
}

func (s *cvAPDBNetworkServiceScalar) BuildLeafMaterialScalar(ctx context.Context) (*cvBuiltLeafMaterialScalar, error) {
	if s == nil || ctx == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil ||
		!cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) {
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
	commitments, coreProof, err := cvProveCoreScalar(
		s.cfg.LeafContext, s.cfg.LocalNode, scalarCoefficients, blindingCoefficients,
	)
	if err != nil {
		return nil, err
	}
	quorum := len(s.cfg.NewRoster) - cvNewFaultBoundFromContextScalar(s.cfg.LeafContext)
	if quorum <= 0 || quorum > len(s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 lane ACK quorum")
	}
	pending := &cvPendingLaneACKsScalar{
		offers:       make([]*cvReceiverLaneOfferScalar, len(s.cfg.NewRoster)),
		offerDigests: make([][]byte, len(s.cfg.NewRoster)),
		witnesses:    make([]*cvDealerReceiverWitnessScalar, len(s.cfg.NewRoster)),
		acks:         make(map[int]*cvACKEvidenceScalar, quorum), quorum: quorum,
		ready: make(chan struct{}, 1), allReady: make(chan struct{}, 1),
	}
	offerWires := make([][]byte, len(s.cfg.NewRoster))
	buildErrs := make([]error, len(s.cfg.NewRoster))
	buildReceiverLane := func(i int) {
		receiverID := s.cfg.NewRoster[i]
		index := i + 1
		scalar := cvEvaluateScalarPolynomialScalar(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialScalar(blindingCoefficients, index)
		var err error
		pending.offers[i], pending.witnesses[i], err = cvEncryptReceiverLanesScalar(
			s.cfg.LeafContext, s.cfg.LocalNode, receiverID, index,
			&s.cfg.Receivers.encryptionPublicKeys[i], scalar, blinding,
		)
		if err != nil {
			buildErrs[i] = err
			return
		}
		offerWires[i], err = cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[i],
		)
		if err == nil {
			pending.offerDigests[i] = cvLaneOfferDigestScalar(offerWires[i])
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
		shardBytes, err = cvEpochShardBytesUpperBoundScalar(
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
	if s.pendingLaneACKsScalar != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 lane ACK collection already active")
	}
	s.pendingLaneACKsScalar = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingLaneACKsScalar == pending {
			s.pendingLaneACKsScalar = nil
		}
		s.mu.Unlock()
	}()
	sentOffers := 0
	var lastSendErr error
	offersByReceiver := make(map[int][]byte, len(s.cfg.NewRoster))
	for i, receiver := range s.cfg.NewRoster {
		offersByReceiver[receiver] = offerWires[i]
	}
	for _, result := range s.sendRecipientPayloadFanoutMeasuredScalar(
		s.cfg.NewRoster, cvTagLaneOfferScalar, offersByReceiver,
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
	if grace := cvACKSettleGraceScalar(); grace > 0 {
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
	acks := make([]*cvACKEvidenceScalar, len(s.cfg.NewRoster))
	partition := &cvEvidencePartitionScalar{}
	fallbackOffers := make([]*cvReceiverLaneOfferScalar, 0, len(s.cfg.NewRoster)-quorum)
	fallbackKeys := make([]bls12381.G1Affine, 0, len(s.cfg.NewRoster)-quorum)
	fallbackWitnesses := make([]*cvDealerReceiverWitnessScalar, 0, len(s.cfg.NewRoster)-quorum)
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
	var fallback *cvFallbackEvidenceScalar
	if len(fallbackOffers) > 0 {
		fallback, err = cvBuildFallbackEvidenceScalar(
			s.cfg.LeafContext, s.cfg.LocalNode, fallbackOffers, fallbackKeys, fallbackWitnesses,
		)
		if err != nil {
			return nil, err
		}
	}
	leaf, wire, err := cvBuildLeafMaterialAfterValidationScalar(
		s.cfg.LeafContext, s.cfg.LocalNode, commitments, coreProof, pending.offers, acks, partition, fallback,
		s.cfg.Receivers, s.cfg.Validators,
	)
	if err != nil {
		return nil, err
	}
	return &cvBuiltLeafMaterialScalar{owner: s, leaf: leaf, wire: wire}, nil
}

func cvEpochShardBytesUpperBoundScalar(
	context *cvLeafContextScalar, params cvScalarParams, receivers *cvReceiverKeyMaterialScalar,
	validators *cvValidatorKeyMaterialScalar, dataShards int,
) (int, error) {
	if context == nil || receivers == nil || validators == nil || dataShards <= 0 || len(context.OldRoster) == 0 ||
		params.componentCount <= 0 || params.componentCount > len(context.OldRoster) ||
		params.newFaults != cvNewFaultBoundFromContextScalar(context) || params.newShareDegree != context.SharingDegree {
		return 0, fmt.Errorf("invalid CV V2 epoch shard sizing input")
	}
	if err := cvValidateReceiverMaterialForLeafScalar(context, receivers); err != nil {
		return 0, err
	}
	if err := cvValidateValidatorMaterialForLeafScalar(context, validators); err != nil {
		return 0, err
	}
	chunks, err := cvChunkCount(context.Profile)
	if err != nil {
		return 0, err
	}
	maxWireBytes := 0
	newFaults := cvNewFaultBoundFromContextScalar(context)
	for fallbackCount := 0; fallbackCount <= newFaults; fallbackCount++ {
		wireBytes, err := cvLeafWireSizeScalar(context, chunks, fallbackCount)
		if err != nil {
			return 0, err
		}
		if wireBytes > maxWireBytes {
			maxWireBytes = wireBytes
		}
	}
	aggregateWireBytes := cvAggregateWireSizeScalar(context, params, chunks)
	if aggregateWireBytes > maxWireBytes {
		maxWireBytes = aggregateWireBytes
	}
	return (8 + maxWireBytes + dataShards - 1) / dataShards, nil
}

func cvLeafWireSizeScalar(context *cvLeafContextScalar, chunks, fallbackCount int) (int, error) {
	if context == nil || chunks <= 0 || fallbackCount < 0 || fallbackCount > cvNewFaultBoundFromContextScalar(context) {
		return 0, fmt.Errorf("invalid CV V2 leaf sizing input")
	}
	contextWire, err := cvLeafContextScalarCanonicalBytes(context)
	if err != nil {
		return 0, err
	}
	receivers := len(context.NewRoster)
	coefficients := context.SharingDegree + 1
	ackCount := receivers - fallbackCount
	pointBytes := bls12381.SizeOfG1AffineCompressed
	ciphertextBytes := 2 * pointBytes

	coreProofBytes := cvFramedWireSizeScalar(len(cvCoreProofWireDomainScalar)) +
		cvPointVectorWireSizeScalar(coefficients) + 2*cvScalarVectorWireSizeScalar(coefficients)
	ownershipProofBytes := cvFramedWireSizeScalar(len(cvOwnershipProofWireDomainScalar)) +
		2*cvPointVectorWireSizeScalar(chunks) + 3*pointBytes +
		2*cvScalarVectorWireSizeScalar(chunks) + 2*fr.Bytes
	fallbackLaneBytes := cvLaneWireSizeScalar(len(cvFallbackLaneWireDomainScalar), chunks, ciphertextBytes)
	ackLaneBytes := cvLaneWireSizeScalar(len(cvLaneOfferWireDomainScalar), chunks, ciphertextBytes) +
		cvFramedWireSizeScalar(ownershipProofBytes)
	ackEvidenceBytes := cvFramedWireSizeScalar(len(cvACKWireDomainScalar)) +
		cvFramedWireSizeScalar(ownershipProofBytes) + cvFramedWireSizeScalar(ed25519.SignatureSize)
	partitionBytes := cvFramedWireSizeScalar(len(cvEvidencePartitionWireDomainScalar)) +
		cvFramedWireSizeScalar(32) + 2*4 + receivers*4

	unsignedBytes := cvFramedWireSizeScalar(len(cvLeafUnsignedWireDomainScalar)) +
		cvFramedWireSizeScalar(len(contextWire)) + 8 + cvPointVectorWireSizeScalar(coefficients) +
		cvFramedWireSizeScalar(coreProofBytes) + cvFramedWireSizeScalar(partitionBytes) + 4
	unsignedBytes += fallbackCount * (4 + cvFramedWireSizeScalar(fallbackLaneBytes))
	unsignedBytes += ackCount * (4 + cvFramedWireSizeScalar(ackLaneBytes) + cvFramedWireSizeScalar(ackEvidenceBytes))
	if fallbackCount == 0 {
		unsignedBytes += cvFramedWireSizeScalar(0)
	} else {
		fallbackBytes, err := cvFallbackEvidenceWireSizeScalar(context, chunks, fallbackCount)
		if err != nil {
			return 0, err
		}
		unsignedBytes += cvFramedWireSizeScalar(fallbackBytes)
	}
	return cvFramedWireSizeScalar(len(cvLeafWireDomainScalar)) + cvFramedWireSizeScalar(unsignedBytes) +
		cvFramedWireSizeScalar(bls12381.SizeOfG1AffineCompressed), nil
}

func cvLaneWireSizeScalar(domainBytes, chunks, ciphertextBytes int) int {
	return cvFramedWireSizeScalar(domainBytes) + cvFramedWireSizeScalar(32) + 8 + 8 + 4 +
		bls12381.SizeOfG1AffineCompressed + 4 + chunks*ciphertextBytes + ciphertextBytes
}

func cvFallbackEvidenceWireSizeScalar(context *cvLeafContextScalar, chunks, fallbackCount int) (int, error) {
	total := chunks * fallbackCount
	pointBytes := bls12381.SizeOfG1AffineCompressed
	linkBytes := cvFramedWireSizeScalar(len(cvFallbackLinkWireDomainScalar)) + 7*4 +
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
	rangeBytes := cvFramedWireSizeScalar(len(cvFallbackRangeWireDomainScalar)) +
		cvFramedWireSizeScalar(len(cvFallbackRangeBackendScalar)) + cvFramedWireSizeScalar(compactRangeBytes)
	return cvFramedWireSizeScalar(len(cvFallbackEvidenceWireDomainScalar)) + (4 + fallbackCount*4) +
		cvFramedWireSizeScalar(linkBytes) + cvFramedWireSizeScalar(rangeBytes), nil
}

func cvAggregateWireSizeScalar(context *cvLeafContextScalar, params cvScalarParams, chunks int) int {
	pointBytes := bls12381.SizeOfG1AffineCompressed
	ciphertextBytes := 2 * pointBytes
	unsignedBytes := cvFramedWireSizeScalar(len(cvAggregateWireScalarDomain)) + cvFramedWireSizeScalar(32) + 4 +
		params.componentCount*(8+cvFramedWireSizeScalar(32)) +
		cvPointVectorWireSizeScalar(context.SharingDegree+1) + 4 +
		len(context.NewRoster)*(8+8+pointBytes+4+(chunks+1)*ciphertextBytes)
	return cvFramedWireSizeScalar(unsignedBytes) + cvFramedWireSizeScalar(32)
}

func cvFramedWireSizeScalar(payloadBytes int) int {
	return 4 + payloadBytes
}

func cvPointVectorWireSizeScalar(points int) int {
	return 4 + points*bls12381.SizeOfG1AffineCompressed
}

func cvScalarVectorWireSizeScalar(scalars int) int {
	return 4 + scalars*fr.Bytes
}
