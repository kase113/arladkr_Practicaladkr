package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
)

const (
	cvNetworkEnvelopeVersion              = byte(1)
	cvMaxNetworkEnvelopeSIDBytes          = 1 << 20
	cvMaxNetworkPayloadBytes              = cvMaxLeafWireBytes + 1<<20
	cvNetworkEnvelopeFixedBytes           = 1 + 4 + 8 + 4
	cvTagComponentInit                    = "CV_COMPONENT_INIT"
	cvTagComponentAck                     = "CV_COMPONENT_ACK"
	cvTagComponentCert                    = "CV_COMPONENT_CERT"
	cvTagComponentGet                     = "CV_COMPONENT_GET"
	cvTagComponentLeaf                    = "CV_COMPONENT_LEAF"
	cvTagComponentReady                   = "CV_COMPONENT_READY"
	cvTagEligibilityShare                 = "CV_ELIGIBILITY_SHARE"
	cvTagAggregateManifest                = "CV_AGG_MANIFEST"
	cvTagARCShare                         = "CV_ARC_SHARE"
	cvTagARCCertificate                   = "CV_ARC_CERTIFICATE"
	cvTagRecoverGet                       = "CV_RECOVER_GET"
	cvTagRecoverShard                     = "CV_RECOVER_SHARD"
	cvTagRecoverDone                      = "CV_RECOVER_DONE"
	cvTagReceipt                          = "CV_RECEIPT"
	cvTagReceiptDone                      = "CV_RECEIPT_DONE"
	apvssTagLaneOffer                     = "APVSS_LANE_OFFER"
	apvssTagLaneACK                       = "APVSS_LANE_ACK"
	cvTagHandoffScalar                    = "CV_V2_HANDOFF"
	cvTagAPDBStoreScalar                  = "CV_V2_APDB_STORE"
	cvTagAPDBStoredShareScalar            = "CV_V2_APDB_STORED_SHARE"
	cvTagAggregateAPDBStoreScalar         = "CV_V2_ARC__STORE"
	cvTagAggregateARCShareScalar          = "CV_V2_ARC__STORED_SHARE"
	cvTagAPDBRecoverGetScalar             = "CV_V2_APDB_RECOVER_GET"
	cvTagAPDBRecoverStoreScalar           = "CV_V2_APDB_RECOVER_STORE"
	cvTagAPDBRecoverPayloadScalar         = "CV_V2_APDB_RECOVER_PAYLOAD"
	cvTagAggregateRecoverGetScalar        = "CV_V2_AGG_RECOVER_GET"
	cvTagAggregateRecoverCancelScalar     = "CV_V2_AGG_RECOVER_CANCEL"
	cvTagAggregateRecoverStoreScalar      = "CV_V2_AGG_RECOVER_STORE"
	cvTagAggregatePayloadGetScalar        = "CV_V2_AGG_PAYLOAD_GET"
	cvTagAggregatePayloadScalar           = "CV_V2_AGG_PAYLOAD"
	cvTagCoinShareScalar                  = "CV_V2_COIN_SHARE"
	cvTagPoolOfferScalar                  = "CV_V2_POOL_OFFER"
	cvTagPoolCertShareScalar              = "CV_V2_POOL_CERT_SHARE"
	cvTagPoolCertScalar                   = "CV_V2_POOL_CERT"
	cvTagValidationRequestScalar          = "CV_V2_VALIDATION_REQUEST"
	cvTagValidationSignatureScalar        = "CV_V2_VALIDATION_SIGNATURE"
	cvTagValidationResultScalar           = "CV_V2_VALIDATION_RESULT"
	cvTagDecisionShareScalar              = "CV_V2_DECISION_SHARE"
	cvTagAggregateShareScalar             = "CV_V2_AGGREGATE_SHARE"
	cvTagLaneOfferScalar                  = "CV_V2_LANE_OFFER"
	cvTagLaneACKScalar                    = "CV_V2_LANE_ACK"
	cvTagComponentRefScalar               = "CV_V2_COMPONENT_REF"
	cvTagCertifiedCandidateScalar         = "CV_V2_CERTIFIED_CANDIDATE"
	cvTagCertifiedCandidateACKScalar      = "CV_V2_CERTIFIED_CANDIDATE_ACK"
	cvTagCertifiedCandidateACKProbeScalar = "CV_V2_CERTIFIED_CANDIDATE_ACK_PROBE"
	cvTagCertifiedCandidateAnnounceScalar = "CV_V2_CERTIFIED_CANDIDATE_ANNOUNCE"
	cvTagCertifiedCandidateFetchScalar    = "CV_V2_CERTIFIED_CANDIDATE_FETCH"
	cvTagCertifiedCandidateResponseScalar = "CV_V2_CERTIFIED_CANDIDATE_RESPONSE"
)

func cvAllowedNetworkTag(tag string) bool {
	switch tag {
	case cvTagComponentInit,
		cvTagComponentAck,
		cvTagComponentCert,
		cvTagComponentGet,
		cvTagComponentLeaf,
		cvTagComponentReady,
		cvTagEligibilityShare,
		cvTagAggregateManifest,
		cvTagARCShare,
		cvTagARCCertificate,
		cvTagRecoverGet,
		cvTagRecoverShard,
		cvTagRecoverDone,
		cvTagReceipt,
		cvTagReceiptDone,
		apvssTagLaneOffer,
		apvssTagLaneACK,
		cvTagHandoffScalar,
		cvTagAPDBStoreScalar,
		cvTagAPDBStoredShareScalar,
		cvTagAggregateAPDBStoreScalar,
		cvTagAggregateARCShareScalar,
		cvTagAPDBRecoverGetScalar,
		cvTagAPDBRecoverStoreScalar,
		cvTagAPDBRecoverPayloadScalar,
		cvTagAggregateRecoverGetScalar,
		cvTagAggregateRecoverCancelScalar,
		cvTagAggregateRecoverStoreScalar,
		cvTagAggregatePayloadGetScalar,
		cvTagAggregatePayloadScalar,
		cvTagCoinShareScalar,
		cvTagPoolOfferScalar,
		cvTagPoolCertShareScalar,
		cvTagPoolCertScalar,
		cvTagValidationRequestScalar,
		cvTagValidationSignatureScalar,
		cvTagValidationResultScalar,
		cvTagDecisionShareScalar,
		cvTagAggregateShareScalar:
		return true
	case cvTagLaneOfferScalar, cvTagLaneACKScalar, cvTagComponentRefScalar, cvTagCertifiedCandidateScalar,
		cvTagCertifiedCandidateACKScalar, cvTagCertifiedCandidateACKProbeScalar, cvTagCertifiedCandidateAnnounceScalar,
		cvTagCertifiedCandidateFetchScalar, cvTagCertifiedCandidateResponseScalar:
		return true
	default:
		return false
	}
}

func cvEncodeNetworkEnvelope(sid string, epoch int, payload []byte) ([]byte, error) {
	if sid == "" || len(sid) > cvMaxNetworkEnvelopeSIDBytes || epoch < 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS network envelope context")
	}
	if len(payload) > cvMaxNetworkPayloadBytes {
		return nil, fmt.Errorf("CV-sAPVSS network payload exceeds limit")
	}
	wire := make([]byte, cvNetworkEnvelopeFixedBytes+len(sid)+len(payload))
	wire[0] = cvNetworkEnvelopeVersion
	offset := 1
	binary.BigEndian.PutUint32(wire[offset:offset+4], uint32(len(sid)))
	offset += 4
	copy(wire[offset:offset+len(sid)], sid)
	offset += len(sid)
	binary.BigEndian.PutUint64(wire[offset:offset+8], uint64(epoch))
	offset += 8
	binary.BigEndian.PutUint32(wire[offset:offset+4], uint32(len(payload)))
	offset += 4
	copy(wire[offset:], payload)
	return wire, nil
}

func cvDecodeNetworkEnvelope(wire []byte, expectedSID string, expectedEpoch int) ([]byte, error) {
	if expectedSID == "" || len(expectedSID) > cvMaxNetworkEnvelopeSIDBytes || expectedEpoch < 0 {
		return nil, fmt.Errorf("invalid expected CV-sAPVSS network context")
	}
	maximum := cvNetworkEnvelopeFixedBytes + len(expectedSID) + cvMaxNetworkPayloadBytes
	if len(wire) < cvNetworkEnvelopeFixedBytes+len(expectedSID) || len(wire) > maximum || wire[0] != cvNetworkEnvelopeVersion {
		return nil, fmt.Errorf("invalid CV-sAPVSS network envelope framing")
	}
	offset := 1
	sidLength := int(binary.BigEndian.Uint32(wire[offset : offset+4]))
	offset += 4
	if sidLength != len(expectedSID) || sidLength > len(wire)-offset ||
		!bytes.Equal(wire[offset:offset+sidLength], []byte(expectedSID)) {
		return nil, fmt.Errorf("CV-sAPVSS network envelope SID mismatch")
	}
	offset += sidLength
	if len(wire)-offset < 12 || binary.BigEndian.Uint64(wire[offset:offset+8]) != uint64(expectedEpoch) {
		return nil, fmt.Errorf("CV-sAPVSS network envelope epoch mismatch")
	}
	offset += 8
	payloadLength := int(binary.BigEndian.Uint32(wire[offset : offset+4]))
	offset += 4
	if payloadLength > cvMaxNetworkPayloadBytes || payloadLength != len(wire)-offset {
		return nil, fmt.Errorf("invalid CV-sAPVSS network payload length")
	}
	return append([]byte(nil), wire[offset:]...), nil
}

type cvSAPVSSRouter struct {
	ctx      context.Context
	cancel   context.CancelFunc
	sid      string
	epoch    int
	oldNodes map[int]struct{}
	newNodes map[int]struct{}
	auth     cvNetworkEnvelopeOpener
	queues   map[int]chan Message
	errors   chan error
	done     chan struct{}
	wait     sync.WaitGroup
	failOnce sync.Once
}

type cvNetworkEnvelopeOpener interface {
	open(from, to int, tag string, wire []byte) ([]byte, error)
}

func newCVSAPVSSRouter(
	ctx context.Context,
	transport agreementTransport,
	sid string,
	epoch int,
	oldNodes, localOldNodes []int,
	queueCapacity int,
) (*cvSAPVSSRouter, error) {
	return newCVSAPVSSRouterWithReceivers(
		ctx, transport, sid, epoch, oldNodes, nil, localOldNodes, queueCapacity,
	)
}

func newCVSAPVSSRouterWithReceivers(
	ctx context.Context,
	transport agreementTransport,
	sid string,
	epoch int,
	oldNodes, newNodes, localNodes []int,
	queueCapacity int,
	authenticators ...cvNetworkEnvelopeOpener,
) (*cvSAPVSSRouter, error) {
	if ctx == nil || transport == nil || sid == "" || len(sid) > cvMaxNetworkEnvelopeSIDBytes ||
		epoch < 0 || queueCapacity <= 0 || len(oldNodes) == 0 || len(localNodes) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS router configuration")
	}
	oldSet := make(map[int]struct{}, len(oldNodes))
	for _, node := range oldNodes {
		if node < 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS old-node ID: %d", node)
		}
		if _, duplicate := oldSet[node]; duplicate {
			return nil, fmt.Errorf("duplicate CV-sAPVSS old-node ID: %d", node)
		}
		oldSet[node] = struct{}{}
	}
	newSet := make(map[int]struct{}, len(newNodes))
	for _, node := range newNodes {
		if node < 0 {
			return nil, fmt.Errorf("invalid APVSS new-node ID: %d", node)
		}
		if _, duplicate := newSet[node]; duplicate {
			return nil, fmt.Errorf("duplicate APVSS new-node ID: %d", node)
		}
		newSet[node] = struct{}{}
	}
	inboxes := make(map[int]<-chan Message, len(localNodes))
	for _, node := range localNodes {
		_, oldOK := oldSet[node]
		_, newOK := newSet[node]
		if !oldOK && !newOK {
			return nil, fmt.Errorf("local APVSS node %d is outside both rosters", node)
		}
		if _, duplicate := inboxes[node]; duplicate {
			return nil, fmt.Errorf("duplicate local CV-sAPVSS node ID: %d", node)
		}
		inbox, err := transport.RecvChan(node)
		if err != nil {
			return nil, fmt.Errorf("open CV-sAPVSS inbox for node %d: %w", node, err)
		}
		if inbox == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS inbox for node %d", node)
		}
		inboxes[node] = inbox
	}
	routerContext, cancel := context.WithCancel(ctx)
	var auth cvNetworkEnvelopeOpener
	if len(authenticators) > 0 {
		auth = authenticators[0]
	}
	router := &cvSAPVSSRouter{
		ctx:      routerContext,
		cancel:   cancel,
		sid:      sid,
		epoch:    epoch,
		oldNodes: oldSet,
		newNodes: newSet,
		auth:     auth,
		queues:   make(map[int]chan Message, len(inboxes)),
		errors:   make(chan error, 1),
		done:     make(chan struct{}),
	}
	for node, inbox := range inboxes {
		queue := make(chan Message, queueCapacity)
		router.queues[node] = queue
		router.wait.Add(1)
		go router.readLoop(node, inbox, queue)
	}
	go func() {
		router.wait.Wait()
		close(router.errors)
		close(router.done)
	}()
	return router, nil
}

func (r *cvSAPVSSRouter) Receive(node int) (<-chan Message, error) {
	queue, ok := r.queues[node]
	if !ok {
		return nil, fmt.Errorf("CV-sAPVSS router has no local node %d", node)
	}
	return queue, nil
}

func (r *cvSAPVSSRouter) Errors() <-chan error {
	return r.errors
}

func (r *cvSAPVSSRouter) Close() error {
	if r == nil {
		return nil
	}
	r.cancel()
	<-r.done
	return nil
}

func (r *cvSAPVSSRouter) readLoop(node int, inbox <-chan Message, queue chan Message) {
	defer r.wait.Done()
	defer close(queue)
	for {
		select {
		case <-r.ctx.Done():
			return
		case msg, ok := <-inbox:
			if !ok {
				if r.ctx.Err() == nil {
					r.fail(fmt.Errorf("CV-sAPVSS transport inbox for node %d closed", node))
				}
				return
			}
			routed, ok := r.route(node, msg)
			if !ok {
				continue
			}
			select {
			case <-r.ctx.Done():
				return
			default:
			}
			select {
			case queue <- routed:
			default:
				r.fail(fmt.Errorf("CV-sAPVSS delivery queue for node %d is full", node))
				return
			}
		}
	}
}

func (r *cvSAPVSSRouter) route(node int, msg Message) (Message, bool) {
	if !cvAllowedNetworkTag(msg.Tag) || msg.To != node {
		return Message{}, false
	}
	wireBytes := tcpMessageFrameFixedBytes + len(msg.Tag) + len(msg.Body)
	switch msg.Tag {
	case apvssTagLaneOffer, cvTagLaneOfferScalar, cvTagAggregateRecoverStoreScalar, cvTagAggregatePayloadScalar:
		if _, ok := r.oldNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.newNodes[msg.To]; !ok {
			return Message{}, false
		}
	case cvTagHandoffScalar:
		if _, ok := r.oldNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, oldOK := r.oldNodes[msg.To]; !oldOK {
			if _, newOK := r.newNodes[msg.To]; !newOK {
				return Message{}, false
			}
		}
	case apvssTagLaneACK, cvTagLaneACKScalar, cvTagAggregateRecoverGetScalar, cvTagAggregateRecoverCancelScalar,
		cvTagAggregatePayloadGetScalar:
		if _, ok := r.newNodes[msg.From]; !ok {
			return Message{}, false
		}
	case cvTagAggregateShareScalar:
		if _, ok := r.newNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.newNodes[msg.To]; !ok {
			return Message{}, false
		}
	default:
		if _, ok := r.oldNodes[msg.From]; !ok {
			return Message{}, false
		}
		if _, ok := r.oldNodes[msg.To]; !ok {
			return Message{}, false
		}
	}
	envelope := append([]byte(nil), msg.Body...)
	if r.auth != nil {
		var err error
		envelope, err = r.auth.open(msg.From, msg.To, msg.Tag, msg.Body)
		if err != nil {
			return Message{}, false
		}
	}
	payload, err := cvDecodeNetworkEnvelope(envelope, r.sid, r.epoch)
	if err != nil {
		return Message{}, false
	}
	return Message{From: msg.From, To: msg.To, Tag: msg.Tag, Body: payload, WireBytes: wireBytes}, true
}

func (r *cvSAPVSSRouter) fail(err error) {
	r.failOnce.Do(func() {
		r.errors <- err
		r.cancel()
	})
}
