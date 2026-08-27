package core

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type cvNetworkEnvelopeSealer interface {
	seal(from, to int, tag string, envelope []byte) ([]byte, error)
}

type cvAPDBNetworkServiceConfigV2 struct {
	SID             string
	Epoch           uint64
	LocalNode       int
	OldRoster       []int
	NewRoster       []int
	ExpectedContext []byte
	TotalShards     int
	DataShards      int
	ShardBytes      int
	MaximumPayload  int
	Params          cvV2Params
	EligibilityCoin *cvCoinOutputV2
	LeafContext     *cvLeafContextV2
	Receivers       *cvReceiverKeyMaterialV2
	Validators      *cvValidatorKeyMaterialV2
	DecisionStore   *cvDecisionSignStoreV2
	ScalarStore     *cvScalarStoreV2
}

type cvAPDBPendingLockV2 struct {
	collector *cvAPDBLockCollectorV2
	ready     chan struct{}
	aggregate bool
}

type cvAPDBPendingRecoveryV2 struct {
	collector *cvAPDBRecoveryCollectorV2
	ready     chan struct{}
	purpose   cvRecoveryPurposeV2
}

type cvPendingAggregatePayloadPullV2 struct {
	allowed   int
	responses chan cvAggregatePayloadPullResponseV2
}

type cvAggregatePayloadPullResponseV2 struct {
	from      int
	payload   []byte
	wireBytes int
}

type cvAggregatePayloadResponseCallV2 struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvAggregatePayloadCacheEntryV2 struct {
	root    []byte
	payload []byte
}

type cvRecoveryPurposeV2 uint8

const (
	cvRecoveryUnclassifiedV2 cvRecoveryPurposeV2 = iota
	cvRecoveryProposerCatalogV2
	cvRecoveryValidatorComponentV2
	cvRecoveryValidatorAggregateV2
	cvRecoveryNewAggregateV2
)

const (
	cvControlRetryIntervalV2     = 250 * time.Millisecond
	cvControlRetryMaxAttemptsV2  = 4
	cvFanoutMaxParallelV2        = 16
	cvValidationFirstWaveExtraV2 = 2
)

type cvFanoutSendResultV2 struct {
	recipient int
	wireBytes int
	err       error
}

type cvOutboundMessageV2 struct {
	to         int
	tag        string
	payload    []byte
	shouldSend func() bool
	onResult   func(error)
	onMeasured func(int, error)
}

type cvCryptoJobKindV2 uint8

const (
	cvCryptoJobLaneOfferV2 cvCryptoJobKindV2 = iota + 1
	cvCryptoJobCertifiedCandidateV2
)

type cvCryptoJobV2 struct {
	kind   cvCryptoJobKindV2
	msg    Message
	digest string
}

type cvRecoveryJobKindV2 uint8

const (
	cvRecoveryPrepareDealerV2 cvRecoveryJobKindV2 = iota + 1
	cvRecoveryDealerRequestV2
	cvRecoveryPayloadResponseV2
	cvRecoveryAggregateRequestV2
	cvRecoveryAggregatePayloadRequestV2
)

const cvAggregateRecoveryResponseCacheCapacityV2 = 64

const cvComponentRecoveryResponseCacheCapacityV2 = 256

const cvAggregatePayloadResponseCacheCapacityV2 = 64

const cvAggregateRecoveryCancelDomainV2 = "RLA/CV-V2/AGG-RECOVER-CANCEL"

const cvAggregatePayloadResponseDomainV2 = "RLA/CV-V2/AGG-PAYLOAD-RESPONSE"

type cvRecoveryJobV2 struct {
	kind             cvRecoveryJobKindV2
	msg              Message
	instanceDigest   []byte
	payload          []byte
	requestDigest    string
	dedupeKey        string
	responseCacheKey string
	queuedAt         time.Time
}

type cvAggregateRecoveryResponseCallV2 struct {
	ready    chan struct{}
	response []byte
	err      error
}

// cvComponentRecoveryResponseCallV2 coalesces concurrent holder-side store
// construction for the same immutable recovery request.  Each requester still
// receives its own network response after the shared computation completes.
type cvComponentRecoveryResponseCallV2 struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvAggregateRecoveryRequestKeyV2 struct {
	receiver int
	digest   string
}

func cvAggregateRecoveryCancelV2CanonicalBytes(request []byte) ([]byte, error) {
	if len(request) == 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery cancel request")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateRecoveryCancelDomainV2))
	_ = cvWriteBytes(&wire, hashBytes(request))
	return wire.Bytes(), nil
}

func cvDecodeAggregateRecoveryCancelV2(wire []byte) (string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateRecoveryCancelDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateRecoveryCancelDomainV2)) {
		return "", fmt.Errorf("invalid CV V2 aggregate recovery cancel domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return "", fmt.Errorf("invalid CV V2 aggregate recovery cancel digest")
	}
	return string(digest), nil
}

func cvAggregatePayloadResponseV2CanonicalBytes(instanceDigest, payload []byte, maximumPayload int) ([]byte, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload {
		return nil, fmt.Errorf("invalid CV V2 aggregate payload response")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregatePayloadResponseDomainV2))
	_ = cvWriteBytes(&wire, instanceDigest)
	_ = cvWriteBytes(&wire, payload)
	return wire.Bytes(), nil
}

func cvDecodeAggregatePayloadResponseV2(wire []byte, maximumPayload int) ([]byte, []byte, error) {
	if maximumPayload <= 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 aggregate payload response limit")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregatePayloadResponseDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregatePayloadResponseDomainV2)) {
		return nil, nil, fmt.Errorf("invalid CV V2 aggregate payload response domain")
	}
	instanceDigest, err := r.bytes(32)
	if err != nil || len(instanceDigest) != 32 {
		return nil, nil, fmt.Errorf("invalid CV V2 aggregate payload response instance")
	}
	payload, err := r.bytes(maximumPayload)
	if err != nil || len(payload) == 0 || r.reader.Len() != 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 aggregate payload response payload")
	}
	// The strict length-prefixed parser above consumes the complete wire: the
	// fixed domain, 32-byte instance digest, bounded non-empty payload, and EOF
	// are all checked. Re-encoding the same fields solely for byte comparison
	// adds an allocation on every recovery response without accepting any
	// additional representation.
	return instanceDigest, payload, nil
}

type cvServiceExperimentMetricsV2 struct {
	proposerRecoverySentBytes           uint64
	proposerRecoveryRecvBytes           uint64
	proposerRecoveryLatency             time.Duration
	proposerCatalogVerificationLatency  time.Duration
	proposerCatalogScanCount            int
	proposerRejectedCount               int
	validatorComponentRecoverySentBytes uint64
	validatorComponentRecoveryRecvBytes uint64
	validatorComponentRecoveryLatency   time.Duration
	validatorAggregateRecoverySentBytes uint64
	validatorAggregateRecoveryRecvBytes uint64
	validatorAggregateRecoveryLatency   time.Duration
	newAggregateRecoverySentBytes       uint64
	newAggregateRecoveryRecvBytes       uint64
	newAggregateRecoveryLatency         time.Duration
	arcFormationLatency                 time.Duration
	validationCertificateLatency        time.Duration
	validationCanonicalLatency          time.Duration
	validationNetworkWaitLatency        time.Duration
	validationSignatureVerifyLatency    time.Duration
	validationAggregateVerifyLatency    time.Duration
	decisionCertificateLatency          time.Duration
	scalarBoundedDLogLatency            time.Duration
	blindingGroupDecryptionLatency      time.Duration
	componentDispersalSentBytes         uint64
	componentDispersalRecvBytes         uint64
	aggregateDispersalSentBytes         uint64
	aggregateDispersalRecvBytes         uint64
	coinFanoutLatency                   time.Duration
	aggregateOfferSendLatency           time.Duration
	candidateFanoutACKWaitLatency       time.Duration
	candidateFanoutRetryWaitLatency     time.Duration
	candidateFanoutMaxPeerLatency       time.Duration
	candidateFanoutAttempts             int
	candidateFanoutRetries              int
	dealerHintBuildLatency              time.Duration
	dealerResponseEncodeLatency         time.Duration
	dealerPayloadSentBytes              uint64
	dealerHintSentBytes                 uint64
	holderFragmentSentBytes             uint64
	componentRecoveryLateRecvBytes      uint64
	componentDirectPayloadHits          uint64
	componentFragmentRecoveries         uint64
	componentDirectGraceWait            time.Duration
	receiverPayloadDecodeLatency        time.Duration
	recoveryQueueWaitLatency            time.Duration
	recoveryWorkerLatency               time.Duration
	recoveryJobs                        uint64
	aggregateRecoveryCacheHits          uint64
	aggregateRecoveryCacheMisses        uint64
	componentRecoveryCacheHits          uint64
	componentRecoveryCacheMisses        uint64
	aggregateRecoveryResponseLatency    time.Duration
	aggregateRecoveryResponseRequests   uint64
	tagSentBytes                        map[string]uint64
	tagRecvBytes                        map[string]uint64
}

type cvPendingCoinV2 struct {
	invocation []byte
	shares     map[int][]byte
	ready      chan struct{}
}

type cvNetworkPoolSlotV2 struct {
	state          cvPoolSlotStateV2
	poolWire       []byte
	certWire       []byte
	localShare     []byte
	localShareWire []byte
	shares         map[int][]byte
	sharesReady    chan struct{}
	certReady      chan struct{}
	certifying     bool
}

type cvPendingValidationV2 struct {
	requestWire []byte
	request     *cvValidationRequestV2
	statement   []byte
	signatures  map[int][]byte
	ready       chan struct{}
}

type cvValidationRecordV2 struct {
	requestWire []byte
	// request is immutable after canonical validation; it avoids decoding the
	// same request again when a validation result arrives.
	request    *cvValidationRequestV2
	statement  []byte
	resultWire []byte
	// Set only after result authentication; awaiters reuse this immutable value.
	result      *cvValidationResultV2
	resultReady chan struct{}
}

// cvValidationResultWireSeenV2 records only results that completed the full
// authentication path. It is used to discard exact retransmissions without
// allowing an unauthenticated wire to bypass validation.
type cvValidationResultWireSeenV2 struct {
	sender    int
	statement string
}

type cvCertifiedValidationV2 struct {
	request     *cvValidationRequestV2
	certificate *cvValidationCertificateV2
}

type cvPendingDecisionV2 struct {
	statement   []byte
	shares      map[int][]byte
	certificate []byte
	ready       chan struct{}
}

type cvPendingScalarSharesV2 struct {
	aggregate *cvAggregateV2
	outputs   map[int]*cvScalarShareOutputV2
	wires     map[int][]byte
	ready     chan struct{}
}

type cvVerifiedComponentV2 struct {
	ref        cvComponentRefV2
	leafDigest []byte
	payload    []byte
	leaf       *cvLeafV2
}

type cvVerifiedComponentCallV2 struct {
	ref  cvComponentRefV2
	leaf *cvLeafV2
	err  error
	done chan struct{}
}

type cvAPDBNetworkServiceV2 struct {
	ctx           context.Context
	cancel        context.CancelFunc
	cfg           cvAPDBNetworkServiceConfigV2
	transport     agreementTransport
	auth          cvNetworkEnvelopeSealer
	holderStore   *cvAPDBHolderStoreV2
	apdbSigner    *tblsThresholdSigner
	controlSigner *tblsThresholdSigner
	coinSigner    *tblsThresholdSigner
	inbox         <-chan Message

	mu                     sync.Mutex
	experimentMu           sync.Mutex
	verifiedCatalogMu      sync.Mutex
	pendingLocks           map[string]*cvAPDBPendingLockV2
	pendingComponents      map[string]*cvAPDBPendingRecoveryV2
	pendingAggregates      map[string]*cvAPDBPendingRecoveryV2
	pendingCoins           map[string]*cvPendingCoinV2
	localCoinShares        map[string][]byte
	coinShareReplies       map[string]map[int]struct{}
	coinShareReplyInFlight map[string]map[int]struct{}
	poolSlots              map[int]*cvNetworkPoolSlotV2
	eligibleProposers      map[int]struct{}
	// Sorted eligibility snapshot reused by the candidate validation path.
	eligibleProposerSample          []int
	eligibilityValue                []byte
	eligibilityCoin                 *cvCoinOutputV2
	validatorSample                 []int
	agreementPublicContextCache     *cvAgreementPublicContextV2
	pendingValidation               map[string]*cvPendingValidationV2
	validationRecords               map[string]*cvValidationRecordV2
	validationInFlight              map[string]struct{}
	validationOneShot               map[int][]byte
	validationLocalShares           map[string][]byte
	validationLocalShareWires       map[string][]byte
	validationRequestStatements     map[string]string
	validationResultWires           map[string]cvValidationResultWireSeenV2
	validationSignatureWires        map[string]int
	certifiedValidation             map[int]*cvCertifiedValidationV2
	certifiedReady                  map[int]chan struct{}
	pendingDecisions                map[string]*cvPendingDecisionV2
	decisionLocalShares             map[string][]byte
	decisionLocalShareWires         map[string][]byte
	decisionCertificates            map[string][]byte
	verifiedHandoffWire             []byte
	acceptedHandoff                 []byte
	handoffReady                    chan struct{}
	localScalarOutputs              map[string][]byte
	scalarAggregates                map[string]*cvAggregateV2
	pendingScalarShares             map[string]*cvPendingScalarSharesV2
	pendingLaneACKsV2               *cvPendingLaneACKsV2
	componentRefsV2                 map[int]cvComponentRefV2
	verifiedComponentsV2            map[int]cvVerifiedComponentV2
	verifiedComponentCalls          map[int]*cvVerifiedComponentCallV2
	rejectedComponentsV2            map[int]struct{}
	verifiedCatalogV2               []cvComponentRefV2
	verifiedCatalogPrewarm          bool
	localComponentRefV2             []byte
	dealerPayloadsV2                map[string][]byte
	dealerPayloadHintStates         map[string]*cvDealerPayloadHintStateV2
	recoveryPrewarmV2               bool
	recoveredPayloadsV2             map[string]cvRecoveredPayloadEntryV2
	recoveredPayloadCallsV2         map[string]*cvRecoveredPayloadCallV2
	aggregatePayloadsV2             map[string]cvAggregatePayloadCacheEntryV2
	aggregatePayloadResponsesV2     map[string][]byte
	aggregatePayloadResponseCallsV2 map[string]*cvAggregatePayloadResponseCallV2
	pendingAggregatePayloadV2       map[string]*cvPendingAggregatePayloadPullV2
	aggregateRecoveryCallsV2        map[string]*cvAggregateRecoveryResponseCallV2
	aggregateRecoveryActiveV2       map[cvAggregateRecoveryRequestKeyV2]bool
	componentRefUpdatesV2           chan struct{}
	certifiedCandidatesV2           map[string][]byte
	candidateACKWiresV2             map[string][]byte
	candidateResponseWiresV2        map[string][]byte
	candidateResponseCallsV2        map[string]*cvCandidateResponseCallV2
	candidateFanoutV2               map[string]*cvCandidateFanoutStateV2
	certifiedCandidateChV2          chan *cvAgreementObjectV2
	outbound                        chan cvOutboundMessageV2
	priorityOutbound                chan cvOutboundMessageV2
	outboundWG                      sync.WaitGroup
	cryptoQueue                     chan cvCryptoJobV2
	cryptoWG                        sync.WaitGroup
	recoveryQueue                   chan cvRecoveryJobV2
	recoveryPriorityQueue           chan cvRecoveryJobV2
	recoveryWG                      sync.WaitGroup
	recoveryRequestsInFlightV2      map[string]struct{}
	componentRecoveryResponsesV2    map[string][]byte
	componentRecoveryCallsV2        map[string]*cvComponentRecoveryResponseCallV2
	verifiedRecoveryLocksV2         map[string]*cvAPDBLockV2
	processingLaneOffersV2          map[[2]int]struct{}
	processingCandidatesV2          map[string]struct{}
	candidateDigestByProposerV2     map[int]string
	candidateOriginsV2              map[string]map[int]struct{}
	candidateFetchWaitersV2         map[string]map[int]struct{}
	experimentMetrics               cvServiceExperimentMetricsV2
	done                            chan struct{}
}

func newCVAPDBNetworkServiceV2(
	ctx context.Context, cfg cvAPDBNetworkServiceConfigV2, transport agreementTransport, router *cvSAPVSSRouter,
	auth cvNetworkEnvelopeSealer, holderStore *cvAPDBHolderStoreV2,
	apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) (*cvAPDBNetworkServiceV2, error) {
	if ctx == nil || cfg.SID == "" || cfg.Epoch == 0 || cfg.Epoch > uint64(^uint(0)>>1) || cfg.LocalNode < 0 ||
		transport == nil || router == nil || auth == nil || len(cfg.ExpectedContext) != 32 ||
		cfg.TotalShards != len(cfg.OldRoster) || cfg.DataShards <= 0 || cfg.DataShards > cfg.TotalShards ||
		cfg.ShardBytes < 0 || cfg.MaximumPayload <= 0 ||
		!equalInts(cfg.OldRoster, sortedUnique(cfg.OldRoster)) ||
		!equalInts(cfg.NewRoster, sortedUnique(cfg.NewRoster)) ||
		!cvV2SignerHasRole(apdbSigner, cvV2RoleAPDB) ||
		!cvV2SignerHasRole(controlSigner, cvV2RoleControl) ||
		!cvV2SignerHasRole(coinSigner, cvV2RoleCoin) ||
		!equalInts(apdbSigner.memberOrder, cfg.OldRoster) ||
		!equalInts(controlSigner.memberOrder, cfg.OldRoster) ||
		!equalInts(coinSigner.memberOrder, cfg.OldRoster) ||
		cfg.Params.apdbLockThreshold != apdbSigner.Threshold() ||
		cfg.Params.decisionThreshold != controlSigner.Threshold() ||
		cfg.Params.componentCount != coinSigner.Threshold() ||
		cfg.Params.recoveryThreshold != cfg.DataShards ||
		cfg.Params.poolSize <= 0 || cfg.Params.poolSize > len(cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service configuration")
	}
	validationParts := 0
	if cfg.LeafContext != nil {
		validationParts++
	}
	if cfg.Receivers != nil {
		validationParts++
	}
	if cfg.Validators != nil {
		validationParts++
	}
	if validationParts != 0 && validationParts != 3 {
		return nil, fmt.Errorf("incomplete CV V2 network validation material")
	}
	if validationParts == 3 {
		contextWire, contextErr := cvLeafContextV2CanonicalBytes(cfg.LeafContext)
		contextDigest, digestErr := cvLeafContextDigestV2(cfg.LeafContext)
		if contextErr != nil || len(contextWire) == 0 || cfg.LeafContext.SID != cfg.SID || cfg.LeafContext.Epoch != cfg.Epoch ||
			digestErr != nil || !bytes.Equal(contextDigest, cfg.ExpectedContext) ||
			cvValidateReceiverMaterialForLeafV2(cfg.LeafContext, cfg.Receivers) != nil ||
			cvValidateValidatorMaterialForLeafV2(cfg.LeafContext, cfg.Validators) != nil {
			return nil, fmt.Errorf("invalid CV V2 network validation material")
		}
	}
	isOld := cvMemberInRosterV2(cfg.LocalNode, cfg.OldRoster)
	isNew := cvMemberInRosterV2(cfg.LocalNode, cfg.NewRoster)
	if (!isOld && !isNew) || (isOld && holderStore == nil) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service local role")
	}
	inbox, err := router.Receive(cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	serviceContext, cancel := context.WithCancel(ctx)
	service := &cvAPDBNetworkServiceV2{
		ctx: serviceContext, cancel: cancel, cfg: cfg, transport: transport, auth: auth,
		holderStore: holderStore, apdbSigner: apdbSigner, controlSigner: controlSigner, coinSigner: coinSigner, inbox: inbox,
		pendingLocks:                    make(map[string]*cvAPDBPendingLockV2),
		pendingComponents:               make(map[string]*cvAPDBPendingRecoveryV2),
		pendingAggregates:               make(map[string]*cvAPDBPendingRecoveryV2),
		pendingCoins:                    make(map[string]*cvPendingCoinV2),
		localCoinShares:                 make(map[string][]byte, 2),
		coinShareReplies:                make(map[string]map[int]struct{}, 2),
		coinShareReplyInFlight:          make(map[string]map[int]struct{}, 2),
		poolSlots:                       make(map[int]*cvNetworkPoolSlotV2, cfg.Params.proposerSampleSize),
		eligibleProposers:               make(map[int]struct{}, cfg.Params.proposerSampleSize),
		pendingValidation:               make(map[string]*cvPendingValidationV2),
		validationRecords:               make(map[string]*cvValidationRecordV2),
		validationInFlight:              make(map[string]struct{}),
		validationOneShot:               make(map[int][]byte),
		validationLocalShares:           make(map[string][]byte),
		validationLocalShareWires:       make(map[string][]byte),
		validationRequestStatements:     make(map[string]string),
		validationResultWires:           make(map[string]cvValidationResultWireSeenV2),
		validationSignatureWires:        make(map[string]int),
		certifiedValidation:             make(map[int]*cvCertifiedValidationV2),
		certifiedReady:                  make(map[int]chan struct{}),
		pendingDecisions:                make(map[string]*cvPendingDecisionV2),
		decisionLocalShares:             make(map[string][]byte),
		decisionLocalShareWires:         make(map[string][]byte),
		decisionCertificates:            make(map[string][]byte),
		handoffReady:                    make(chan struct{}, 1),
		localScalarOutputs:              make(map[string][]byte),
		scalarAggregates:                make(map[string]*cvAggregateV2),
		pendingScalarShares:             make(map[string]*cvPendingScalarSharesV2),
		componentRefsV2:                 make(map[int]cvComponentRefV2, cfg.Params.poolSize),
		verifiedComponentsV2:            make(map[int]cvVerifiedComponentV2, cfg.Params.poolSize),
		verifiedComponentCalls:          make(map[int]*cvVerifiedComponentCallV2),
		rejectedComponentsV2:            make(map[int]struct{}),
		aggregatePayloadsV2:             make(map[string]cvAggregatePayloadCacheEntryV2, cfg.Params.proposerSampleSize),
		aggregatePayloadResponsesV2:     make(map[string][]byte, cvAggregatePayloadResponseCacheCapacityV2),
		aggregatePayloadResponseCallsV2: make(map[string]*cvAggregatePayloadResponseCallV2),
		pendingAggregatePayloadV2:       make(map[string]*cvPendingAggregatePayloadPullV2),
		aggregateRecoveryCallsV2:        make(map[string]*cvAggregateRecoveryResponseCallV2),
		aggregateRecoveryActiveV2:       make(map[cvAggregateRecoveryRequestKeyV2]bool),
		componentRefUpdatesV2:           make(chan struct{}, 1),
		certifiedCandidatesV2:           make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateACKWiresV2:             make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateResponseWiresV2:        make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateResponseCallsV2:        make(map[string]*cvCandidateResponseCallV2),
		candidateFanoutV2:               make(map[string]*cvCandidateFanoutStateV2),
		certifiedCandidateChV2:          make(chan *cvAgreementObjectV2, cfg.Params.proposerSampleSize),
		outbound:                        make(chan cvOutboundMessageV2, cvOutboundQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		priorityOutbound:                make(chan cvOutboundMessageV2, cvPriorityOutboundQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		cryptoQueue:                     make(chan cvCryptoJobV2, cvCryptoQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryQueue:                   make(chan cvRecoveryJobV2, cvRecoveryQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryPriorityQueue:           make(chan cvRecoveryJobV2, cvRecoveryPriorityQueueCapacityV2(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryRequestsInFlightV2:      make(map[string]struct{}),
		componentRecoveryResponsesV2:    make(map[string][]byte),
		componentRecoveryCallsV2:        make(map[string]*cvComponentRecoveryResponseCallV2),
		verifiedRecoveryLocksV2:         make(map[string]*cvAPDBLockV2, 256),
		processingLaneOffersV2:          make(map[[2]int]struct{}, len(cfg.OldRoster)),
		processingCandidatesV2:          make(map[string]struct{}, cfg.Params.proposerSampleSize),
		candidateDigestByProposerV2:     make(map[int]string, cfg.Params.proposerSampleSize),
		candidateOriginsV2:              make(map[string]map[int]struct{}, cfg.Params.proposerSampleSize),
		candidateFetchWaitersV2:         make(map[string]map[int]struct{}, cfg.Params.proposerSampleSize),
		experimentMetrics: cvServiceExperimentMetricsV2{
			tagSentBytes: make(map[string]uint64), tagRecvBytes: make(map[string]uint64),
		},
		done: make(chan struct{}),
	}
	service.cfg.OldRoster = append([]int(nil), cfg.OldRoster...)
	service.cfg.NewRoster = append([]int(nil), cfg.NewRoster...)
	service.cfg.ExpectedContext = append([]byte(nil), cfg.ExpectedContext...)
	if cfg.EligibilityCoin != nil {
		if err := service.setEligibilityCoin(cfg.EligibilityCoin); err != nil {
			cancel()
			return nil, err
		}
	}
	workers := len(cfg.OldRoster) + len(cfg.NewRoster)
	if workers < 1 {
		workers = 1
	}
	if workers > 8 {
		workers = 8
	}
	service.outboundWG.Add(workers)
	for range workers {
		go service.runOutbound()
	}
	cryptoWorkers := cvCryptoWorkers(cap(service.cryptoQueue))
	service.cryptoWG.Add(cryptoWorkers)
	for range cryptoWorkers {
		go service.runCryptoWorkerV2()
	}
	recoveryWorkers := cvRecoveryServiceWorkers(len(cfg.OldRoster) + len(cfg.NewRoster))
	service.recoveryWG.Add(recoveryWorkers)
	for range recoveryWorkers {
		go service.runRecoveryWorkerV2()
	}
	go service.run()
	return service, nil
}

func cvOutboundQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 32
	if capacity < 128 {
		return 128
	}
	if capacity > 4096 {
		return 4096
	}
	return capacity
}

func cvPriorityOutboundQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 8
	if capacity < 64 {
		return 64
	}
	if capacity > 1024 {
		return 1024
	}
	return capacity
}

func cvCryptoQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 2
	if capacity < 64 {
		return 64
	}
	if capacity > 2048 {
		return 2048
	}
	return capacity
}

func cvRecoveryQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 4
	if capacity < 64 {
		capacity = 64
	}
	if capacity > 1024 {
		capacity = 1024
	}
	return capacity
}

func cvRecoveryPriorityQueueCapacityV2(committeeSize int) int {
	capacity := committeeSize * 2
	if capacity < 32 {
		capacity = 32
	}
	if capacity > 512 {
		capacity = 512
	}
	return capacity
}

func cvRecoveryServiceWorkers(committeeSize int) int {
	workers := committeeSize / 16
	if workers < 2 {
		workers = 2
	}
	if configured, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_APDB_RECOVERY_WORKERS"))); err == nil && configured > 0 {
		workers = configured
	}
	if workers > 16 {
		workers = 16
	}
	return workers
}

func (s *cvAPDBNetworkServiceV2) runCryptoWorkerV2() {
	defer s.cryptoWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.cryptoQueue:
			s.runCryptoJobV2(job)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) runRecoveryWorkerV2() {
	defer s.recoveryWG.Done()
	for {
		// Drain completed payload responses before ordinary recovery work so a
		// holder request cannot delay an already-returned shard.
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.recoveryPriorityQueue:
			started := time.Now()
			s.runRecoveryJobV2(job)
			s.recordRecoveryWorkerMetricsV2(job, started)
			continue
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.recoveryPriorityQueue:
			started := time.Now()
			s.runRecoveryJobV2(job)
			s.recordRecoveryWorkerMetricsV2(job, started)
		case job := <-s.recoveryQueue:
			started := time.Now()
			s.runRecoveryJobV2(job)
			s.recordRecoveryWorkerMetricsV2(job, started)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) recordRecoveryWorkerMetricsV2(job cvRecoveryJobV2, started time.Time) {
	s.experimentMu.Lock()
	s.experimentMetrics.recoveryJobs++
	s.experimentMetrics.recoveryWorkerLatency += time.Since(started)
	if !job.queuedAt.IsZero() {
		s.experimentMetrics.recoveryQueueWaitLatency += started.Sub(job.queuedAt)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) enqueueRecoveryJobV2(job cvRecoveryJobV2) bool {
	if job.queuedAt.IsZero() {
		job.queuedAt = time.Now()
	}
	queue := s.recoveryQueue
	if job.kind == cvRecoveryPayloadResponseV2 {
		queue = s.recoveryPriorityQueue
	}
	select {
	case <-s.ctx.Done():
		return false
	case queue <- job:
		return true
	}
}

// claimRecoveryRequestV2 suppresses duplicate holder work while an identical
// request is already queued or being handled. The sender's normal retry path
// remains responsible for retransmission if the first response is lost.
func (s *cvAPDBNetworkServiceV2) claimRecoveryRequestV2(key string) bool {
	if s == nil || key == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recoveryRequestsInFlightV2 == nil {
		s.recoveryRequestsInFlightV2 = make(map[string]struct{})
	}
	if _, exists := s.recoveryRequestsInFlightV2[key]; exists {
		return false
	}
	s.recoveryRequestsInFlightV2[key] = struct{}{}
	return true
}

func (s *cvAPDBNetworkServiceV2) releaseRecoveryRequestV2(key string) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	delete(s.recoveryRequestsInFlightV2, key)
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) cachedComponentRecoveryResponseV2(key string) []byte {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Entries are immutable after insertion. sendAsync copies at the queue
	// boundary, so returning the cached slice avoids a redundant full-response
	// allocation on every cache hit.
	return s.componentRecoveryResponsesV2[key]
}

func (s *cvAPDBNetworkServiceV2) recordComponentRecoveryCacheV2(hit bool) {
	if s == nil {
		return
	}
	s.experimentMu.Lock()
	if hit {
		s.experimentMetrics.componentRecoveryCacheHits++
	} else {
		s.experimentMetrics.componentRecoveryCacheMisses++
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) cacheComponentRecoveryResponseV2(key string, response []byte) {
	if s == nil || key == "" || len(response) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.componentRecoveryResponsesV2 == nil {
		s.componentRecoveryResponsesV2 = make(map[string][]byte)
	}
	if _, exists := s.componentRecoveryResponsesV2[key]; exists {
		return
	}
	if len(s.componentRecoveryResponsesV2) >= cvComponentRecoveryResponseCacheCapacityV2 {
		return
	}
	s.componentRecoveryResponsesV2[key] = append([]byte(nil), response...)
}

func (s *cvAPDBNetworkServiceV2) runRecoveryJobV2(job cvRecoveryJobV2) {
	if job.kind == cvRecoveryDealerRequestV2 {
		defer s.releaseRecoveryRequestV2(job.dedupeKey)
	}
	switch job.kind {
	case cvRecoveryPrepareDealerV2:
		payload := job.payload
		if len(payload) == 0 {
			payload, _ = s.dealerPayloadV2(job.instanceDigest)
		}
		if len(job.instanceDigest) == 32 && len(payload) > 0 {
			_ = s.dealerPayloadResponseV2(job.instanceDigest, payload)
		}
	case cvRecoveryDealerRequestV2:
		if cached := s.cachedComponentRecoveryResponseV2(job.responseCacheKey); len(cached) > 0 {
			s.recordComponentRecoveryCacheV2(true)
			_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreV2, cached, func(err error) {
				if err == nil {
					s.recordComponentRecoveryResponseSentV2(0, 0, len(cached))
				}
			})
			return
		}
		s.recordComponentRecoveryCacheV2(false)
		var lock *cvAPDBLockV2
		s.mu.Lock()
		lock = s.verifiedRecoveryLocksV2[job.responseCacheKey]
		s.mu.Unlock()
		if lock == nil {
			var err error
			lock, err = cvDecodeAPDBLockV2(job.msg.Body)
			if err != nil || cvVerifyAPDBLockV2(lock, s.apdbSigner) != nil {
				return
			}
			s.mu.Lock()
			if len(s.verifiedRecoveryLocksV2) < 256 {
				s.verifiedRecoveryLocksV2[job.responseCacheKey] = lock
			}
			s.mu.Unlock()
		}
		if payload, ok := s.dealerPayloadV2(lock.InstanceDigest); ok {
			if cvComponentDealerResponseModeV2() == cvComponentDealerResponseDropV2 {
				return
			}
			if response := s.dealerPayloadResponseV2(lock.InstanceDigest, payload); len(response) > 0 {
				hintsBytes := s.dealerPayloadHintBytesV2(lock.InstanceDigest)
				_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverPayloadV2, response, func(err error) {
					if err == nil {
						s.recordComponentRecoveryResponseSentV2(len(payload), hintsBytes, 0)
					}
				})
				return
			}
		}
		var response []byte
		var responseErr error
		var call *cvComponentRecoveryResponseCallV2
		s.mu.Lock()
		call = s.componentRecoveryCallsV2[job.responseCacheKey]
		if call == nil && len(s.componentRecoveryCallsV2) < cvComponentRecoveryResponseCacheCapacityV2 {
			call = &cvComponentRecoveryResponseCallV2{ready: make(chan struct{})}
			s.componentRecoveryCallsV2[job.responseCacheKey] = call
		} else if call != nil {
			// Another holder job is constructing this immutable response.
			s.mu.Unlock()
			select {
			case <-s.ctx.Done():
				return
			case <-call.ready:
				response, responseErr = call.response, call.err
			}
			if responseErr == nil && len(response) > 0 {
				_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreV2, response, func(err error) {
					if err == nil {
						s.recordComponentRecoveryResponseSentV2(0, 0, len(response))
					}
				})
			}
			return
		}
		s.mu.Unlock()
		response, responseErr = cvHandleAPDBRecoveryLockV2(s.cfg.SID, s.cfg.Epoch, job.msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, lock, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore)
		if responseErr == nil {
			s.cacheComponentRecoveryResponseV2(job.responseCacheKey, response)
		}
		if call != nil {
			s.mu.Lock()
			call.response, call.err = response, responseErr
			delete(s.componentRecoveryCallsV2, job.responseCacheKey)
			close(call.ready)
			s.mu.Unlock()
		}
		if responseErr == nil {
			_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreV2, response, func(err error) {
				if err == nil {
					s.recordComponentRecoveryResponseSentV2(0, 0, len(response))
				}
			})
		}
	case cvRecoveryPayloadResponseV2:
		started := time.Now()
		response, err := cvDecodeAPDBPayloadResponseV2(job.msg.Body, s.cfg.MaximumPayload)
		if err != nil {
			return
		}
		pending := s.lookupRecovery(string(response.InstanceDigest), false)
		if pending == nil {
			s.recordComponentRecoveryLateRecvBytesV2(job.msg.WireBytes)
			return
		}
		if pending.collector.complete() {
			s.recordComponentRecoveryLateRecvBytesV2(job.msg.WireBytes)
			return
		}
		s.recordRecoveryBytesV2(pending.purpose, false, job.msg.WireBytes)
		if complete, addErr := pending.collector.addDecodedPayloadOwned(response); addErr == nil && complete {
			cvNotifyAPDBV2(pending.ready)
		}
		s.experimentMu.Lock()
		s.experimentMetrics.receiverPayloadDecodeLatency += time.Since(started)
		s.experimentMu.Unlock()
	case cvRecoveryAggregateRequestV2:
		digest := job.requestDigest
		if digest == "" {
			digest = string(hashBytes(job.msg.Body))
		}
		requestKey := cvAggregateRecoveryRequestKeyV2{receiver: job.msg.From, digest: digest}
		if s.aggregateRecoveryRequestCanceledV2(requestKey) {
			s.finishAggregateRecoveryRequestV2(requestKey)
			return
		}
		started := time.Now()
		response, err := s.aggregateRecoveryResponseDigestV2(job.msg.From, job.msg.Body, digest)
		s.recordAggregateRecoveryResponseV2(time.Since(started))
		if err != nil || s.aggregateRecoveryRequestCanceledV2(requestKey) {
			s.finishAggregateRecoveryRequestV2(requestKey)
			return
		}
		err = s.sendAsyncConditionalV2(job.msg.From, cvTagAggregateRecoverStoreV2, response,
			func() bool { return !s.aggregateRecoveryRequestCanceledV2(requestKey) },
			func(error) { s.finishAggregateRecoveryRequestV2(requestKey) })
		if err != nil {
			s.finishAggregateRecoveryRequestV2(requestKey)
		}
	case cvRecoveryAggregatePayloadRequestV2:
		s.handleAggregatePayloadPullRequestV2(job.msg)
	}
}

func (s *cvAPDBNetworkServiceV2) registerAggregateRecoveryRequestV2(key cvAggregateRecoveryRequestKeyV2) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aggregateRecoveryActiveV2[key]; exists {
		return false
	}
	s.aggregateRecoveryActiveV2[key] = false
	return true
}

func (s *cvAPDBNetworkServiceV2) cancelAggregateRecoveryRequestV2(key cvAggregateRecoveryRequestKeyV2) {
	s.mu.Lock()
	if _, active := s.aggregateRecoveryActiveV2[key]; active {
		s.aggregateRecoveryActiveV2[key] = true
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) aggregateRecoveryRequestCanceledV2(key cvAggregateRecoveryRequestKeyV2) bool {
	s.mu.Lock()
	canceled := s.aggregateRecoveryActiveV2[key]
	s.mu.Unlock()
	return canceled
}

func (s *cvAPDBNetworkServiceV2) finishAggregateRecoveryRequestV2(key cvAggregateRecoveryRequestKeyV2) {
	s.mu.Lock()
	delete(s.aggregateRecoveryActiveV2, key)
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) aggregateRecoveryResponseV2(receiver int, request []byte) ([]byte, error) {
	return s.aggregateRecoveryResponseDigestV2(receiver, request, string(hashBytes(request)))
}

func (s *cvAPDBNetworkServiceV2) aggregateRecoveryResponseDigestV2(
	receiver int, request []byte, digest string,
) ([]byte, error) {
	if s == nil || !cvMemberInRosterV2(receiver, s.cfg.NewRoster) || s.holderStore == nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request")
	}
	if digest == "" {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request digest")
	}
	key := digest

	s.mu.Lock()
	if call := s.aggregateRecoveryCallsV2[key]; call != nil {
		s.mu.Unlock()
		s.recordAggregateRecoveryCacheV2(true)
		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-call.ready:
			return call.response, call.err
		}
	}
	if len(s.aggregateRecoveryCallsV2) >= cvAggregateRecoveryResponseCacheCapacityV2 {
		s.mu.Unlock()
		s.recordAggregateRecoveryCacheV2(false)
		return cvHandleAggregateRecoveryRequestV2(s.cfg.SID, s.cfg.Epoch, receiver, s.cfg.LocalNode,
			s.cfg.OldRoster, s.cfg.NewRoster, request, s.cfg.ExpectedContext, s.cfg.TotalShards,
			s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
	}
	call := &cvAggregateRecoveryResponseCallV2{ready: make(chan struct{})}
	s.aggregateRecoveryCallsV2[key] = call
	s.mu.Unlock()
	s.recordAggregateRecoveryCacheV2(false)

	response, err := cvHandleAggregateRecoveryRequestV2(s.cfg.SID, s.cfg.Epoch, receiver, s.cfg.LocalNode,
		s.cfg.OldRoster, s.cfg.NewRoster, request, s.cfg.ExpectedContext, s.cfg.TotalShards,
		s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
	s.mu.Lock()
	call.response, call.err = response, err
	if err != nil {
		delete(s.aggregateRecoveryCallsV2, key)
	}
	close(call.ready)
	s.mu.Unlock()
	return response, err
}

func (s *cvAPDBNetworkServiceV2) recordAggregateRecoveryCacheV2(hit bool) {
	s.experimentMu.Lock()
	if hit {
		s.experimentMetrics.aggregateRecoveryCacheHits++
	} else {
		s.experimentMetrics.aggregateRecoveryCacheMisses++
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordAggregateRecoveryResponseV2(elapsed time.Duration) {
	s.experimentMu.Lock()
	s.experimentMetrics.aggregateRecoveryResponseLatency += elapsed
	s.experimentMetrics.aggregateRecoveryResponseRequests++
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) rememberVerifiedAggregatePayloadV2(instanceDigest, root, payload []byte) error {
	if s == nil || len(instanceDigest) != 32 || len(root) != 32 || len(payload) == 0 || len(payload) > s.cfg.MaximumPayload {
		return fmt.Errorf("invalid verified CV V2 aggregate payload cache entry")
	}
	key := string(instanceDigest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.aggregatePayloadsV2[key]; ok {
		if !bytes.Equal(existing.root, root) || !bytes.Equal(existing.payload, payload) {
			return fmt.Errorf("conflicting verified CV V2 aggregate payload cache entry")
		}
		return nil
	}
	if len(s.aggregatePayloadsV2) >= cvAggregateRecoveryResponseCacheCapacityV2 {
		return fmt.Errorf("verified CV V2 aggregate payload cache is full")
	}
	s.aggregatePayloadsV2[key] = cvAggregatePayloadCacheEntryV2{
		root: append([]byte(nil), root...), payload: append([]byte(nil), payload...),
	}
	return nil
}

func (s *cvAPDBNetworkServiceV2) cachedAggregatePayloadV2(handoff *cvHandoffV2) ([]byte, bool) {
	if s == nil || handoff == nil || len(handoff.Header.APDBInstance) != 32 || len(handoff.ARC.Root) != 32 {
		return nil, false
	}
	s.mu.Lock()
	entry, ok := s.aggregatePayloadsV2[string(handoff.Header.APDBInstance)]
	s.mu.Unlock()
	if !ok || !bytes.Equal(entry.root, handoff.ARC.Root) {
		return nil, false
	}
	digest, err := cvAggregatePayloadDigestV2(entry.payload)
	if err != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
		return nil, false
	}
	return append([]byte(nil), entry.payload...), true
}

func cvAggregatePayloadPullEnabledV2() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_AGGREGATE_PAYLOAD_PULL"))) {
	case "0", "false", "off", "disabled":
		return false
	default:
		return true
	}
}

func (s *cvAPDBNetworkServiceV2) aggregatePayloadPullProvidersV2(handoff *cvHandoffV2) []int {
	if s == nil || handoff == nil {
		return nil
	}
	s.mu.Lock()
	providers := append([]int{handoff.Header.ProposerID}, s.validatorSample...)
	s.mu.Unlock()
	providers = sortedUnique(providers)
	filtered := providers[:0]
	for _, provider := range providers {
		if cvMemberInRosterV2(provider, s.cfg.OldRoster) {
			filtered = append(filtered, provider)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	receiverIndex := sort.SearchInts(s.cfg.NewRoster, s.cfg.LocalNode)
	rotation := receiverIndex % len(filtered)
	return append(append([]int(nil), filtered[rotation:]...), filtered[:rotation]...)
}

func (s *cvAPDBNetworkServiceV2) validatePulledAggregatePayloadV2(
	handoff *cvHandoffV2, payload []byte, bindingCheck func([]byte) error,
) error {
	if s == nil || handoff == nil || len(payload) == 0 {
		return fmt.Errorf("invalid pulled CV V2 aggregate payload")
	}
	digest, err := cvAggregatePayloadDigestV2(payload)
	if err != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
		return fmt.Errorf("pulled CV V2 aggregate payload digest mismatch")
	}
	encoded, err := cvAPDBEncodeSizedV2(
		handoff.ARC.InstanceDigest, payload, s.cfg.DataShards, s.cfg.TotalShards, s.cfg.ShardBytes, s.cfg.MaximumPayload,
	)
	if err != nil || !bytes.Equal(encoded.root, handoff.ARC.Root) {
		return fmt.Errorf("pulled CV V2 aggregate payload ARC root mismatch")
	}
	if bindingCheck != nil {
		if err := bindingCheck(payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *cvAPDBNetworkServiceV2) tryAggregatePayloadPullV2(
	ctx context.Context, handoff *cvHandoffV2, requestWire []byte, bindingCheck func([]byte) error,
) ([]byte, bool, error) {
	if !cvAggregatePayloadPullEnabledV2() {
		return nil, false, nil
	}
	if payload, ok := s.cachedAggregatePayloadV2(handoff); ok {
		if err := s.validatePulledAggregatePayloadV2(handoff, payload, bindingCheck); err == nil {
			return payload, true, nil
		}
	}
	providers := s.aggregatePayloadPullProvidersV2(handoff)
	if len(providers) == 0 {
		return nil, false, nil
	}
	provider := providers[0]
	pending := &cvPendingAggregatePayloadPullV2{
		allowed: provider, responses: make(chan cvAggregatePayloadPullResponseV2, 1),
	}
	key := string(handoff.ARC.InstanceDigest)
	s.mu.Lock()
	if s.pendingAggregatePayloadV2[key] != nil {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("CV V2 aggregate payload pull already active")
	}
	s.pendingAggregatePayloadV2[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingAggregatePayloadV2[key] == pending {
			delete(s.pendingAggregatePayloadV2, key)
		}
		s.mu.Unlock()
	}()
	wireBytes, err := s.sendMeasured(provider, cvTagAggregatePayloadGetV2, requestWire)
	if err != nil {
		return nil, false, nil
	}
	s.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, true, wireBytes)
	grace := durationEnvMs("RLADKR_AGGREGATE_PAYLOAD_PULL_GRACE_MS", 500*time.Millisecond)
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-s.ctx.Done():
		return nil, false, s.ctx.Err()
	case <-timer.C:
		return nil, false, nil
	case response := <-pending.responses:
		s.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, false, response.wireBytes)
		if err := s.validatePulledAggregatePayloadV2(handoff, response.payload, bindingCheck); err != nil {
			return nil, false, nil
		}
		return response.payload, true, nil
	}
}

func (s *cvAPDBNetworkServiceV2) handleAggregatePayloadPullRequestV2(msg Message) {
	if s == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) ||
		!cvMemberInRosterV2(msg.From, s.cfg.NewRoster) {
		return
	}
	handoff, err := cvAuthorizeAggregateRecoveryRequestV2(
		msg.Body, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner,
	)
	if err != nil {
		return
	}
	payload, ok := s.cachedAggregatePayloadV2(handoff)
	if !ok {
		return
	}
	key := string(handoff.ARC.InstanceDigest)
	s.mu.Lock()
	response := s.aggregatePayloadResponsesV2[key]
	call := s.aggregatePayloadResponseCallsV2[key]
	creator := false
	if len(response) == 0 && call == nil && len(s.aggregatePayloadResponseCallsV2) < cvAggregatePayloadResponseCacheCapacityV2 {
		call = &cvAggregatePayloadResponseCallV2{ready: make(chan struct{})}
		if s.aggregatePayloadResponseCallsV2 == nil {
			s.aggregatePayloadResponseCallsV2 = make(map[string]*cvAggregatePayloadResponseCallV2)
		}
		s.aggregatePayloadResponseCallsV2[key] = call
		creator = true
	}
	s.mu.Unlock()
	if len(response) == 0 && call != nil && !creator {
		// The creator performs the encode below; waiters block until it closes.
		select {
		case <-s.ctx.Done():
			return
		case <-call.ready:
		}
		response, err = call.response, call.err
		if err != nil || len(response) == 0 {
			return
		}
	}
	if len(response) == 0 {
		var encodeErr error
		response, encodeErr = cvAggregatePayloadResponseV2CanonicalBytes(
			handoff.ARC.InstanceDigest, payload, s.cfg.MaximumPayload,
		)
		if encodeErr != nil {
			if call != nil {
				s.mu.Lock()
				call.err = encodeErr
				delete(s.aggregatePayloadResponseCallsV2, key)
				close(call.ready)
				s.mu.Unlock()
			}
			return
		}
		s.mu.Lock()
		if s.aggregatePayloadResponsesV2 == nil {
			s.aggregatePayloadResponsesV2 = make(map[string][]byte)
		}
		if len(s.aggregatePayloadResponsesV2) < cvAggregatePayloadResponseCacheCapacityV2 {
			s.aggregatePayloadResponsesV2[key] = append([]byte(nil), response...)
		}
		if call != nil {
			call.response = response
			delete(s.aggregatePayloadResponseCallsV2, key)
			close(call.ready)
		}
		s.mu.Unlock()
	}
	_ = s.sendAsyncMeasuredV2(msg.From, cvTagAggregatePayloadV2, response, func(wireBytes int, sendErr error) {
		if sendErr == nil {
			s.recordRecoveryBytesV2(cvRecoveryNewAggregateV2, true, wireBytes)
		}
	})
}

func (s *cvAPDBNetworkServiceV2) handleAggregatePayloadPullResponseV2(msg Message) {
	instanceDigest, payload, err := cvDecodeAggregatePayloadResponseV2(msg.Body, s.cfg.MaximumPayload)
	if err != nil {
		return
	}
	s.mu.Lock()
	pending := s.pendingAggregatePayloadV2[string(instanceDigest)]
	s.mu.Unlock()
	if pending == nil || pending.allowed != msg.From {
		return
	}
	response := cvAggregatePayloadPullResponseV2{
		from: msg.From, payload: append([]byte(nil), payload...), wireBytes: msg.WireBytes,
	}
	select {
	case pending.responses <- response:
	default:
	}
}

func (s *cvAPDBNetworkServiceV2) runCryptoJobV2(job cvCryptoJobV2) {
	switch job.kind {
	case cvCryptoJobLaneOfferV2:
		key := [2]int{job.msg.From, job.msg.To}
		defer func() {
			s.mu.Lock()
			delete(s.processingLaneOffersV2, key)
			s.mu.Unlock()
		}()
		s.handleLaneOfferV2(job.msg)
	case cvCryptoJobCertifiedCandidateV2:
		digest := job.digest
		if digest == "" {
			digest = cvCertifiedCandidateDigestV2(job.msg.Body)
		}
		defer func() {
			s.mu.Lock()
			delete(s.processingCandidatesV2, digest)
			s.mu.Unlock()
		}()
		s.processCertifiedCandidateDigestV2(job.msg, digest)
	}
}

func (s *cvAPDBNetworkServiceV2) enqueueLaneOfferV2(msg Message) {
	key := [2]int{msg.From, msg.To}
	s.mu.Lock()
	if _, duplicate := s.processingLaneOffersV2[key]; duplicate {
		s.mu.Unlock()
		return
	}
	s.processingLaneOffersV2[key] = struct{}{}
	s.mu.Unlock()
	select {
	case s.cryptoQueue <- cvCryptoJobV2{kind: cvCryptoJobLaneOfferV2, msg: msg}:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingLaneOffersV2, key)
		s.mu.Unlock()
	}
}

func (s *cvAPDBNetworkServiceV2) runOutbound() {
	defer s.outboundWG.Done()
	for {
		// Drain control replies first. Candidate ACKs are intentionally kept
		// separate from bulk recovery/candidate traffic so delivery confirmation
		// cannot be delayed behind large payload writes.
		select {
		case message := <-s.priorityOutbound:
			s.runOutboundMessageV2(message)
			continue
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case message := <-s.priorityOutbound:
			s.runOutboundMessageV2(message)
		case message := <-s.outbound:
			s.runOutboundMessageV2(message)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) runOutboundMessageV2(message cvOutboundMessageV2) {
	var err error
	var wireBytes int
	if message.shouldSend != nil && !message.shouldSend() {
		err = context.Canceled
	} else {
		wireBytes, err = s.sendMeasured(message.to, message.tag, message.payload)
	}
	if message.onResult != nil {
		message.onResult(err)
	}
	if message.onMeasured != nil {
		message.onMeasured(wireBytes, err)
	}
}

// sendAsync keeps the protocol dispatch loop free of transport ACK waits.
// The bounded queue supplies backpressure without dropping protocol replies.
func (s *cvAPDBNetworkServiceV2) sendAsync(to int, tag string, payload []byte, onResult func(error)) error {
	return s.sendAsyncConditionalV2(to, tag, payload, nil, onResult)
}

func (s *cvAPDBNetworkServiceV2) sendAsyncMeasuredV2(
	to int, tag string, payload []byte, onMeasured func(int, error),
) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid measured asynchronous CV V2 send")
	}
	message := cvOutboundMessageV2{
		to: to, tag: tag, payload: append([]byte(nil), payload...), onMeasured: onMeasured,
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.outbound <- message:
		return nil
	}
}

func (s *cvAPDBNetworkServiceV2) sendAsyncConditionalV2(
	to int, tag string, payload []byte, shouldSend func() bool, onResult func(error),
) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid asynchronous CV V2 send")
	}
	message := cvOutboundMessageV2{
		to: to, tag: tag, payload: append([]byte(nil), payload...), shouldSend: shouldSend, onResult: onResult,
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.outbound <- message:
		return nil
	}
}

func (s *cvAPDBNetworkServiceV2) sendPriorityAsync(to int, tag string, payload []byte, onResult func(error)) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid priority asynchronous CV V2 send")
	}
	message := cvOutboundMessageV2{to: to, tag: tag, payload: append([]byte(nil), payload...), onResult: onResult}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.priorityOutbound <- message:
		return nil
	}
}

func cvControlRetryDelayV2(attempt int) time.Duration {
	delay := cvControlRetryIntervalV2
	for i := 0; i < attempt && delay < 2*time.Second; i++ {
		delay *= 2
	}
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
}

// cvDecisionRetryBudgetV2 bounds how long decision finalization keeps
// requesting missing shares; the same knob widens the post-success linger so
// a decided node keeps answering decision-share requests for stragglers.
func cvDecisionRetryBudgetV2() time.Duration {
	budget := arlDurationFromEnv("RLADKR_DECISION_RETRY_BUDGET_MS", 30*time.Second)
	if budget < 5*time.Second {
		return 5 * time.Second
	}
	if budget > 120*time.Second {
		return 120 * time.Second
	}
	return budget
}

// cvDecisionResponderGraceV2 optionally extends the success-path linger so
// decision-share responders outlive slow finalizers. Zero (default) keeps
// the recover-shard grace as the only linger window.
func cvDecisionResponderGraceV2() time.Duration {
	grace := arlDurationFromEnv("RLADKR_DECISION_RESPONDER_GRACE_MS", 0)
	if grace > 120*time.Second {
		return 120 * time.Second
	}
	return grace
}

func (s *cvAPDBNetworkServiceV2) EligibilityCoin(ctx context.Context) (*cvCoinOutputV2, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	invocation, err := cvEligibilityCoinInvocationV2(s.cfg.SID, s.cfg.Epoch)
	if err != nil {
		return nil, err
	}
	output, err := s.runCoin(ctx, invocation)
	if err != nil {
		return nil, err
	}
	if err := s.setEligibilityCoin(output); err != nil {
		return nil, err
	}
	return output, nil
}

func (s *cvAPDBNetworkServiceV2) ContributorCoin(
	ctx context.Context, pool *cvPoolV2, certificate *cvPoolCertificateV2,
) (*cvCoinOutputV2, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	if _, err := s.validatePool(pool); err != nil {
		return nil, err
	}
	if err := cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner); err != nil {
		return nil, fmt.Errorf("CV V2 contributor coin requires PoolCert: %w", err)
	}
	invocation, err := cvContributorCoinInvocationV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return nil, err
	}
	return s.runCoin(ctx, invocation)
}

func (s *cvAPDBNetworkServiceV2) setEligibilityCoin(output *cvCoinOutputV2) error {
	invocation, err := cvEligibilityCoinInvocationV2(s.cfg.SID, s.cfg.Epoch)
	if err != nil || cvVerifyCoinOutputV2(output, invocation, s.coinSigner) != nil {
		return fmt.Errorf("invalid CV V2 network eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesV2(
		s.cfg.OldRoster, output.Value, s.cfg.Params.proposerSampleSize, s.cfg.Params.validatorSampleSize,
	)
	if err != nil {
		return err
	}
	coinWire, err := cvCoinOutputV2CanonicalBytes(output)
	if err != nil {
		return err
	}
	coin, err := cvDecodeCoinOutputV2(coinWire)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if len(s.eligibilityValue) != 0 && !bytes.Equal(s.eligibilityValue, output.Value) {
		s.mu.Unlock()
		return fmt.Errorf("conflicting CV V2 network eligibility coin")
	}
	s.eligibilityValue = append([]byte(nil), output.Value...)
	s.eligibilityCoin = coin
	s.eligibleProposers = nodeSet(proposers)
	s.eligibleProposerSample = append([]int(nil), proposers...)
	s.validatorSample = append([]int(nil), validators...)
	s.agreementPublicContextCache = nil
	prewarmCatalog := false
	prewarmRecovery := false
	// Proposers still prewarm the full verified catalog. Sampled validators
	// follow the configured policy.
	_, proposerEligible := s.eligibleProposers[s.cfg.LocalNode]
	validatorSampled := false
	for _, member := range s.validatorSample {
		if member == s.cfg.LocalNode {
			validatorSampled = true
			break
		}
	}
	validatorPrewarmMode := cvValidatorPrewarmModeFromEnvV2(len(s.cfg.OldRoster))
	if proposerEligible && !s.verifiedCatalogPrewarm {
		s.verifiedCatalogPrewarm = true
		prewarmCatalog = true
	}
	if validatorSampled && !proposerEligible && !s.recoveryPrewarmV2 {
		switch validatorPrewarmMode {
		case cvValidatorPrewarmRecoverV2:
			s.recoveryPrewarmV2 = true
			prewarmRecovery = true
		case cvValidatorPrewarmFullV2:
			if !s.verifiedCatalogPrewarm {
				s.verifiedCatalogPrewarm = true
				prewarmCatalog = true
			}
		}
	}
	s.mu.Unlock()
	if prewarmCatalog {
		go func() { _, _ = s.AwaitVerifiedComponentCatalogV2(s.ctx) }()
	}
	if prewarmRecovery {
		go s.prewarmComponentRecoveryV2()
	}
	return nil
}

func (s *cvAPDBNetworkServiceV2) CertifyPool(ctx context.Context, pool *cvPoolV2) (*cvPoolCertificateV2, error) {
	if s == nil || ctx == nil || pool == nil || pool.ProposerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 pool certification caller")
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return nil, err
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	slot := s.poolSlotLocked(pool.ProposerID)
	if err := slot.state.observePool(pool); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if slot.certifying {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 pool certification already active")
	}
	if !slot.state.signed {
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
		if signErr != nil {
			s.mu.Unlock()
			return nil, signErr
		}
		if err := slot.state.markSigned(pool.Digest); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		slot.localShare = append([]byte(nil), localShare...)
		slot.shares[s.cfg.LocalNode] = append([]byte(nil), localShare...)
	} else if len(slot.localShare) == 0 {
		s.mu.Unlock()
		return nil, fmt.Errorf("incomplete CV V2 pool proposer slot")
	}
	slot.poolWire = append([]byte(nil), poolWire...)
	slot.certifying = true
	if len(slot.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(slot.sharesReady)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		slot.certifying = false
		s.mu.Unlock()
	}()

	// The transport already acknowledges delivery into the peer inbox. Send
	// once, then retry only peers that have not contributed a share. This keeps
	// a WAN RTT from turning a whole-fleet ticker into a resend storm.
	_ = s.sendFanoutMeasuredV2(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolOfferV2, poolWire)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-slot.sharesReady:
			goto recoverCertificate
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if member != s.cfg.LocalNode {
				if _, ok := slot.shares[member]; !ok {
					missing = append(missing, member)
				}
			}
		}
		s.mu.Unlock()
		if len(missing) == 0 {
			continue
		}
		_ = s.sendFanoutMeasuredV2(missing, -1, cvTagPoolOfferV2, poolWire)
	}
	select {
	case <-slot.sharesReady:
		goto recoverCertificate
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}

recoverCertificate:
	s.mu.Lock()
	shares := make(map[int][]byte, len(slot.shares))
	for member, share := range slot.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	recovered, err := s.controlSigner.Recover(cvPoolCertV2Domain, statement, shares)
	if err != nil {
		return nil, err
	}
	certificate := &cvPoolCertificateV2{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: recovered}
	if err := cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner); err != nil {
		return nil, err
	}
	certWire, err := cvPoolCertificateV2CanonicalBytes(certificate)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := slot.state.observeCertificate(certificate); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	slot.certWire = append([]byte(nil), certWire...)
	cvNotifyAPDBV2(slot.certReady)
	s.mu.Unlock()
	_ = s.sendFanoutMeasuredV2(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolCertV2, certWire)
	return certificate, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitCertifiedPool(ctx context.Context, proposer int) (*cvPoolV2, *cvPoolCertificateV2, error) {
	if s == nil || ctx == nil {
		return nil, nil, fmt.Errorf("invalid CV V2 certified-pool wait")
	}
	s.mu.Lock()
	if _, eligible := s.eligibleProposers[proposer]; !eligible {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("CV V2 pool proposer is not eligible")
	}
	slot := s.poolSlotLocked(proposer)
	ready := slot.state.certSeen
	certReady := slot.certReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, s.ctx.Err()
		case <-certReady:
		}
	}
	s.mu.Lock()
	poolWire := append([]byte(nil), slot.poolWire...)
	certWire := append([]byte(nil), slot.certWire...)
	s.mu.Unlock()
	pool, err := cvDecodePoolV2(poolWire, s.cfg.Params)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := cvDecodePoolCertificateV2(certWire)
	if err != nil || cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 certified pool state")
	}
	return pool, certificate, nil
}

func (s *cvAPDBNetworkServiceV2) CertifyAggregate(
	ctx context.Context, request *cvValidationRequestV2,
) (*cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || request == nil || request.Header.ProposerID != s.cfg.LocalNode ||
		s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate certification caller")
	}
	s.mu.Lock()
	eligible := make(map[int]struct{}, len(s.eligibleProposers))
	for member := range s.eligibleProposers {
		eligible[member] = struct{}{}
	}
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	if err := s.validateKnownComponentRefsV2(request.Pool.Components); err != nil {
		return nil, err
	}
	requestWire, canonicalLatency, err := cvValidateValidationRequestPublicAfterComponentValidationV2(
		request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
		s.apdbSigner, s.controlSigner, s.coinSigner,
	)
	if err != nil {
		return nil, err
	}
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingValidationV2{requestWire: append([]byte(nil), requestWire...), request: request,
		statement: statement, signatures: make(map[int][]byte), ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingValidation[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 aggregate certification already active")
	}
	s.pendingValidation[key] = pending
	record := s.validationRecords[key]
	if record == nil {
		record = &cvValidationRecordV2{requestWire: append([]byte(nil), requestWire...), request: request, statement: append([]byte(nil), statement...), resultReady: make(chan struct{}, 1)}
		s.validationRecords[key] = record
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingValidation[key] == pending {
			delete(s.pendingValidation, key)
		}
		s.mu.Unlock()
	}()

	firstWave, deferredWave := cvValidationRequestWavesV2(
		validatorSample, s.cfg.Params.validatorThreshold, request.Header.ProposerID,
	)
	if len(firstWave) < s.cfg.Params.validatorThreshold {
		return nil, fmt.Errorf("invalid CV V2 validation request wave")
	}
	networkStarted := time.Now()
	firstWaveComplete, err := cvSendValidationRequestWavesV2(
		ctx, s.ctx, pending.ready, firstWave, deferredWave, cvValidationFirstWaveGraceV2(),
		func(recipients []int) {
			_ = s.sendFanoutMeasuredV2(recipients, -1, cvTagValidationRequestV2, requestWire)
		},
	)
	if err != nil {
		return nil, err
	}
	if firstWaveComplete {
		goto buildCertificate
	}
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto buildCertificate
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(validatorSample))
		for _, member := range validatorSample {
			if _, ok := pending.signatures[member]; !ok {
				missing = append(missing, member)
			}
		}
		s.mu.Unlock()
		if len(missing) > 0 {
			_ = s.sendFanoutMeasuredV2(missing, -1, cvTagValidationRequestV2, requestWire)
		}
	}
	select {
	case <-pending.ready:
		goto buildCertificate
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}

buildCertificate:
	networkWaitLatency := time.Since(networkStarted)
	s.mu.Lock()
	signatures := make(map[int][]byte, len(pending.signatures))
	for member, signature := range pending.signatures {
		signatures[member] = append([]byte(nil), signature...)
	}
	s.mu.Unlock()
	formationStarted := time.Now()
	certificate, buildTimings, err := cvBuildValidationCertificateModeV2(
		&request.Header, validatorSample, s.cfg.Params.validatorThreshold, signatures, s.cfg.Validators, false,
	)
	s.recordCertificateFormationV2(cvCertificateValidationV2, time.Since(formationStarted))
	s.recordValidationProfileV2(
		canonicalLatency, networkWaitLatency, 0, buildTimings.AggregateVerify,
	)
	if err != nil {
		return nil, err
	}
	resultWire, err := cvValidationResultV2CanonicalBytes(
		&cvValidationResultV2{Statement: statement, Certificate: *certificate}, validatorSample,
	)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), resultWire...)
	cvNotifyAPDBV2(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationV2{request: request, certificate: certificate}
	cvNotifyAPDBV2(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
	if err := s.publishValidationResultV2(resultWire); err != nil {
		return nil, err
	}
	return certificate, nil
}

func (s *cvAPDBNetworkServiceV2) publishValidationResultV2(resultWire []byte) error {
	if s == nil || len(resultWire) == 0 {
		return fmt.Errorf("invalid CV V2 validation result publication")
	}
	for _, member := range s.cfg.OldRoster {
		if member == s.cfg.LocalNode {
			continue
		}
		// The certified candidate carries the same VCert and is sufficient for
		// the epoch's first-candidate path. Queue this backup-slot result on the
		// control lane instead of delaying candidate publication on every peer.
		if err := s.sendPriorityAsync(member, cvTagValidationResultV2, resultWire, nil); err != nil {
			return err
		}
	}
	return nil
}

func cvValidationFirstWaveGraceV2() time.Duration {
	grace := arlDurationFromEnv("RLADKR_VALIDATION_FIRST_WAVE_GRACE_MS", 2*time.Second)
	if grace < 100*time.Millisecond {
		return 100 * time.Millisecond
	}
	if grace > 10*time.Second {
		return 10 * time.Second
	}
	return grace
}

func CVValidationFirstWaveExtra() int {
	return cvValidationFirstWaveExtraV2
}

func CVValidationFirstWaveGrace() time.Duration {
	return cvValidationFirstWaveGraceV2()
}

func cvValidationRequestWavesV2(
	validatorSample []int, threshold, proposer int,
) ([]int, []int) {
	if threshold <= 0 || threshold > len(validatorSample) || proposer < 0 ||
		len(sortedUnique(validatorSample)) != len(validatorSample) {
		return nil, nil
	}
	ordered := cvRotatedAggregateRecoveryFirstWaveV2(validatorSample, len(validatorSample), proposer)
	firstCount := threshold + cvValidationFirstWaveExtraV2
	if firstCount > len(ordered) {
		firstCount = len(ordered)
	}
	return append([]int(nil), ordered[:firstCount]...), append([]int(nil), ordered[firstCount:]...)
}

func cvSendValidationRequestWavesV2(
	ctx, serviceCtx context.Context, ready <-chan struct{}, firstWave, deferredWave []int,
	grace time.Duration, send func([]int),
) (bool, error) {
	if ctx == nil || serviceCtx == nil || ready == nil || len(firstWave) == 0 || grace <= 0 || send == nil {
		return false, fmt.Errorf("invalid CV V2 validation request wave schedule")
	}
	send(firstWave)
	if len(deferredWave) == 0 {
		return false, nil
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-serviceCtx.Done():
		return false, serviceCtx.Err()
	case <-ready:
		return true, nil
	case <-timer.C:
		send(deferredWave)
		return false, nil
	}
}

func (s *cvAPDBNetworkServiceV2) AwaitCertifiedValidationV2(
	ctx context.Context, proposer int,
) (*cvValidationRequestV2, *cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || proposer < 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 certified validation wait")
	}
	s.mu.Lock()
	certified := s.certifiedValidation[proposer]
	ready := s.certifiedReadyLocked(proposer)
	s.mu.Unlock()
	if certified == nil {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, s.ctx.Err()
		case <-ready:
		}
		s.mu.Lock()
		certified = s.certifiedValidation[proposer]
		s.mu.Unlock()
	}
	if certified == nil {
		return nil, nil, fmt.Errorf("missing CV V2 certified validation")
	}
	return certified.request, certified.certificate, nil
}

func (s *cvAPDBNetworkServiceV2) certifiedReadyLocked(proposer int) chan struct{} {
	ready := s.certifiedReady[proposer]
	if ready == nil {
		ready = make(chan struct{}, 1)
		s.certifiedReady[proposer] = ready
	}
	return ready
}

func (s *cvAPDBNetworkServiceV2) AwaitValidationResult(
	ctx context.Context, request *cvValidationRequestV2,
) (*cvValidationCertificateV2, error) {
	if s == nil || ctx == nil || request == nil {
		return nil, fmt.Errorf("invalid CV V2 validation-result wait")
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil {
		wire, encodeErr := cvValidationRequestV2CanonicalBytes(request, s.cfg.Params)
		if encodeErr != nil {
			s.mu.Unlock()
			return nil, encodeErr
		}
		record = &cvValidationRecordV2{requestWire: wire, request: request, statement: append([]byte(nil), statement...), resultReady: make(chan struct{}, 1)}
		s.validationRecords[key] = record
	}
	ready := len(record.resultWire) != 0
	resultReady := record.resultReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-resultReady:
		}
	}
	s.mu.Lock()
	result := record.result
	resultWire := append([]byte(nil), record.resultWire...)
	s.mu.Unlock()
	if result != nil {
		if !bytes.Equal(result.Statement, statement) {
			return nil, fmt.Errorf("invalid CV V2 validation result state")
		}
		return &result.Certificate, nil
	}
	// Keep a complete decode/verification fallback for records populated by
	// internal or legacy paths that only retained the wire representation.
	decoded, err := cvDecodeValidationResultV2(resultWire, validatorSample)
	if err != nil || !bytes.Equal(decoded.Statement, statement) ||
		cvVerifyValidationCertificateV2(&decoded.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 validation result state")
	}
	return &decoded.Certificate, nil
}

func (s *cvAPDBNetworkServiceV2) FinalizeDecision(
	ctx context.Context, decided *cvAgreementObjectV2,
) (*cvHandoffV2, error) {
	if s == nil || ctx == nil || decided == nil || s.cfg.DecisionStore == nil ||
		!cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 decision finalization input")
	}
	statement, err := cvDecisionStatementV2(s.cfg.ExpectedContext, &decided.Header, &decided.ARC)
	if err != nil {
		return nil, err
	}
	localShare, err := s.cfg.DecisionStore.SignHandoffOnce(
		s.cfg.SID, s.cfg.Epoch, s.cfg.LocalNode, s.cfg.ExpectedContext,
		&decided.Header, &decided.ARC, s.controlSigner,
	)
	if err != nil {
		return nil, err
	}
	shareWire, err := cvDecisionShareV2CanonicalBytes(&cvDecisionShareV2{Statement: statement, Signature: localShare})
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingDecisionV2{statement: statement, shares: map[int][]byte{
		s.cfg.LocalNode: append([]byte(nil), localShare...),
	}, ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingDecisions[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 decision finalization already active")
	}
	s.pendingDecisions[key] = pending
	s.decisionLocalShares[key] = append([]byte(nil), localShare...)
	s.decisionLocalShareWires[key] = append([]byte(nil), shareWire...)
	if certificate := s.decisionCertificates[key]; len(certificate) != 0 {
		pending.certificate = append([]byte(nil), certificate...)
	}
	if len(pending.certificate) != 0 || len(pending.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingDecisions[key] == pending {
			delete(s.pendingDecisions, key)
		}
		s.mu.Unlock()
	}()
	// The retry loop is bounded by a wall-clock budget rather than a small
	// attempt count: under shared-host CPU contention the few-attempt window
	// (~5s) expired while a live, responding majority was still exchanging
	// shares, turning one slow node into a cluster-wide finalization failure.
	// The budget only extends liveness waiting; thresholds, statements, and
	// the share themselves are unchanged, and ctx cancellation still aborts
	// immediately.
	budget := cvDecisionRetryBudgetV2()
	budgetDeadline := time.Now().Add(budget)
	for attempt := 0; ; attempt++ {
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if member == s.cfg.LocalNode {
				continue
			}
			if _, received := pending.shares[member]; !received {
				missing = append(missing, member)
			}
		}
		shareCount := len(pending.shares)
		hasCertificate := len(pending.certificate) != 0
		s.mu.Unlock()
		if hasCertificate || shareCount >= s.controlSigner.Threshold() {
			break
		}
		if len(missing) != 0 {
			s.sendPriorityFanoutV2(missing, -1, cvTagDecisionShareV2, shareWire)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			break
		default:
		}
		s.mu.Lock()
		shareCount = len(pending.shares)
		hasCertificate = len(pending.certificate) != 0
		s.mu.Unlock()
		if hasCertificate || shareCount >= s.controlSigner.Threshold() {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsV2 && time.Now().After(budgetDeadline) {
			return nil, fmt.Errorf(
				"CV V2 decision finalization reached %d shares, need %d (budget %s)",
				shareCount, s.controlSigner.Threshold(), budget,
			)
		}
		timer := time.NewTimer(cvControlRetryDelayV2(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			break
		case <-timer.C:
		}
	}

	s.mu.Lock()
	decCert := append([]byte(nil), pending.certificate...)
	shares := make(map[int][]byte, len(pending.shares))
	for member, share := range pending.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	formationStarted := time.Now()
	if len(decCert) == 0 {
		decCert, err = s.controlSigner.Recover(cvDecisionCertificateV2Domain, statement, shares)
	}
	if err == nil && !s.controlSigner.VerifyRecovered(cvDecisionCertificateV2Domain, statement, decCert) {
		err = fmt.Errorf("invalid recovered CV V2 decision certificate")
	}
	s.recordCertificateFormationV2(cvCertificateDecisionV2, time.Since(formationStarted))
	if err != nil {
		return nil, err
	}
	handoff := &cvHandoffV2{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), Header: decided.Header,
		ARC: decided.ARC, DecCert: decCert,
	}
	if err := cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner); err != nil {
		return nil, err
	}
	handoffWire, err := cvHandoffV2CanonicalBytes(handoff)
	if err != nil {
		return nil, err
	}
	recipients := sortedUnique(append(append([]int(nil), s.cfg.OldRoster...), s.cfg.NewRoster...))
	s.sendFanoutMeasuredV2(recipients, s.cfg.LocalNode, cvTagHandoffV2, handoffWire)
	return handoff, nil
}

func (s *cvAPDBNetworkServiceV2) AwaitHandoff(ctx context.Context) (*cvHandoffV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 handoff wait")
	}
	s.mu.Lock()
	ready := len(s.acceptedHandoff) != 0
	handoffReady := s.handoffReady
	s.mu.Unlock()
	if !ready {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-handoffReady:
		}
	}
	s.mu.Lock()
	wire := append([]byte(nil), s.acceptedHandoff...)
	s.mu.Unlock()
	handoff, err := cvDecodeHandoffV2(wire)
	if err != nil || cvVerifyHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 accepted handoff")
	}
	return handoff, nil
}

func (s *cvAPDBNetworkServiceV2) RecoverAndExchangeScalarShare(
	ctx context.Context, handoff *cvHandoffV2,
) (*cvAggregateV2, fr.Element, *cvScalarShareOutputV2, bls12381.G1Affine, error) {
	if s == nil || ctx == nil || handoff == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil ||
		s.cfg.ScalarStore == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 receiver recovery input")
	}
	requestWire, err := cvAggregateRecoveryRequestV2CanonicalBytes(
		&cvAggregateRecoveryRequestV2{Handoff: *handoff},
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	payload, err := s.RecoverAggregate(ctx, requestWire, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestV2(recovered)
		if digestErr != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 recovered aggregate payload mismatch")
		}
		return nil
	})
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	aggregate, err := cvDecodeAggregateV2(payload, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadV2(&handoff.Header, payload, aggregate) != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 recovered aggregate")
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[s.cfg.LocalNode]
	secret, hasSecret := s.cfg.Receivers.localEncryptionSecrets[s.cfg.LocalNode]
	if !ok || !hasSecret {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("missing local CV V2 receiver secret")
	}
	scalar, output, decryptTimings, err := cvDecryptAggregateShareMeasuredV2(
		aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.LocalNode, receiverIndex,
		&s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1], secret,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	s.experimentMu.Lock()
	s.experimentMetrics.scalarBoundedDLogLatency += decryptTimings.ScalarBoundedDLog
	s.experimentMetrics.blindingGroupDecryptionLatency += decryptTimings.BlindingGroupDecryption
	s.experimentMu.Unlock()
	if err := s.cfg.ScalarStore.PersistOnce(
		s.cfg.SID, s.cfg.Epoch, s.cfg.LocalNode, aggregate.Digest, scalar, output,
	); err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("persist CV V2 scalar before release: %w", err)
	}
	outputWire, err := cvScalarShareOutputV2CanonicalBytesAfterValidation(output)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	key := string(aggregate.Digest)
	pending := &cvPendingScalarSharesV2{aggregate: aggregate, outputs: map[int]*cvScalarShareOutputV2{
		s.cfg.LocalNode: output,
	}, wires: map[int][]byte{s.cfg.LocalNode: append([]byte(nil), outputWire...)}, ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingScalarShares[key]; exists {
		s.mu.Unlock()
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("CV V2 scalar exchange already active")
	}
	s.localScalarOutputs[key] = append([]byte(nil), outputWire...)
	s.scalarAggregates[key] = aggregate
	s.pendingScalarShares[key] = pending
	if len(pending.outputs) >= s.cfg.Params.newShareThreshold {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingScalarShares[key] == pending {
			delete(s.pendingScalarShares, key)
		}
		s.mu.Unlock()
	}()
	for attempt := 0; ; attempt++ {
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.NewRoster))
		for _, member := range s.cfg.NewRoster {
			if member == s.cfg.LocalNode {
				continue
			}
			if _, received := pending.outputs[member]; !received {
				missing = append(missing, member)
			}
		}
		outputCount := len(pending.outputs)
		s.mu.Unlock()
		if outputCount >= s.cfg.Params.newShareThreshold {
			break
		}
		if len(missing) != 0 {
			s.sendFanoutMeasuredV2(missing, -1, cvTagAggregateShareV2, outputWire)
		}
		select {
		case <-ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			break
		default:
		}
		s.mu.Lock()
		outputCount = len(pending.outputs)
		s.mu.Unlock()
		if outputCount >= s.cfg.Params.newShareThreshold {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsV2 {
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf(
				"CV V2 scalar-share exchange reached %d outputs, need %d",
				outputCount, s.cfg.Params.newShareThreshold,
			)
		}
		timer := time.NewTimer(cvControlRetryDelayV2(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			break
		case <-timer.C:
		}
	}

	s.mu.Lock()
	outputs := make([]*cvScalarShareOutputV2, 0, len(pending.outputs))
	for _, share := range pending.outputs {
		outputs = append(outputs, share)
	}
	s.mu.Unlock()
	publicKey, err := cvRecoverThresholdPublicKeyAfterValidationV2(
		outputs, aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	return aggregate, scalar, output, publicKey, nil
}

func (s *cvAPDBNetworkServiceV2) validatePool(pool *cvPoolV2) ([]byte, error) {
	if pool == nil || !bytes.Equal(pool.ContextDigest, s.cfg.ExpectedContext) {
		return nil, fmt.Errorf("CV V2 pool context mismatch")
	}
	s.mu.Lock()
	_, eligible := s.eligibleProposers[pool.ProposerID]
	s.mu.Unlock()
	if !eligible {
		return nil, fmt.Errorf("CV V2 pool proposer is not eligible")
	}
	wire, err := cvPoolV2CanonicalBytes(pool, s.cfg.Params)
	if err != nil {
		return nil, err
	}
	if err := s.validateKnownComponentRefsV2(pool.Components); err != nil {
		return nil, fmt.Errorf("invalid CV V2 pool component: %w", err)
	}
	return wire, nil
}

func (s *cvAPDBNetworkServiceV2) validateKnownComponentRefsV2(refs []cvComponentRefV2) error {
	s.mu.Lock()
	knownRefs := make(map[int]cvComponentRefV2, len(refs))
	for _, ref := range refs {
		if known, ok := s.componentRefsV2[ref.Header.DealerID]; ok {
			knownRefs[ref.Header.DealerID] = known
		}
	}
	s.mu.Unlock()
	for _, ref := range refs {
		known, ok := knownRefs[ref.Header.DealerID]
		if ok && equalComponentRefsV2(known, ref) {
			continue
		}
		if ok {
			return fmt.Errorf("CV V2 component reference conflicts with verified cache")
		}
		if err := cvValidateComponentRefV2(ref, s.apdbSigner); err != nil {
			return err
		}
	}
	return nil
}

func (s *cvAPDBNetworkServiceV2) poolSlotLocked(proposer int) *cvNetworkPoolSlotV2 {
	slot := s.poolSlots[proposer]
	if slot == nil {
		slot = &cvNetworkPoolSlotV2{
			shares: make(map[int][]byte), sharesReady: make(chan struct{}, 1), certReady: make(chan struct{}, 1),
		}
		s.poolSlots[proposer] = slot
	}
	return slot
}

// Coin runs either V2 threshold-coin invocation among the old committee.
// The invocation itself is domain separated by cvEligibilityCoinInvocationV2
// or cvContributorCoinInvocationV2 before reaching this method.
func (s *cvAPDBNetworkServiceV2) runCoin(ctx context.Context, invocation []byte) (*cvCoinOutputV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) ||
		!cvV2SignerHasRole(s.coinSigner, cvV2RoleCoin) {
		return nil, fmt.Errorf("invalid CV V2 network coin input")
	}
	digest, err := cvCoinInvocationDigestV2(invocation)
	if err != nil {
		return nil, err
	}
	localSignature, err := s.coinSigner.SignShare(s.cfg.LocalNode, cvV2CoinDomain, digest)
	if err != nil {
		return nil, err
	}
	message, err := cvCoinShareV2CanonicalBytes(&cvCoinShareV2{InvocationDigest: digest, Signature: localSignature})
	if err != nil {
		return nil, err
	}
	pending := &cvPendingCoinV2{invocation: append([]byte(nil), invocation...), shares: make(map[int][]byte), ready: make(chan struct{}, 1)}
	key := string(digest)
	s.mu.Lock()
	if _, exists := s.pendingCoins[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 coin invocation already active")
	}
	pending.shares[s.cfg.LocalNode] = append([]byte(nil), localSignature...)
	s.pendingCoins[key] = pending
	s.localCoinShares[key] = append([]byte(nil), message...)
	if s.coinShareReplies[key] == nil {
		s.coinShareReplies[key] = make(map[int]struct{}, len(s.cfg.OldRoster)-1)
	}
	if s.coinShareReplyInFlight[key] == nil {
		s.coinShareReplyInFlight[key] = make(map[int]struct{}, len(s.cfg.OldRoster)-1)
	}
	if len(pending.shares) >= s.coinSigner.Threshold() {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingCoins[key] == pending {
			delete(s.pendingCoins, key)
		}
		s.mu.Unlock()
	}()

	sendShare := func(recipients []int) {
		started := time.Now()
		_ = s.sendFanoutMeasuredV2(recipients, s.cfg.LocalNode, cvTagCoinShareV2, message)
		s.recordCoinFanoutLatencyV2(time.Since(started))
	}
	sendShare(s.cfg.OldRoster)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsV2; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto recovered
		case <-time.After(cvControlRetryDelayV2(attempt)):
		}
		s.mu.Lock()
		missing := make([]int, 0, len(s.cfg.OldRoster))
		for _, member := range s.cfg.OldRoster {
			if _, ok := pending.shares[member]; !ok {
				missing = append(missing, member)
			}
		}
		s.mu.Unlock()
		if len(missing) > 0 {
			sendShare(missing)
		}
	}
	select {
	case <-pending.ready:
		goto recovered
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}

recovered:
	s.mu.Lock()
	shares := make(map[int][]byte, len(pending.shares))
	for member, share := range pending.shares {
		shares[member] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	certificate, err := s.coinSigner.Recover(cvV2CoinDomain, digest, shares)
	if err != nil {
		return nil, err
	}
	return cvBuildCoinOutputV2(invocation, certificate, s.coinSigner)
}

func (s *cvAPDBNetworkServiceV2) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	s.outboundWG.Wait()
	s.cryptoWG.Wait()
	s.recoveryWG.Wait()
	return nil
}

func (s *cvAPDBNetworkServiceV2) Lock(ctx context.Context, encoded *cvAPDBEncodedV2) (*cvAPDBLockV2, error) {
	return s.lockForPurposeV2(ctx, encoded, false)
}

func (s *cvAPDBNetworkServiceV2) LockAggregate(ctx context.Context, encoded *cvAPDBEncodedV2) (*cvAPDBLockV2, error) {
	return s.lockForPurposeV2(ctx, encoded, true)
}

func (s *cvAPDBNetworkServiceV2) lockForPurposeV2(
	ctx context.Context, encoded *cvAPDBEncodedV2, aggregate bool,
) (*cvAPDBLockV2, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) || encoded == nil ||
		s.cfg.ShardBytes <= 0 ||
		encoded.totalShards != s.cfg.TotalShards || encoded.dataShards != s.cfg.DataShards ||
		encoded.shardBytes != s.cfg.ShardBytes {
		return nil, fmt.Errorf("invalid CV V2 network LockPD input")
	}
	collector, err := newCVAPDBLockCollectorV2(encoded, s.cfg.OldRoster, s.apdbSigner)
	if err != nil {
		return nil, err
	}
	key := string(encoded.instanceDigest)
	pending := &cvAPDBPendingLockV2{collector: collector, ready: make(chan struct{}, 1), aggregate: aggregate}
	if err := s.registerLock(key, pending); err != nil {
		return nil, err
	}
	defer s.unregisterLock(key, pending)

	holders := collector.StoreRecipients()
	offers := make(map[int][]byte, len(holders))
	for _, holder := range holders {
		offer, offerErr := collector.StoreOffer(holder)
		if offerErr == nil {
			offers[holder] = offer
		}
	}
	started := time.Now()
	// Store offers are recipient-specific. Send them with the same bounded
	// fan-out used by other control paths instead of serializing WAN RTTs.
	if len(offers) != len(holders) {
		return nil, fmt.Errorf("CV V2 LockPD could not construct every store offer")
	}
	lockCtx, cancelFanout := context.WithCancel(ctx)
	defer cancelFanout()
	fanoutDone := make(chan []cvFanoutSendResultV2, 1)
	storeTag := cvTagAPDBStoreV2
	if aggregate {
		storeTag = cvTagAggregateAPDBStoreV2
	}
	go func() {
		results := s.sendRecipientPayloadFanoutContextMeasuredV2(
			lockCtx, holders, storeTag, offers,
		)
		for _, result := range results {
			if result.err == nil {
				s.recordDispersalBytesV2(aggregate, true, result.wireBytes)
			}
		}
		fanoutDone <- results
	}()
	var results []cvFanoutSendResultV2
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
		cancelFanout()
	case results = <-fanoutDone:
		sent := 0
		for _, result := range results {
			if result.err == nil {
				sent++
			}
		}
		if sent < s.apdbSigner.Threshold() {
			return nil, fmt.Errorf("CV V2 LockPD reached %d holders, need %d", sent, s.apdbSigner.Threshold())
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
		}
	}
	if aggregate {
		s.recordAggregateOfferSendLatencyV2(time.Since(started))
	}
	{
		formationStarted := time.Now()
		lock, recoverErr := collector.RecoverLock()
		if aggregate {
			s.recordCertificateFormationV2(cvCertificateARCV2, time.Since(formationStarted))
		}
		return lock, recoverErr
	}
}

func (s *cvAPDBNetworkServiceV2) RecoverComponent(
	ctx context.Context, lock *cvAPDBLockV2, bindingCheck func([]byte) error,
) ([]byte, error) {
	payload, _, err := s.recoverComponentForPurpose(ctx, lock, bindingCheck, cvRecoveryUnclassifiedV2, -1)
	return payload, err
}

// recoverComponentForPurpose additionally returns the uncompressed-point
// sidecar a dealer attached to its payload response; callers that decode the
// recovered leaf pass it to cvDecodeLeafV2WithHints, others discard it.
func (s *cvAPDBNetworkServiceV2) recoverComponentForPurpose(
	ctx context.Context, lock *cvAPDBLockV2, bindingCheck func([]byte) error, purpose cvRecoveryPurposeV2,
	dealerID int,
) ([]byte, []byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, nil, fmt.Errorf("invalid CV V2 component recovery caller")
	}
	started := time.Now()
	if purpose != cvRecoveryUnclassifiedV2 {
		defer func() { s.recordRecoveryLatencyV2(purpose, time.Since(started)) }()
	}
	request, err := cvAPDBLockV2CanonicalBytes(lock)
	if err != nil {
		return nil, nil, err
	}
	collector, err := newCVAPDBRecoveryCollectorV2(lock, s.cfg.OldRoster, s.cfg.DataShards, s.cfg.ShardBytes,
		s.cfg.MaximumPayload, s.apdbSigner, bindingCheck)
	if err != nil {
		return nil, nil, err
	}
	recipients := collector.RequestRecipients()
	firstWave := cvRecoveryFirstWaveV2(
		recipients, s.cfg.DataShards+cvRecoveryFirstWaveHoldersV2, s.cfg.LocalNode, dealerID,
	)
	waves := []cvRecoveryRequestWaveV2{{
		recipients: firstWave, responseGrace: cvRecoveryResponseGraceV2,
	}}
	if cvComponentRecoveryScheduleV2() == cvComponentRecoveryDealerFirstV2 &&
		cvMemberInRosterV2(dealerID, recipients) {
		holderWave := make([]int, 0, len(firstWave)-1)
		for _, recipient := range firstWave {
			if recipient != dealerID {
				holderWave = append(holderWave, recipient)
			}
		}
		waves = []cvRecoveryRequestWaveV2{
			{recipients: []int{dealerID}, responseGrace: cvComponentDirectGraceForCommitteeV2(len(s.cfg.OldRoster)), waitAfterSend: true,
				onGraceWait: func(elapsed time.Duration) { s.recordComponentDirectGraceWaitV2(elapsed) }},
			{recipients: holderWave, responseGrace: cvRecoveryResponseGraceV2},
		}
	}
	payload, err := s.runRecoveryWithSchedule(ctx, cvTagAPDBRecoverGetV2, request, string(lock.InstanceDigest),
		collector, false, purpose, waves)
	if err != nil {
		return nil, nil, err
	}
	return payload, collector.RecoveredHints(), nil
}

func (s *cvAPDBNetworkServiceV2) RecoverAggregate(
	ctx context.Context, requestWire []byte, bindingCheck func([]byte) error,
) ([]byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery caller")
	}
	collector, err := newCVAggregateRecoveryCollectorV2(requestWire, s.cfg.ExpectedContext, s.cfg.OldRoster,
		s.cfg.DataShards, s.cfg.ShardBytes, s.cfg.MaximumPayload, s.apdbSigner, s.controlSigner, bindingCheck)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	defer func() { s.recordRecoveryLatencyV2(cvRecoveryNewAggregateV2, time.Since(started)) }()
	request, err := cvDecodeAggregateRecoveryRequestV2(requestWire)
	if err != nil {
		return nil, err
	}
	if payload, ok, pullErr := s.tryAggregatePayloadPullV2(ctx, &request.Handoff, requestWire, bindingCheck); pullErr != nil {
		return nil, pullErr
	} else if ok {
		return payload, nil
	}
	receiverIndex := sort.SearchInts(s.cfg.NewRoster, s.cfg.LocalNode)
	firstWave := cvRotatedAggregateRecoveryFirstWaveV2(
		collector.RequestRecipients(), collector.dataShards+cvAggregateRecoveryFirstWaveExtraV2, receiverIndex,
	)
	payload, err := s.runRecoveryWithWave(ctx, cvTagAggregateRecoverGetV2, requestWire,
		string(collector.lock.InstanceDigest), collector, true, cvRecoveryNewAggregateV2,
		firstWave, cvRecoveryResponseGraceV2)
	if err == nil {
		s.cancelLateAggregateRecoveryV2(requestWire)
	}
	return payload, err
}

func (s *cvAPDBNetworkServiceV2) runRecoveryWithWave(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorV2, aggregate bool, purpose cvRecoveryPurposeV2,
	firstWave []int, responseGrace time.Duration,
) ([]byte, error) {
	return s.runRecoveryWithSchedule(ctx, requestTag, request, key, collector, aggregate, purpose,
		[]cvRecoveryRequestWaveV2{{recipients: firstWave, responseGrace: responseGrace}})
}

func (s *cvAPDBNetworkServiceV2) runRecoveryWithSchedule(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorV2, aggregate bool, purpose cvRecoveryPurposeV2,
	waves []cvRecoveryRequestWaveV2,
) ([]byte, error) {
	pending := &cvAPDBPendingRecoveryV2{collector: collector, ready: make(chan struct{}, 1), purpose: purpose}
	if err := s.registerRecovery(key, pending, aggregate); err != nil {
		return nil, err
	}
	defer s.unregisterRecovery(key, pending, aggregate)
	ready, err := cvSendRecoveryRequestsWithScheduleV2(
		ctx, s.ctx, pending.ready, collector.RequestRecipients(), collector.dataShards,
		cvControlRetryMaxAttemptsV2, cvControlRetryDelayV2, waves,
		func(recipients []int) []cvFanoutSendResultV2 {
			return s.sendFanoutMeasuredV2(recipients, -1, requestTag, request)
		},
		func(result cvFanoutSendResultV2) {
			s.recordRecoveryBytesV2(purpose, true, result.wireBytes)
		},
	)
	if err != nil {
		return nil, err
	}
	if ready {
		return s.recoverAndRecordComponentSourceV2(collector, purpose)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
		return s.recoverAndRecordComponentSourceV2(collector, purpose)
	}
}

func (s *cvAPDBNetworkServiceV2) recoverAndRecordComponentSourceV2(
	collector *cvAPDBRecoveryCollectorV2, purpose cvRecoveryPurposeV2,
) ([]byte, error) {
	payload, direct, err := collector.recoverWithSource()
	if err != nil || (purpose != cvRecoveryProposerCatalogV2 && purpose != cvRecoveryValidatorComponentV2) {
		return payload, err
	}
	s.experimentMu.Lock()
	if direct {
		s.experimentMetrics.componentDirectPayloadHits++
	} else {
		s.experimentMetrics.componentFragmentRecoveries++
	}
	s.experimentMu.Unlock()
	return payload, nil
}

const (
	cvRecoveryFirstWaveHoldersV2        = 3
	cvAggregateRecoveryFirstWaveExtraV2 = 3
	cvRecoveryResponseGraceV2           = 500 * time.Millisecond
	cvComponentDirectGraceDefaultV2     = 250 * time.Millisecond
	cvComponentDirectGraceLargeV2       = 500 * time.Millisecond
	cvComponentRecoveryHedgedV2         = "hedged"
	cvComponentRecoveryDealerFirstV2    = "dealer-first"
	cvComponentDealerResponseNormalV2   = "normal"
	cvComponentDealerResponseDropV2     = "drop"
)

func cvComponentRecoveryScheduleV2() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE")),
		cvComponentRecoveryHedgedV2) {
		return cvComponentRecoveryHedgedV2
	}
	return cvComponentRecoveryDealerFirstV2
}

func cvComponentDirectGraceV2() time.Duration {
	return durationEnvMs("RLADKR_COMPONENT_DIRECT_GRACE_MS", cvComponentDirectGraceDefaultV2)
}

func cvComponentDirectGraceForCommitteeV2(n int) time.Duration {
	fallback := cvComponentDirectGraceDefaultV2
	if n >= 32 {
		fallback = cvComponentDirectGraceLargeV2
	}
	return durationEnvMs("RLADKR_COMPONENT_DIRECT_GRACE_MS", fallback)
}

func cvComponentDealerResponseModeV2() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_DEALER_RESPONSE")),
		cvComponentDealerResponseDropV2) {
		return cvComponentDealerResponseDropV2
	}
	return cvComponentDealerResponseNormalV2
}

func cvComponentPayloadCompressionEnabledV2() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_PAYLOAD_COMPRESSION"))) {
	case "0", "false", "off", "disabled":
		return false
	default:
		return true
	}
}

// CVComponentRecoverySchedule reports the active component request schedule.
func CVComponentRecoverySchedule() string { return cvComponentRecoveryScheduleV2() }

// CVComponentDirectGrace reports how long dealer-first waits before requesting fragments.
func CVComponentDirectGrace() time.Duration { return cvComponentDirectGraceV2() }

// CVComponentDirectGraceForCommittee reports the active dealer-first grace,
// including the larger default used by committees of at least 32 nodes.
func CVComponentDirectGraceForCommittee(n int) time.Duration {
	return cvComponentDirectGraceForCommitteeV2(n)
}

// CVComponentDealerResponseMode reports the experiment-only dealer fault mode.
func CVComponentDealerResponseMode() string { return cvComponentDealerResponseModeV2() }

// CVComponentPayloadCompressionEnabled reports whether dealer payload
// responses use the compatible compressed transport representation.
func CVComponentPayloadCompressionEnabled() bool { return cvComponentPayloadCompressionEnabledV2() }

func cvRotatedAggregateRecoveryFirstWaveV2(recipients []int, count, rotateBy int) []int {
	if count <= 0 || len(recipients) == 0 {
		return nil
	}
	ordered := sortedUnique(recipients)
	if count > len(ordered) {
		count = len(ordered)
	}
	rotation := rotateBy % len(ordered)
	if rotation < 0 {
		rotation += len(ordered)
	}
	rotated := append(append([]int(nil), ordered[rotation:]...), ordered[:rotation]...)
	return append([]int(nil), rotated[:count]...)
}

func (s *cvAPDBNetworkServiceV2) cancelLateAggregateRecoveryV2(request []byte) {
	wire, err := cvAggregateRecoveryCancelV2CanonicalBytes(request)
	if err != nil {
		return
	}
	for _, holder := range s.cfg.OldRoster {
		_ = s.sendPriorityAsync(holder, cvTagAggregateRecoverCancelV2, wire, nil)
	}
}

// cvRecoveryFirstWaveV2 orders a dealer-anchored, requester-rotated subset of
// the recipients so the dealer's single payload response lands first while
// concurrent requesters spread their shard fallback over different holders.
func cvRecoveryFirstWaveV2(recipients []int, count, rotateBy, dealer int) []int {
	if count <= 0 || len(recipients) == 0 {
		return nil
	}
	ordered := append([]int(nil), recipients...)
	if r := rotateBy % len(ordered); r > 0 {
		ordered = append(ordered[r:], ordered[:r]...)
	}
	wave := make([]int, 0, count+1)
	if dealer >= 0 {
		wave = append(wave, dealer)
	}
	for _, member := range ordered {
		if len(wave) >= count+1 {
			break
		}
		if member == dealer {
			continue
		}
		wave = append(wave, member)
	}
	return wave
}

func cvSendRecoveryRequestsWithRetryV2(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, send func([]int) []cvFanoutSendResultV2,
	onSuccess func(cvFanoutSendResultV2),
) (bool, error) {
	return cvSendRecoveryRequestsWithWavesV2(
		ctx, serviceCtx, ready, recipients, dataShards, maxRetries, retryDelay, nil, 0, send, onSuccess,
	)
}

func cvSendRecoveryRequestsWithWavesV2(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, firstWave []int, responseGrace time.Duration,
	send func([]int) []cvFanoutSendResultV2,
	onSuccess func(cvFanoutSendResultV2),
) (bool, error) {
	return cvSendRecoveryRequestsWithScheduleV2(
		ctx, serviceCtx, ready, recipients, dataShards, maxRetries, retryDelay,
		[]cvRecoveryRequestWaveV2{{recipients: firstWave, responseGrace: responseGrace}}, send, onSuccess,
	)
}

type cvRecoveryRequestWaveV2 struct {
	recipients    []int
	responseGrace time.Duration
	waitAfterSend bool
	onGraceWait   func(time.Duration)
}

func cvSendRecoveryRequestsWithScheduleV2(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, waves []cvRecoveryRequestWaveV2,
	send func([]int) []cvFanoutSendResultV2,
	onSuccess func(cvFanoutSendResultV2),
) (bool, error) {
	succeeded := make(map[int]struct{}, len(recipients))
	allowed := make(map[int]struct{}, len(recipients))
	for _, recipient := range recipients {
		allowed[recipient] = struct{}{}
	}
	trackWave := func(targets []int) int {
		newlySucceeded := 0
		results := send(targets)
		byRecipient := make(map[int]cvFanoutSendResultV2, len(results))
		for _, result := range results {
			byRecipient[result.recipient] = result
		}
		for _, recipient := range targets {
			result, attempted := byRecipient[recipient]
			if attempted && result.err == nil {
				if _, duplicate := succeeded[recipient]; !duplicate {
					succeeded[recipient] = struct{}{}
					newlySucceeded++
					if onSuccess != nil {
						onSuccess(result)
					}
				}
			}
		}
		return newlySucceeded
	}
	for _, wave := range waves {
		targets := make([]int, 0, len(wave.recipients))
		seen := make(map[int]struct{}, len(wave.recipients))
		for _, recipient := range wave.recipients {
			if _, ok := allowed[recipient]; !ok {
				continue
			}
			if _, sent := succeeded[recipient]; sent {
				continue
			}
			if _, duplicate := seen[recipient]; duplicate {
				continue
			}
			seen[recipient] = struct{}{}
			targets = append(targets, recipient)
		}
		if len(targets) == 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-serviceCtx.Done():
			return false, serviceCtx.Err()
		case <-ready:
			return true, nil
		default:
		}
		waveSucceeded := trackWave(targets)
		if ((wave.waitAfterSend && waveSucceeded > 0) || len(succeeded) >= dataShards) && wave.responseGrace > 0 {
			graceStarted := time.Now()
			timer := time.NewTimer(wave.responseGrace)
			select {
			case <-ctx.Done():
				_ = timer.Stop()
				return false, ctx.Err()
			case <-serviceCtx.Done():
				_ = timer.Stop()
				return false, serviceCtx.Err()
			case <-ready:
				_ = timer.Stop()
				return true, nil
			case <-timer.C:
				if wave.onGraceWait != nil {
					wave.onGraceWait(time.Since(graceStarted))
				}
			}
		}
	}
	missing := make([]int, 0, len(recipients))
	for _, recipient := range recipients {
		if _, sent := succeeded[recipient]; !sent {
			missing = append(missing, recipient)
		}
	}
	if len(missing) == 0 {
		return false, nil
	}
	for attempt := 0; ; attempt++ {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-serviceCtx.Done():
			return false, serviceCtx.Err()
		case <-ready:
			return true, nil
		default:
		}
		results := send(missing)
		byRecipient := make(map[int]cvFanoutSendResultV2, len(results))
		for _, result := range results {
			byRecipient[result.recipient] = result
		}
		nextMissing := make([]int, 0, len(missing))
		for _, recipient := range missing {
			result, attempted := byRecipient[recipient]
			if !attempted || result.err != nil {
				nextMissing = append(nextMissing, recipient)
				continue
			}
			if _, duplicate := succeeded[recipient]; !duplicate {
				succeeded[recipient] = struct{}{}
				if onSuccess != nil {
					onSuccess(result)
				}
			}
		}
		if len(succeeded) >= dataShards {
			return false, nil
		}
		select {
		case <-ready:
			return true, nil
		default:
		}
		if attempt >= maxRetries {
			return false, fmt.Errorf("CV V2 APDB recovery reached %d holders, need %d", len(succeeded), dataShards)
		}
		missing = nextMissing
		timer := time.NewTimer(retryDelay(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return false, ctx.Err()
		case <-serviceCtx.Done():
			_ = timer.Stop()
			return false, serviceCtx.Err()
		case <-ready:
			_ = timer.Stop()
			return true, nil
		case <-timer.C:
		}
	}
}

func (s *cvAPDBNetworkServiceV2) run() {
	defer close(s.done)
	defer s.cancel()
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-s.inbox:
			if !ok {
				return
			}
			s.dispatch(msg)
		}
	}
}

type cvValidatorPrewarmModeV2 int

const (
	cvValidatorPrewarmOffV2 cvValidatorPrewarmModeV2 = iota
	cvValidatorPrewarmRecoverV2
	cvValidatorPrewarmFullV2
)

// cvValidatorPrewarmModeV2 selects how sampled validators prepare before a
// validation request arrives. At large n the full-catalog prewarm pulls and
// verifies every pool component on most nodes, which dominates cluster bytes
// and CPU; deployments pick the trade-off explicitly.
func cvValidatorPrewarmModeFromEnvV2(rosterSize int) cvValidatorPrewarmModeV2 {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("RLADKR_VALIDATOR_PREWARM"))) {
	case "full":
		return cvValidatorPrewarmFullV2
	case "recover":
		return cvValidatorPrewarmRecoverV2
	case "off":
		return cvValidatorPrewarmOffV2
	default:
		// Latency runs win from fully prewarmed validators while proposer
		// catalogs keep validator cores idle; beyond n=128 that idle window
		// shrinks and the full-catalog verify dominates committee CPU and
		// bytes, so payload prewarm with on-request verification takes over.
		if rosterSize > 128 {
			return cvValidatorPrewarmRecoverV2
		}
		return cvValidatorPrewarmFullV2
	}
}

type cvRecoveredPayloadCallV2 struct {
	done    chan struct{}
	payload []byte
	hints   []byte
	err     error
}

// cvRecoveredPayloadEntryV2 caches a recovered payload together with any
// uncompressed-point sidecar so a later verified decode reuses both.
type cvRecoveredPayloadEntryV2 struct {
	payload []byte
	hints   []byte
}

// cacheRecoveredPayloadLockedV2 takes ownership of collector-owned immutable
// slices. The caller must hold s.mu and must not mutate them after this call.
func (s *cvAPDBNetworkServiceV2) cacheRecoveredPayloadLockedV2(
	key string, payload, hints []byte,
) {
	if s.recoveredPayloadsV2 == nil {
		s.recoveredPayloadsV2 = make(map[string]cvRecoveredPayloadEntryV2, len(s.cfg.OldRoster))
	}
	if len(s.recoveredPayloadsV2) < len(s.cfg.OldRoster) {
		s.recoveredPayloadsV2[key] = cvRecoveredPayloadEntryV2{payload: payload, hints: hints}
	}
}

func cvRecoveredComponentPayloadKeyV2(ref cvComponentRefV2) string {
	// These fields are fixed-width after cvValidateComponentRefV2. Including
	// both payload and APDB bindings prevents an equivocating dealer from
	// sharing a cache/singleflight entry across conflicting component refs.
	return string(hashBytes(
		[]byte("ARL-CV-V2/recovered-component-payload-cache"),
		ref.Header.Instance, ref.Header.PayloadDigest, ref.Lock.Root,
	))
}

// recoveredComponentPayloadV2 returns a payload already bound to the supplied
// component ref plus any dealer-attached uncompressed-point sidecar. It uses
// the verified-leaf cache first, then a service-level recovered-payload cache, and only falling back
// to the network, whose collector runs the PayloadDigest binding check before
// success. Returned slices are immutable service-owned values.
func (s *cvAPDBNetworkServiceV2) recoveredComponentPayloadV2(
	ctx context.Context, ref cvComponentRefV2, purpose cvRecoveryPurposeV2,
) ([]byte, []byte, error) {
	key := cvRecoveredComponentPayloadKeyV2(ref)
	s.mu.Lock()
	if entry, ok := s.verifiedComponentsV2[ref.Header.DealerID]; ok &&
		equalComponentRefsV2(entry.ref, ref) && len(entry.payload) > 0 {
		payload := entry.payload
		s.mu.Unlock()
		return payload, nil, nil
	}
	if entry, ok := s.recoveredPayloadsV2[key]; ok {
		payload, hints := entry.payload, entry.hints
		s.mu.Unlock()
		return payload, hints, nil
	}
	if call := s.recoveredPayloadCallsV2[key]; call != nil {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, s.ctx.Err()
		case <-call.done:
			return call.payload, call.hints, call.err
		}
	}
	call := &cvRecoveredPayloadCallV2{done: make(chan struct{})}
	if s.recoveredPayloadCallsV2 == nil {
		s.recoveredPayloadCallsV2 = make(map[string]*cvRecoveredPayloadCallV2, 8)
	}
	s.recoveredPayloadCallsV2[key] = call
	s.mu.Unlock()

	payload, hints, err := s.recoverComponentForPurpose(ctx, &ref.Lock, func(recovered []byte) error {
		if !bytes.Equal(cvComponentPayloadDigestV2(recovered), ref.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 component payload mismatch")
		}
		return nil
	}, purpose, ref.Header.DealerID)

	s.mu.Lock()
	call.payload, call.hints, call.err = payload, hints, err
	delete(s.recoveredPayloadCallsV2, key)
	if err == nil {
		s.cacheRecoveredPayloadLockedV2(key, payload, hints)
	}
	close(call.done)
	s.mu.Unlock()
	return payload, hints, err
}

// prewarmComponentRecoveryV2 pulls every broadcast component payload into the
// recovered-payload cache without verifying it. Sampled validators use it so
// the expensive APVSS verification runs only for the components a validation
// request actually selects.
func (s *cvAPDBNetworkServiceV2) prewarmComponentRecoveryV2() {
	workers := make(chan struct{}, 4)
	var group sync.WaitGroup
	defer group.Wait()
	seen := make(map[int]struct{}, len(s.cfg.OldRoster))
	for {
		s.mu.Lock()
		pending := make([]cvComponentRefV2, 0, len(s.componentRefsV2))
		for dealer, ref := range s.componentRefsV2 {
			if _, done := seen[dealer]; done {
				continue
			}
			seen[dealer] = struct{}{}
			if _, verified := s.verifiedComponentsV2[dealer]; verified {
				continue
			}
			pending = append(pending, ref)
		}
		updates := s.componentRefUpdatesV2
		complete := len(seen) >= len(s.cfg.OldRoster)
		s.mu.Unlock()
		if complete {
			return
		}
		for _, ref := range pending {
			group.Add(1)
			workers <- struct{}{}
			go func(ref cvComponentRefV2) {
				defer func() { <-workers; group.Done() }()
				_, _, _ = s.recoveredComponentPayloadV2(s.ctx, ref, cvRecoveryValidatorComponentV2)
			}(ref)
		}
		select {
		case <-s.ctx.Done():
			return
		case <-updates:
		}
	}
}

// cacheDealerPayloadV2 retains this node's own locked component payload so the
// dealer can serve authenticated full-payload recovery responses.
func (s *cvAPDBNetworkServiceV2) cacheDealerPayloadV2(instanceDigest, payload []byte) {
	if s == nil || len(instanceDigest) != 32 || len(payload) == 0 || len(payload) > s.cfg.MaximumPayload {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dealerPayloadsV2 == nil {
		s.dealerPayloadsV2 = make(map[string][]byte, 8)
	}
	jobPayload := []byte(nil)
	if cached, exists := s.dealerPayloadsV2[string(instanceDigest)]; !exists && len(s.dealerPayloadsV2) < 64 {
		s.dealerPayloadsV2[string(instanceDigest)] = append([]byte(nil), payload...)
	} else if !exists && len(cached) == 0 {
		// Keep the old behavior when the bounded cache is full: the prepare job
		// still receives an owned payload and can build its response once.
		jobPayload = append([]byte(nil), payload...)
	}
	if s.dealerPayloadHintStates == nil {
		s.dealerPayloadHintStates = make(map[string]*cvDealerPayloadHintStateV2, 8)
	}
	if s.dealerPayloadHintStates[string(instanceDigest)] == nil {
		s.dealerPayloadHintStates[string(instanceDigest)] = &cvDealerPayloadHintStateV2{ready: make(chan struct{})}
	}
	go s.enqueueRecoveryJobV2(cvRecoveryJobV2{kind: cvRecoveryPrepareDealerV2,
		instanceDigest: append([]byte(nil), instanceDigest...), payload: jobPayload})
}

func (s *cvAPDBNetworkServiceV2) dealerPayloadV2(instanceDigest []byte) ([]byte, bool) {
	if s == nil || len(instanceDigest) != 32 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.dealerPayloadsV2[string(instanceDigest)]
	if !ok {
		return nil, false
	}
	return payload, true
}

// cvDealerPayloadHintStateV2 memoizes the uncompressed-point attachment for
// one cached dealer payload. Recording replays the exact consumer decode, so
// it costs one full verification per component, once, off the request path.
type cvDealerPayloadHintStateV2 struct {
	once     sync.Once
	ready    chan struct{}
	hints    []byte
	response []byte
}

func (s *cvAPDBNetworkServiceV2) dealerPayloadHintBytesV2(instanceDigest []byte) int {
	if s == nil || len(instanceDigest) != 32 {
		return 0
	}
	s.mu.Lock()
	state := s.dealerPayloadHintStates[string(instanceDigest)]
	s.mu.Unlock()
	if state == nil {
		return 0
	}
	<-state.ready
	return len(state.hints)
}

// dealerPayloadResponseV2 returns a cached full-payload response, computing
// hints and canonical encoding once per instance. A nil result means the
// payload could not be encoded and callers may use the shard fallback.
func (s *cvAPDBNetworkServiceV2) dealerPayloadResponseV2(instanceDigest, payload []byte) []byte {
	if s == nil || len(instanceDigest) != 32 || len(payload) == 0 {
		return nil
	}
	s.mu.Lock()
	if s.dealerPayloadHintStates == nil {
		s.dealerPayloadHintStates = make(map[string]*cvDealerPayloadHintStateV2, 8)
	}
	state := s.dealerPayloadHintStates[string(instanceDigest)]
	if state == nil {
		state = &cvDealerPayloadHintStateV2{ready: make(chan struct{})}
		s.dealerPayloadHintStates[string(instanceDigest)] = state
	}
	s.mu.Unlock()
	state.once.Do(func() {
		hintStarted := time.Now()
		defer close(state.ready)
		if cvPayloadHintsEnabledV2() && s.cfg.LeafContext != nil && s.cfg.Receivers != nil && s.cfg.Validators != nil {
			state.hints = cvRecordLeafDeferredHintsV2(payload, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators)
		}
		if len(state.hints) > cvMaxPayloadHintsBytesV2(s.cfg.MaximumPayload) {
			state.hints = nil
		}
		s.experimentMu.Lock()
		s.experimentMetrics.dealerHintBuildLatency += time.Since(hintStarted)
		s.experimentMu.Unlock()
		encodeStarted := time.Now()
		payloadResponse := &cvAPDBPayloadResponseV2{
			InstanceDigest: instanceDigest, Payload: payload, Hints: state.hints,
		}
		response, err := cvAPDBPayloadResponseV2CanonicalBytes(payloadResponse)
		if cvComponentPayloadCompressionEnabledV2() {
			response, err = cvAPDBPayloadResponseV2TransportBytes(payloadResponse)
		}
		if err == nil {
			state.response = response
			s.experimentMu.Lock()
			s.experimentMetrics.dealerResponseEncodeLatency += time.Since(encodeStarted)
			s.experimentMu.Unlock()
		}
	})
	<-state.ready
	return state.response
}

func (s *cvAPDBNetworkServiceV2) dispatch(msg Message) {
	s.recordTagBytesV2(msg.Tag, false, msg.WireBytes)
	switch msg.Tag {
	case cvTagAPDBStoreV2, cvTagAggregateAPDBStoreV2:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAPDBStoreOfferV2(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore, s.apdbSigner)
		if err == nil {
			responseTag := cvTagAPDBStoredShareV2
			if msg.Tag == cvTagAggregateAPDBStoreV2 {
				responseTag = cvTagAggregateARCShareV2
			}
			_ = s.sendAsync(msg.From, responseTag, response, nil)
		}
	case cvTagAPDBStoredShareV2, cvTagAggregateARCShareV2:
		response, err := cvDecodeAPDBStoredShareV2(msg.Body)
		if err != nil {
			return
		}
		pending := s.lookupLock(string(response.InstanceDigest))
		if pending != nil {
			if pending.aggregate != (msg.Tag == cvTagAggregateARCShareV2) {
				return
			}
			s.recordDispersalBytesV2(pending.aggregate, false, msg.WireBytes)
			if complete, addErr := pending.collector.AddDecodedStoredShare(msg.From, response, msg.Body); addErr == nil && complete {
				cvNotifyAPDBV2(pending.ready)
			}
		}
	case cvTagAPDBRecoverGetV2:
		if s.holderStore == nil {
			return
		}
		requestDigest := hashBytes(msg.Body)
		dedupeKey := fmt.Sprintf("%d:%x", msg.From, requestDigest)
		responseCacheKey := fmt.Sprintf("%x", requestDigest)
		if !s.claimRecoveryRequestV2(dedupeKey) {
			return
		}
		if !s.enqueueRecoveryJobV2(cvRecoveryJobV2{kind: cvRecoveryDealerRequestV2, msg: msg, dedupeKey: dedupeKey, responseCacheKey: responseCacheKey}) {
			s.releaseRecoveryRequestV2(dedupeKey)
		}
	case cvTagAPDBRecoverPayloadV2:
		_ = s.enqueueRecoveryJobV2(cvRecoveryJobV2{kind: cvRecoveryPayloadResponseV2, msg: msg})
	case cvTagAggregatePayloadGetV2:
		_ = s.enqueueRecoveryJobV2(cvRecoveryJobV2{kind: cvRecoveryAggregatePayloadRequestV2, msg: msg})
	case cvTagAggregatePayloadV2:
		s.handleAggregatePayloadPullResponseV2(msg)
	case cvTagAggregateRecoverGetV2:
		if s.holderStore == nil {
			return
		}
		requestKey := cvAggregateRecoveryRequestKeyV2{receiver: msg.From, digest: string(hashBytes(msg.Body))}
		if !s.registerAggregateRecoveryRequestV2(requestKey) {
			return
		}
		if !s.enqueueRecoveryJobV2(cvRecoveryJobV2{kind: cvRecoveryAggregateRequestV2, msg: msg, requestDigest: requestKey.digest}) {
			s.finishAggregateRecoveryRequestV2(requestKey)
		}
	case cvTagAggregateRecoverCancelV2:
		digest, err := cvDecodeAggregateRecoveryCancelV2(msg.Body)
		if err == nil {
			s.cancelAggregateRecoveryRequestV2(cvAggregateRecoveryRequestKeyV2{receiver: msg.From, digest: digest})
		}
	case cvTagAPDBRecoverStoreV2, cvTagAggregateRecoverStoreV2:
		store, err := cvDecodeAPDBStoreV2(msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes)
		if err != nil {
			return
		}
		aggregate := msg.Tag == cvTagAggregateRecoverStoreV2
		pending := s.lookupRecovery(string(store.InstanceDigest), aggregate)
		if pending != nil {
			if pending.collector.complete() {
				if !aggregate {
					s.recordComponentRecoveryLateRecvBytesV2(msg.WireBytes)
				}
				return
			}
			s.recordRecoveryBytesV2(pending.purpose, false, msg.WireBytes)
			if complete, addErr := pending.collector.AddDecodedStore(msg.From, store, msg.Body); addErr == nil {
				if complete {
					cvNotifyAPDBV2(pending.ready)
				}
			}
		} else if !aggregate {
			s.recordComponentRecoveryLateRecvBytesV2(msg.WireBytes)
		}
	case cvTagCoinShareV2:
		share, err := cvDecodeCoinShareV2(msg.Body)
		if err != nil || !cvV2SignerHasRole(s.coinSigner, cvV2RoleCoin) {
			return
		}
		key := string(share.InvocationDigest)
		s.mu.Lock()
		pending := s.pendingCoins[key]
		duplicate := false
		if pending != nil {
			_, duplicate = pending.shares[msg.From]
		}
		s.mu.Unlock()
		if !duplicate && !s.coinSigner.VerifyShare(
			msg.From, cvV2CoinDomain, share.InvocationDigest, share.Signature,
		) {
			return
		}
		var reply []byte
		s.mu.Lock()
		pending = s.pendingCoins[key]
		if pending != nil {
			if _, exists := pending.shares[msg.From]; !duplicate && !exists {
				pending.shares[msg.From] = append([]byte(nil), share.Signature...)
			}
			if len(pending.shares) >= s.coinSigner.Threshold() {
				cvNotifyAPDBV2(pending.ready)
			}
		}
		peer := msg.From
		if local := s.localCoinShares[key]; len(local) != 0 {
			replied := s.coinShareReplies[key]
			inFlight := s.coinShareReplyInFlight[key]
			if _, duplicate := replied[peer]; !duplicate {
				if _, queued := inFlight[peer]; !queued {
					inFlight[peer] = struct{}{}
					reply = append([]byte(nil), local...)
				}
			}
		}
		s.mu.Unlock()
		if len(reply) != 0 {
			err := s.sendAsync(peer, cvTagCoinShareV2, reply, func(sendErr error) {
				s.mu.Lock()
				delete(s.coinShareReplyInFlight[key], peer)
				if sendErr == nil {
					s.coinShareReplies[key][peer] = struct{}{}
				}
				s.mu.Unlock()
			})
			if err != nil {
				s.mu.Lock()
				delete(s.coinShareReplyInFlight[key], peer)
				s.mu.Unlock()
			}
		}
	case cvTagPoolOfferV2:
		s.handlePoolOffer(msg)
	case cvTagPoolCertShareV2:
		s.handlePoolCertificateShare(msg)
	case cvTagPoolCertV2:
		s.handlePoolCertificate(msg)
	case cvTagValidationRequestV2:
		s.handleValidationRequest(msg)
	case cvTagValidationSignatureV2:
		s.handleValidationSignature(msg)
	case cvTagValidationResultV2:
		s.handleValidationResult(msg)
	case cvTagDecisionShareV2:
		s.handleDecisionShare(msg)
	case cvTagHandoffV2:
		s.handleHandoff(msg)
	case cvTagAggregateShareV2:
		s.handleAggregateShare(msg)
	case cvTagLaneOfferV2:
		s.enqueueLaneOfferV2(msg)
	case cvTagLaneACKV2:
		s.handleLaneACKV2(msg)
	case cvTagComponentRefV2:
		s.handleComponentRefV2(msg)
	case cvTagCertifiedCandidateV2:
		s.enqueueCertifiedCandidateV2(msg)
	case cvTagCertifiedCandidateACKV2:
		digest, err := cvDecodeCertifiedCandidateACKV2(msg.Body)
		if err == nil {
			s.markCertifiedCandidateACKV2(digest, msg.From)
		}
	case cvTagCertifiedCandidateACKProbeV2:
		s.handleCertifiedCandidateACKProbeV2(msg)
	case cvTagCertifiedCandidateAnnounceV2:
		s.handleCertifiedCandidateAnnounceV2(msg)
	case cvTagCertifiedCandidateFetchV2:
		s.handleCertifiedCandidateFetchV2(msg)
	case cvTagCertifiedCandidateResponseV2:
		s.handleCertifiedCandidateResponseV2(msg)
	}
}

func (s *cvAPDBNetworkServiceV2) handleLaneOfferV2(msg Message) {
	if s.cfg.Receivers == nil || s.cfg.LeafContext == nil {
		return
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[msg.To]
	secret, secretOK := s.cfg.Receivers.localEncryptionSecrets[msg.To]
	identitySecret, identityOK := s.cfg.Receivers.localIdentitySecrets[msg.To]
	if !ok || !secretOK || !identityOK {
		return
	}
	offer, err := cvDecodeReceiverLaneOfferBeforeVerificationV2(msg.Body, s.cfg.LeafContext, msg.From, msg.To,
		receiverIndex, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1])
	if err != nil {
		return
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKAfterPointDecodingV2(
		s.cfg.LeafContext, msg.From, offer, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1],
		secret, s.cfg.Receivers.identityPublicKeys[receiverIndex-1], identitySecret,
	)
	if err != nil {
		return
	}
	message := &cvLaneACKMessageV2{DealerID: msg.From, ReceiverID: msg.To, ReceiverIndex: receiverIndex,
		OfferDigest: cvLaneOfferDigestV2(msg.Body), Evidence: *evidence}
	wire, err := cvLaneACKMessageV2CanonicalBytes(message, s.cfg.LeafContext)
	if err == nil {
		_ = s.send(msg.From, cvTagLaneACKV2, wire)
	}
}

func (s *cvAPDBNetworkServiceV2) handleLaneACKV2(msg Message) {
	s.mu.Lock()
	pending := s.pendingLaneACKsV2
	s.mu.Unlock()
	if pending == nil {
		return
	}
	message, err := cvDecodeLaneACKMessageV2(msg.Body, s.cfg.LeafContext)
	if err != nil || message.DealerID != s.cfg.LocalNode || message.ReceiverID != msg.From ||
		message.ReceiverIndex <= 0 || message.ReceiverIndex > len(s.cfg.NewRoster) ||
		s.cfg.NewRoster[message.ReceiverIndex-1] != msg.From {
		return
	}
	offerIndex := message.ReceiverIndex - 1
	wantOfferDigest := []byte(nil)
	if offerIndex >= 0 && offerIndex < len(pending.offerDigests) {
		wantOfferDigest = pending.offerDigests[offerIndex]
	}
	if len(wantOfferDigest) == 0 && offerIndex >= 0 && offerIndex < len(pending.offers) {
		wire, _ := cvReceiverLaneOfferV2CanonicalBytesAfterValidation(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[offerIndex],
		)
		wantOfferDigest = cvLaneOfferDigestV2(wire)
	}
	if offerIndex < 0 || offerIndex >= len(pending.offers) || !bytes.Equal(message.OfferDigest, wantOfferDigest) {
		return
	}
	if err := cvVerifyACKAfterLocalOwnershipValidationV2(
		s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[message.ReceiverIndex-1],
		s.cfg.Receivers.identityPublicKeys[message.ReceiverIndex-1], &message.Evidence); err != nil {
		return
	}
	s.mu.Lock()
	if s.pendingLaneACKsV2 != pending || pending.frozen {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.acks[message.ReceiverIndex]; !duplicate {
		pending.acks[message.ReceiverIndex] = &message.Evidence
	}
	if len(pending.acks) >= pending.quorum {
		cvNotifyAPDBV2(pending.ready)
	}
	if len(pending.acks) == len(s.cfg.NewRoster) {
		cvNotifyAPDBV2(pending.allReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handlePoolOffer(msg Message) {
	s.mu.Lock()
	if slot := s.poolSlots[msg.From]; slot != nil && bytes.Equal(slot.poolWire, msg.Body) && len(slot.localShareWire) != 0 {
		shareWire := append([]byte(nil), slot.localShareWire...)
		s.mu.Unlock()
		_ = s.sendAsync(msg.From, cvTagPoolCertShareV2, shareWire, nil)
		return
	}
	s.mu.Unlock()
	pool, err := cvDecodePoolV2(msg.Body, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From {
		return
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return
	}
	statement, err := cvPoolCertificateStatementV2(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return
	}
	s.mu.Lock()
	slot := s.poolSlotLocked(pool.ProposerID)
	if slot.state.observePool(pool) != nil {
		s.mu.Unlock()
		return
	}
	deferredCertificateWire := append([]byte(nil), slot.certWire...)
	if !slot.state.signed {
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertV2Domain, statement)
		if signErr != nil {
			s.mu.Unlock()
			return
		}
		if slot.state.markSigned(pool.Digest) != nil {
			s.mu.Unlock()
			return
		}
		slot.poolWire = append([]byte(nil), poolWire...)
		slot.localShare = append([]byte(nil), localShare...)
	} else if len(slot.localShare) == 0 || !bytes.Equal(slot.state.poolDigest, pool.Digest) {
		s.mu.Unlock()
		return
	}
	shareWire, err := cvPoolCertificateShareV2CanonicalBytes(&cvPoolCertificateShareV2{
		ProposerID: pool.ProposerID, PoolDigest: pool.Digest, Signature: slot.localShare,
	})
	if err == nil && len(slot.localShareWire) == 0 {
		slot.localShareWire = append([]byte(nil), shareWire...)
	}
	s.mu.Unlock()
	if len(deferredCertificateWire) != 0 {
		s.handlePoolCertificate(Message{From: pool.ProposerID, Body: deferredCertificateWire})
	}
	if err == nil {
		_ = s.sendAsync(pool.ProposerID, cvTagPoolCertShareV2, shareWire, nil)
	}
}

func (s *cvAPDBNetworkServiceV2) handlePoolCertificateShare(msg Message) {
	share, err := cvDecodePoolCertificateShareV2(msg.Body)
	if err != nil || share.ProposerID != s.cfg.LocalNode {
		return
	}
	s.mu.Lock()
	slot := s.poolSlots[share.ProposerID]
	if slot == nil || !slot.state.poolSeen || !bytes.Equal(slot.state.poolDigest, share.PoolDigest) {
		s.mu.Unlock()
		return
	}
	if _, duplicate := slot.shares[msg.From]; duplicate {
		s.mu.Unlock()
		return
	}
	statement, err := cvPoolCertificateStatementV2(s.cfg.ExpectedContext, share.ProposerID, share.PoolDigest)
	s.mu.Unlock()
	if err != nil || !s.controlSigner.VerifyShare(msg.From, cvPoolCertV2Domain, statement, share.Signature) {
		return
	}
	s.mu.Lock()
	if s.poolSlots[share.ProposerID] != slot || !slot.state.poolSeen ||
		!bytes.Equal(slot.state.poolDigest, share.PoolDigest) {
		s.mu.Unlock()
		return
	}
	if _, duplicate := slot.shares[msg.From]; !duplicate {
		slot.shares[msg.From] = append([]byte(nil), share.Signature...)
	}
	if len(slot.shares) >= s.controlSigner.Threshold() {
		cvNotifyAPDBV2(slot.sharesReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handlePoolCertificate(msg Message) {
	s.mu.Lock()
	if slot := s.poolSlots[msg.From]; slot != nil && slot.state.certSeen && bytes.Equal(slot.certWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	certificate, err := cvDecodePoolCertificateV2(msg.Body)
	if err != nil {
		return
	}
	s.mu.Lock()
	slot := s.poolSlots[msg.From]
	if slot == nil {
		slot = s.poolSlotLocked(msg.From)
	}
	if !slot.state.poolSeen {
		slot.certWire = append([]byte(nil), msg.Body...)
		s.mu.Unlock()
		return
	}
	if !bytes.Equal(slot.state.poolDigest, certificate.PoolDigest) {
		s.mu.Unlock()
		return
	}
	poolWire := append([]byte(nil), slot.poolWire...)
	s.mu.Unlock()
	pool, err := cvDecodePoolV2(poolWire, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From || cvVerifyPoolCertificateV2(pool, certificate, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if slot.state.observeCertificate(certificate) == nil {
		slot.certWire = append([]byte(nil), msg.Body...)
		cvNotifyAPDBV2(slot.certReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleValidationRequest(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil {
		return
	}
	requestKey := fmt.Sprintf("%d:%x", msg.From, hashBytes(msg.Body))
	s.mu.Lock()
	verifiedKey := s.validationRequestStatements[requestKey]
	localShareWire := append([]byte(nil), s.validationLocalShareWires[verifiedKey]...)
	_, inFlightFast := s.validationInFlight[verifiedKey]
	var cachedRequest *cvValidationRequestV2
	var cachedCanonical []byte
	if verifiedKey != "" {
		if record := s.validationRecords[verifiedKey]; record != nil && bytes.Equal(record.requestWire, msg.Body) && record.request != nil {
			cachedRequest = record.request
			cachedCanonical = record.requestWire
		}
	}
	s.mu.Unlock()
	if len(localShareWire) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagValidationSignatureV2, localShareWire, nil)
		return
	}
	if verifiedKey != "" && inFlightFast {
		return
	}
	request, canonical := cachedRequest, cachedCanonical
	if request == nil {
		var err error
		request, canonical, err = cvDecodeValidationRequestV2WithCanonical(msg.Body, s.cfg.Params)
		if err != nil || request.Header.ProposerID != msg.From {
			return
		}
	}
	s.mu.Lock()
	eligible := make(map[int]struct{}, len(s.eligibleProposers))
	for member := range s.eligibleProposers {
		eligible[member] = struct{}{}
	}
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	statement, err := cvValidationStatementV2(validatorSample, &request.Header)
	if err != nil {
		return
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record != nil && !bytes.Equal(record.requestWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	alreadyVerified := record != nil
	s.mu.Unlock()
	if !alreadyVerified {
		if err := s.validateKnownComponentRefsV2(request.Pool.Components); err != nil {
			return
		}
		if err := cvValidateValidationRequestPublicAfterComponentValidationV2WithCanonical(request, canonical,
			s.cfg.ExpectedContext, s.cfg.Params, eligible, s.apdbSigner, s.controlSigner, s.coinSigner); err != nil {
			return
		}
		s.mu.Lock()
		record = s.validationRecords[key]
		if record == nil {
			record = &cvValidationRecordV2{
				requestWire: append([]byte(nil), msg.Body...), request: request, statement: append([]byte(nil), statement...), resultReady: make(chan struct{}, 1),
			}
			s.validationRecords[key] = record
		} else if !bytes.Equal(record.requestWire, msg.Body) {
			s.mu.Unlock()
			return
		} else if record.request == nil {
			record.request = request
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	if s.validationRequestStatements == nil {
		s.validationRequestStatements = make(map[string]string)
	}
	s.validationRequestStatements[requestKey] = key
	s.mu.Unlock()
	s.mu.Lock()
	localShare := append([]byte(nil), s.validationLocalShares[key]...)
	localShareWire = append([]byte(nil), s.validationLocalShareWires[key]...)
	_, inFlight := s.validationInFlight[key]
	isValidator := cvContainsID(validatorSample, s.cfg.LocalNode)
	if isValidator && len(localShare) == 0 && !inFlight {
		if !cvReserveValidationStatementV2(
			s.validationOneShot, request.Header.ProposerID, statement,
		) {
			s.mu.Unlock()
			return
		}
		s.validationInFlight[key] = struct{}{}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		if len(localShareWire) != 0 {
			_ = s.sendPriorityAsync(request.Header.ProposerID, cvTagValidationSignatureV2, localShareWire, nil)
		} else {
			_ = s.sendValidationSignatureV2(request.Header.ProposerID, statement, localShare)
		}
		return
	}
	if isValidator && !inFlight {
		go s.validateAndSignAggregate(request, statement, key)
	}
}

func (s *cvAPDBNetworkServiceV2) validateAndSignAggregate(
	request *cvValidationRequestV2, statement []byte, key string,
) {
	defer func() {
		s.mu.Lock()
		delete(s.validationInFlight, key)
		s.mu.Unlock()
	}()
	leaves, err := s.loadValidationLeavesV2(request)
	if err != nil {
		return
	}
	aggregatePayload, _, err := s.recoverComponentForPurpose(s.ctx, &request.ARC, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestV2(recovered)
		if digestErr != nil || !bytes.Equal(digest, request.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 validation aggregate payload mismatch")
		}
		return nil
	}, cvRecoveryValidatorAggregateV2, -1)
	if err != nil {
		return
	}
	aggregate, err := cvAVerVerifiedV2(aggregatePayload, leaves, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadV2(&request.Header, aggregatePayload, aggregate) != nil {
		return
	}
	if err := s.rememberVerifiedAggregatePayloadV2(request.ARC.InstanceDigest, request.ARC.Root, aggregatePayload); err != nil {
		return
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	reservedStatement := append([]byte(nil), s.validationOneShot[request.Header.ProposerID]...)
	s.mu.Unlock()
	if !bytes.Equal(reservedStatement, statement) {
		return
	}
	signature, err := cvSignValidationV2(s.cfg.LocalNode, &request.Header, validatorSample, s.cfg.Validators)
	if err != nil {
		return
	}
	shareWire, err := cvValidationSignatureV2CanonicalBytes(
		&cvValidationSignatureV2{Statement: statement, Signature: signature},
	)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.validationLocalShares[key] = append([]byte(nil), signature...)
	if s.validationLocalShareWires == nil {
		s.validationLocalShareWires = make(map[string][]byte)
	}
	s.validationLocalShareWires[key] = append([]byte(nil), shareWire...)
	s.mu.Unlock()
	_ = s.sendPriorityAsync(request.Header.ProposerID, cvTagValidationSignatureV2, shareWire, nil)
}

func (s *cvAPDBNetworkServiceV2) sendValidationSignatureV2(
	proposer int, statement, signature []byte,
) error {
	shareWire, err := cvValidationSignatureV2CanonicalBytes(
		&cvValidationSignatureV2{Statement: statement, Signature: signature},
	)
	if err != nil {
		return err
	}
	// The share is useful only after the validator has completed the full
	// predicate. Keep this small threshold response ahead of bulk recovery
	// payloads so verified work reaches the proposer without queueing behind
	// unrelated component traffic.
	return s.sendPriorityAsync(proposer, cvTagValidationSignatureV2, shareWire, nil)
}

func (s *cvAPDBNetworkServiceV2) loadValidationLeavesV2(
	request *cvValidationRequestV2,
) ([]*cvLeafV2, error) {
	if request == nil || len(request.SelectedIndices) != s.cfg.Params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 validation leaf selection")
	}
	leaves := make([]*cvLeafV2, len(request.SelectedIndices))
	errs := make([]error, len(request.SelectedIndices))
	workers := cvLeafVerifyWorkers(len(request.SelectedIndices))
	jobs := make(chan int, len(request.SelectedIndices))
	for index := range request.SelectedIndices {
		jobs <- index
	}
	close(jobs)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				poolIndex := request.SelectedIndices[index]
				if poolIndex < 0 || poolIndex >= len(request.Pool.Components) {
					errs[index] = fmt.Errorf("invalid CV V2 validation pool index")
					continue
				}
				leaves[index], errs[index] = s.verifiedComponentLeafV2(
					s.ctx, request.Pool.Components[poolIndex], cvRecoveryValidatorComponentV2,
				)
			}
		}()
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return leaves, nil
}

func cvReserveValidationStatementV2(reservations map[int][]byte, proposer int, statement []byte) bool {
	if reservations == nil || proposer < 0 || len(statement) != 32 {
		return false
	}
	if previous, exists := reservations[proposer]; exists {
		return bytes.Equal(previous, statement)
	}
	reservations[proposer] = append([]byte(nil), statement...)
	return true
}

func (s *cvAPDBNetworkServiceV2) handleValidationSignature(msg Message) {
	wireDigest := string(hashBytes(msg.Body))
	s.mu.Lock()
	if sender, ok := s.validationSignatureWires[wireDigest]; ok && sender == msg.From {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	value, err := cvDecodeValidationSignatureV2(msg.Body)
	if err != nil || s.cfg.Validators == nil {
		return
	}
	key := string(value.Statement)
	s.mu.Lock()
	pending := s.pendingValidation[key]
	validatorSample := append([]int(nil), s.validatorSample...)
	if pending == nil || !cvContainsID(validatorSample, msg.From) {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.signatures[msg.From]; duplicate {
		s.mu.Unlock()
		return
	}
	index, ok := s.cfg.Validators.memberIndex[msg.From]
	if !ok {
		s.mu.Unlock()
		return
	}
	publicKey := s.cfg.Validators.publicKeys[index]
	s.mu.Unlock()
	verifyStarted := time.Now()
	valid := cvVerifyValidatorSignatureV2(&publicKey,
		cvValidationCertificateV2Domain, value.Statement, value.Signature)
	s.recordValidationProfileV2(0, 0, time.Since(verifyStarted), 0)
	if !valid {
		return
	}
	s.mu.Lock()
	if s.pendingValidation[key] != pending {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.signatures[msg.From]; !duplicate {
		pending.signatures[msg.From] = append([]byte(nil), value.Signature...)
		if s.validationSignatureWires == nil {
			s.validationSignatureWires = make(map[string]int)
		}
		if len(s.validationSignatureWires) < 512 {
			s.validationSignatureWires[wireDigest] = msg.From
		}
	}
	if len(pending.signatures) >= s.cfg.Params.validatorThreshold {
		cvNotifyAPDBV2(pending.ready)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleValidationResult(msg Message) {
	if s.cfg.Validators == nil {
		return
	}
	// An exact wire previously accepted from the same proposer is safe to
	// discard before decoding. Different senders still take the full path so
	// proposer/request binding cannot be bypassed by a shared wire digest.
	wireDigest := string(hashBytes(msg.Body))
	s.mu.Lock()
	if seen, ok := s.validationResultWires[wireDigest]; ok && seen.sender == msg.From {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	result, err := cvDecodeValidationResultV2(msg.Body, validatorSample)
	if err != nil {
		return
	}
	key := string(result.Statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil || len(record.requestWire) == 0 {
		s.mu.Unlock()
		return
	}
	request := record.request
	recordStatement := append([]byte(nil), record.statement...)
	requestWire := append([]byte(nil), record.requestWire...)
	s.mu.Unlock()
	if request == nil {
		request, err = cvDecodeValidationRequestV2(requestWire, s.cfg.Params)
	}
	if err != nil || request.Header.ProposerID != msg.From {
		return
	}
	if len(recordStatement) != 0 {
		if !bytes.Equal(recordStatement, result.Statement) {
			return
		}
		if cvVerifyValidationCertificateV2WithStatement(&result.Certificate, recordStatement, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
			return
		}
	} else {
		wantStatement, statementErr := cvValidationStatementV2(validatorSample, &request.Header)
		if statementErr != nil || !bytes.Equal(wantStatement, result.Statement) {
			return
		}
		if cvVerifyValidationCertificateV2(&result.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
			return
		}
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), msg.Body...)
	record.result = result
	if s.validationResultWires == nil {
		s.validationResultWires = make(map[string]cvValidationResultWireSeenV2)
	}
	if len(s.validationResultWires) < 256 {
		s.validationResultWires[wireDigest] = cvValidationResultWireSeenV2{
			sender: msg.From, statement: string(result.Statement),
		}
	}
	cvNotifyAPDBV2(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationV2{request: request, certificate: &result.Certificate}
	cvNotifyAPDBV2(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleDecisionShare(msg Message) {
	share, err := cvDecodeDecisionShareV2(msg.Body)
	if err != nil {
		return
	}
	key := string(share.Statement)
	s.mu.Lock()
	pending := s.pendingDecisions[key]
	localShare := append([]byte(nil), s.decisionLocalShares[key]...)
	localShareWire := append([]byte(nil), s.decisionLocalShareWires[key]...)
	duplicate := false
	if pending != nil {
		_, duplicate = pending.shares[msg.From]
	}
	s.mu.Unlock()
	if duplicate {
		if len(localShareWire) == 0 && len(localShare) != 0 {
			localShareWire, _ = cvDecisionShareV2CanonicalBytes(
				&cvDecisionShareV2{Statement: share.Statement, Signature: localShare},
			)
		}
		if len(localShareWire) != 0 {
			_ = s.sendPriorityAsync(msg.From, cvTagDecisionShareV2, localShareWire, nil)
		}
		return
	}
	if !s.controlSigner.VerifyShare(
		msg.From, cvDecisionCertificateV2Domain, share.Statement, share.Signature,
	) {
		return
	}
	s.mu.Lock()
	if s.pendingDecisions[key] != pending {
		s.mu.Unlock()
		return
	}
	if pending != nil {
		if _, duplicate = pending.shares[msg.From]; !duplicate {
			pending.shares[msg.From] = append([]byte(nil), share.Signature...)
		}
		if len(pending.shares) >= s.controlSigner.Threshold() {
			cvNotifyAPDBV2(pending.ready)
		}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		if len(localShareWire) == 0 {
			localShareWire, _ = cvDecisionShareV2CanonicalBytes(
				&cvDecisionShareV2{Statement: share.Statement, Signature: localShare},
			)
		}
		if len(localShareWire) != 0 {
			_ = s.sendPriorityAsync(msg.From, cvTagDecisionShareV2, localShareWire, nil)
		}
	}
}

func (s *cvAPDBNetworkServiceV2) handleHandoff(msg Message) {
	isOld := cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.OldRoster)
	isNew := cvMemberInRosterV2(s.cfg.LocalNode, s.cfg.NewRoster)
	if !isOld && !isNew {
		return
	}
	s.mu.Lock()
	if len(s.verifiedHandoffWire) != 0 && bytes.Equal(s.verifiedHandoffWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	handoff, err := cvDecodeHandoffV2(msg.Body)
	if err != nil || cvVerifyDecodedHandoffV2(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if len(s.verifiedHandoffWire) == 0 {
		s.verifiedHandoffWire = append([]byte(nil), msg.Body...)
	}
	if isOld {
		statement, statementErr := cvDecisionStatementV2(
			s.cfg.ExpectedContext, &handoff.Header, &handoff.ARC,
		)
		if statementErr == nil {
			key := string(statement)
			if len(s.decisionCertificates[key]) == 0 {
				s.decisionCertificates[key] = append([]byte(nil), handoff.DecCert...)
			}
			if pending := s.pendingDecisions[key]; pending != nil && len(pending.certificate) == 0 {
				pending.certificate = append([]byte(nil), handoff.DecCert...)
				cvNotifyAPDBV2(pending.ready)
			}
		}
	}
	if isNew && len(s.acceptedHandoff) == 0 {
		s.acceptedHandoff = append([]byte(nil), msg.Body...)
		cvNotifyAPDBV2(s.handoffReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) handleAggregateShare(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil {
		return
	}
	// The aggregate digest is the fixed first field after the domain. Decode it
	// only after locating a currently active aggregate, so unknown digests are
	// never retained.
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvAggregateShareWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainV2)) {
		return
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return
	}
	key := string(digest)
	s.mu.Lock()
	pending := s.pendingScalarShares[key]
	aggregate := s.scalarAggregates[key]
	localWire := append([]byte(nil), s.localScalarOutputs[key]...)
	duplicate := false
	if pending != nil {
		if previous := pending.wires[msg.From]; len(previous) != 0 {
			duplicate = bytes.Equal(previous, msg.Body)
		}
	}
	s.mu.Unlock()
	if aggregate == nil || len(localWire) == 0 {
		return
	}
	if duplicate {
		_ = s.sendAsync(msg.From, cvTagAggregateShareV2, localWire, nil)
		return
	}
	output, err := cvDecodeScalarShareOutputV2(
		msg.Body, aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers,
	)
	if err != nil || output.ReceiverID != msg.From {
		return
	}
	if pending != nil {
		s.mu.Lock()
		if s.pendingScalarShares[key] != pending {
			s.mu.Unlock()
			return
		}
		if _, duplicate = pending.outputs[msg.From]; !duplicate {
			pending.outputs[msg.From] = output
		}
		if pending.wires == nil {
			pending.wires = make(map[int][]byte)
		}
		if len(pending.wires[msg.From]) == 0 {
			pending.wires[msg.From] = append([]byte(nil), msg.Body...)
		}
		if len(pending.outputs) >= s.cfg.Params.newShareThreshold {
			cvNotifyAPDBV2(pending.ready)
		}
		s.mu.Unlock()
	}
	_ = s.sendAsync(msg.From, cvTagAggregateShareV2, localWire, nil)
}

func (s *cvAPDBNetworkServiceV2) send(to int, tag string, payload []byte) error {
	_, err := s.sendMeasured(to, tag, payload)
	return err
}

func (s *cvAPDBNetworkServiceV2) sendMeasured(to int, tag string, payload []byte) (int, error) {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, int(s.cfg.Epoch), payload)
	if err != nil {
		return 0, err
	}
	return s.sendEnvelopeMeasuredV2(to, tag, envelope)
}

func (s *cvAPDBNetworkServiceV2) sendEnvelopeMeasuredV2(to int, tag string, envelope []byte) (int, error) {
	wire, err := s.auth.seal(s.cfg.LocalNode, to, tag, envelope)
	if err != nil {
		return 0, err
	}
	message := Message{From: s.cfg.LocalNode, To: to, Tag: tag, Body: wire}
	if err := s.transport.Send(message); err != nil {
		return 0, err
	}
	wireBytes := tcpMessageFrameFixedBytes + len(tag) + len(wire)
	s.recordTagBytesV2(tag, true, wireBytes)
	return wireBytes, nil
}

// sendFanoutMeasuredV2 bounds goroutine count while allowing independent TCP
// destinations to make progress concurrently. It preserves the recipient set
// and returns only after every attempted send has completed.
func (s *cvAPDBNetworkServiceV2) sendFanoutMeasuredV2(
	recipients []int, excluded int, tag string, payload []byte,
) []cvFanoutSendResultV2 {
	targets := make([]int, 0, len(recipients))
	for _, recipient := range recipients {
		if recipient != excluded {
			targets = append(targets, recipient)
		}
	}
	if len(targets) == 0 {
		return nil
	}
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, int(s.cfg.Epoch), payload)
	if err != nil {
		results := make([]cvFanoutSendResultV2, 0, len(targets))
		for _, target := range targets {
			results = append(results, cvFanoutSendResultV2{recipient: target, err: err})
		}
		return results
	}
	parallel := cvFanoutMaxParallelV2
	if parallel > len(targets) {
		parallel = len(targets)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultV2, len(targets))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				wireBytes, err := s.sendEnvelopeMeasuredV2(target, tag, envelope)
				results <- cvFanoutSendResultV2{recipient: target, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultV2, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}
	return out
}

// sendPriorityFanoutV2 routes small threshold/control messages through the
// priority lane. The authenticated envelope and byte accounting remain the
// same as sendFanoutMeasuredV2; only queue selection changes.
func (s *cvAPDBNetworkServiceV2) sendPriorityFanoutV2(recipients []int, excluded int, tag string, payload []byte) {
	for _, recipient := range recipients {
		if recipient == excluded {
			continue
		}
		_ = s.sendPriorityAsync(recipient, tag, payload, nil)
	}
}

// sendRecipientPayloadFanoutMeasuredV2 is the bounded-fanout equivalent for
// authenticated messages whose payload is intentionally recipient-specific.
func (s *cvAPDBNetworkServiceV2) sendRecipientPayloadFanoutMeasuredV2(
	recipients []int, tag string, payloads map[int][]byte,
) []cvFanoutSendResultV2 {
	if len(recipients) == 0 || len(payloads) == 0 {
		return nil
	}
	parallel := cvFanoutMaxParallelV2
	if parallel > len(recipients) {
		parallel = len(recipients)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultV2, len(recipients))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for recipient := range jobs {
				payload := payloads[recipient]
				wireBytes, err := s.sendMeasured(recipient, tag, payload)
				results <- cvFanoutSendResultV2{recipient: recipient, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, recipient := range recipients {
		jobs <- recipient
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultV2, 0, len(recipients))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (s *cvAPDBNetworkServiceV2) sendRecipientPayloadFanoutContextMeasuredV2(
	ctx context.Context, recipients []int, tag string, payloads map[int][]byte,
) []cvFanoutSendResultV2 {
	if ctx == nil || len(recipients) == 0 || len(payloads) == 0 {
		return nil
	}
	parallel := min(cvFanoutMaxParallelV2, len(recipients))
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultV2, len(recipients))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for recipient := range jobs {
				wireBytes, err := s.sendMeasured(recipient, tag, payloads[recipient])
				results <- cvFanoutSendResultV2{recipient: recipient, wireBytes: wireBytes, err: err}
			}
		}()
	}
sendLoop:
	for _, recipient := range recipients {
		select {
		case jobs <- recipient:
		case <-ctx.Done():
			break sendLoop
		case <-s.ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultV2, 0, len(recipients))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (s *cvAPDBNetworkServiceV2) recordTagBytesV2(tag string, sent bool, n int) {
	if s == nil || tag == "" || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	if s.experimentMetrics.tagSentBytes == nil {
		s.experimentMetrics.tagSentBytes = make(map[string]uint64)
	}
	if s.experimentMetrics.tagRecvBytes == nil {
		s.experimentMetrics.tagRecvBytes = make(map[string]uint64)
	}
	if sent {
		s.experimentMetrics.tagSentBytes[tag] += uint64(n)
	} else {
		s.experimentMetrics.tagRecvBytes[tag] += uint64(n)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordDispersalBytesV2(aggregate, sent bool, n int) {
	if s == nil || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	if aggregate {
		if sent {
			s.experimentMetrics.aggregateDispersalSentBytes += uint64(n)
		} else {
			s.experimentMetrics.aggregateDispersalRecvBytes += uint64(n)
		}
	} else if sent {
		s.experimentMetrics.componentDispersalSentBytes += uint64(n)
	} else {
		s.experimentMetrics.componentDispersalRecvBytes += uint64(n)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordRecoveryBytesV2(purpose cvRecoveryPurposeV2, sent bool, n int) {
	if s == nil || purpose == cvRecoveryUnclassifiedV2 || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvRecoveryProposerCatalogV2:
		if sent {
			s.experimentMetrics.proposerRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.proposerRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorComponentV2:
		if sent {
			s.experimentMetrics.validatorComponentRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorComponentRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorAggregateV2:
		if sent {
			s.experimentMetrics.validatorAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorAggregateRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryNewAggregateV2:
		if sent {
			s.experimentMetrics.newAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.newAggregateRecoveryRecvBytes += uint64(n)
		}
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordRecoveryLatencyV2(purpose cvRecoveryPurposeV2, elapsed time.Duration) {
	if s == nil || purpose == cvRecoveryUnclassifiedV2 || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if purpose == cvRecoveryProposerCatalogV2 {
		s.experimentMetrics.proposerRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorComponentV2 {
		s.experimentMetrics.validatorComponentRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorAggregateV2 {
		s.experimentMetrics.validatorAggregateRecoveryLatency += elapsed
	} else if purpose == cvRecoveryNewAggregateV2 {
		s.experimentMetrics.newAggregateRecoveryLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordComponentRecoveryResponseSentV2(payload, hints, fragment int) {
	if s == nil || payload < 0 || hints < 0 || fragment < 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.dealerPayloadSentBytes += uint64(payload)
	s.experimentMetrics.dealerHintSentBytes += uint64(hints)
	s.experimentMetrics.holderFragmentSentBytes += uint64(fragment)
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordComponentRecoveryLateRecvBytesV2(wireBytes int) {
	if s == nil || wireBytes <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.componentRecoveryLateRecvBytes += uint64(wireBytes)
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordComponentDirectGraceWaitV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.componentDirectGraceWait += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCoinFanoutLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.coinFanoutLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordAggregateOfferSendLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.aggregateOfferSendLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCandidateFanoutAttemptV2(wait time.Duration, retry bool) {
	if s == nil || wait < 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.candidateFanoutACKWaitLatency += wait
	s.experimentMetrics.candidateFanoutAttempts++
	if retry {
		s.experimentMetrics.candidateFanoutRetryWaitLatency += wait
		s.experimentMetrics.candidateFanoutRetries++
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordCandidateFanoutPeerLatencyV2(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if elapsed > s.experimentMetrics.candidateFanoutMaxPeerLatency {
		s.experimentMetrics.candidateFanoutMaxPeerLatency = elapsed
	}
	s.experimentMu.Unlock()
}

type cvCertificatePurposeV2 uint8

const (
	cvCertificateARCV2 cvCertificatePurposeV2 = iota + 1
	cvCertificateValidationV2
	cvCertificateDecisionV2
)

func (s *cvAPDBNetworkServiceV2) recordCertificateFormationV2(purpose cvCertificatePurposeV2, elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvCertificateARCV2:
		s.experimentMetrics.arcFormationLatency += elapsed
	case cvCertificateValidationV2:
		s.experimentMetrics.validationCertificateLatency += elapsed
	case cvCertificateDecisionV2:
		s.experimentMetrics.decisionCertificateLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) recordValidationProfileV2(
	canonical, networkWait, signatureVerify, aggregateVerify time.Duration,
) {
	if s == nil {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.validationCanonicalLatency += canonical
	s.experimentMetrics.validationNetworkWaitLatency += networkWait
	s.experimentMetrics.validationSignatureVerifyLatency += signatureVerify
	s.experimentMetrics.validationAggregateVerifyLatency += aggregateVerify
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceV2) experimentMetricsV2() cvServiceExperimentMetricsV2 {
	if s == nil {
		return cvServiceExperimentMetricsV2{}
	}
	s.experimentMu.Lock()
	defer s.experimentMu.Unlock()
	metrics := s.experimentMetrics
	metrics.tagSentBytes = cloneUint64MapV2(metrics.tagSentBytes)
	metrics.tagRecvBytes = cloneUint64MapV2(metrics.tagRecvBytes)
	return metrics
}

func cloneUint64MapV2(input map[string]uint64) map[string]uint64 {
	output := make(map[string]uint64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (s *cvAPDBNetworkServiceV2) registerLock(key string, pending *cvAPDBPendingLockV2) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pendingLocks[key]; exists {
		return fmt.Errorf("CV V2 LockPD already active for instance")
	}
	s.pendingLocks[key] = pending
	return nil
}

func (s *cvAPDBNetworkServiceV2) unregisterLock(key string, pending *cvAPDBPendingLockV2) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingLocks[key] == pending {
		delete(s.pendingLocks, key)
	}
}

func (s *cvAPDBNetworkServiceV2) lookupLock(key string) *cvAPDBPendingLockV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocks[key]
}

func (s *cvAPDBNetworkServiceV2) registerRecovery(key string, pending *cvAPDBPendingRecoveryV2, aggregate bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.pendingComponents
	if aggregate {
		target = s.pendingAggregates
	}
	if _, exists := target[key]; exists {
		return fmt.Errorf("CV V2 APDB recovery already active for instance")
	}
	target[key] = pending
	return nil
}

func (s *cvAPDBNetworkServiceV2) unregisterRecovery(key string, pending *cvAPDBPendingRecoveryV2, aggregate bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	target := s.pendingComponents
	if aggregate {
		target = s.pendingAggregates
	}
	if target[key] == pending {
		delete(target, key)
	}
}

func (s *cvAPDBNetworkServiceV2) lookupRecovery(key string, aggregate bool) *cvAPDBPendingRecoveryV2 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if aggregate {
		return s.pendingAggregates[key]
	}
	return s.pendingComponents[key]
}

func cvNotifyAPDBV2(ready chan struct{}) {
	select {
	case ready <- struct{}{}:
	default:
	}
}
