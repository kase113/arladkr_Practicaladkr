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

type cvAPDBNetworkServiceConfigScalar struct {
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
	Params          cvScalarParams
	EligibilityCoin *cvCoinOutputScalar
	LeafContext     *cvLeafContextScalar
	Receivers       *cvReceiverKeyMaterialScalar
	Validators      *cvValidatorKeyMaterialScalar
	DecisionStore   *cvDecisionSignStoreScalar
	ScalarStore     *cvScalarStoreScalar
}

type cvAPDBPendingLockScalar struct {
	collector *cvAPDBLockCollectorScalar
	ready     chan struct{}
	aggregate bool
}

type cvAPDBPendingRecoveryScalar struct {
	collector *cvAPDBRecoveryCollectorScalar
	ready     chan struct{}
	purpose   cvRecoveryPurposeScalar
}

type cvPendingAggregatePayloadPullScalar struct {
	allowed   int
	responses chan cvAggregatePayloadPullResponseScalar
}

type cvAggregatePayloadPullResponseScalar struct {
	from      int
	payload   []byte
	wireBytes int
}

type cvAggregatePayloadResponseCallScalar struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvAggregatePayloadCacheEntryScalar struct {
	root    []byte
	payload []byte
}

type cvRecoveryPurposeScalar uint8

const (
	cvRecoveryUnclassifiedScalar cvRecoveryPurposeScalar = iota
	cvRecoveryProposerCatalogScalar
	cvRecoveryValidatorComponentScalar
	cvRecoveryValidatorAggregateScalar
	cvRecoveryNewAggregateScalar
)

const (
	cvControlRetryIntervalScalar     = 250 * time.Millisecond
	cvControlRetryMaxAttemptsScalar  = 4
	cvFanoutMaxParallelScalar        = 16
	cvValidationFirstWaveExtraScalar = 2
)

type cvFanoutSendResultScalar struct {
	recipient int
	wireBytes int
	err       error
}

type cvOutboundMessageScalar struct {
	to         int
	tag        string
	payload    []byte
	shouldSend func() bool
	onResult   func(error)
	onMeasured func(int, error)
}

type cvCryptoJobKindScalar uint8

const (
	cvCryptoJobLaneOfferScalar cvCryptoJobKindScalar = iota + 1
	cvCryptoJobCertifiedCandidateScalar
)

type cvCryptoJobScalar struct {
	kind   cvCryptoJobKindScalar
	msg    Message
	digest string
}

type cvRecoveryJobKindScalar uint8

const (
	cvRecoveryPrepareDealerScalar cvRecoveryJobKindScalar = iota + 1
	cvRecoveryDealerRequestScalar
	cvRecoveryPayloadResponseScalar
	cvRecoveryAggregateRequestScalar
	cvRecoveryAggregatePayloadRequestScalar
)

const cvAggregateRecoveryResponseCacheCapacityScalar = 64

const cvComponentRecoveryResponseCacheCapacityScalar = 256

const cvAggregatePayloadResponseCacheCapacityScalar = 64

const cvAggregateRecoveryCancelDomainScalar = "RLA/CV-V2/AGG-RECOVER-CANCEL"

const cvAggregatePayloadResponseDomainScalar = "RLA/CV-V2/AGG-PAYLOAD-RESPONSE"

type cvRecoveryJobScalar struct {
	kind             cvRecoveryJobKindScalar
	msg              Message
	instanceDigest   []byte
	payload          []byte
	requestDigest    string
	dedupeKey        string
	responseCacheKey string
	queuedAt         time.Time
}

type cvAggregateRecoveryResponseCallScalar struct {
	ready    chan struct{}
	response []byte
	err      error
}

// cvComponentRecoveryResponseCallScalar coalesces concurrent holder-side store
// construction for the same immutable recovery request.  Each requester still
// receives its own network response after the shared computation completes.
type cvComponentRecoveryResponseCallScalar struct {
	ready    chan struct{}
	response []byte
	err      error
}

type cvAggregateRecoveryRequestKeyScalar struct {
	receiver int
	digest   string
}

func cvAggregateRecoveryCancelScalarCanonicalBytes(request []byte) ([]byte, error) {
	if len(request) == 0 {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery cancel request")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregateRecoveryCancelDomainScalar))
	_ = cvWriteBytes(&wire, hashBytes(request))
	return wire.Bytes(), nil
}

func cvDecodeAggregateRecoveryCancelScalar(wire []byte) (string, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregateRecoveryCancelDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateRecoveryCancelDomainScalar)) {
		return "", fmt.Errorf("invalid CV V2 aggregate recovery cancel domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return "", fmt.Errorf("invalid CV V2 aggregate recovery cancel digest")
	}
	return string(digest), nil
}

func cvAggregatePayloadResponseScalarCanonicalBytes(instanceDigest, payload []byte, maximumPayload int) ([]byte, error) {
	if len(instanceDigest) != 32 || len(payload) == 0 || maximumPayload <= 0 || len(payload) > maximumPayload {
		return nil, fmt.Errorf("invalid CV V2 aggregate payload response")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvAggregatePayloadResponseDomainScalar))
	_ = cvWriteBytes(&wire, instanceDigest)
	_ = cvWriteBytes(&wire, payload)
	return wire.Bytes(), nil
}

func cvDecodeAggregatePayloadResponseScalar(wire []byte, maximumPayload int) ([]byte, []byte, error) {
	if maximumPayload <= 0 {
		return nil, nil, fmt.Errorf("invalid CV V2 aggregate payload response limit")
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvAggregatePayloadResponseDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregatePayloadResponseDomainScalar)) {
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
	// The strict parser validates framing, bounds, and EOF without re-encoding.
	return instanceDigest, payload, nil
}

type cvServiceExperimentMetricsScalar struct {
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

type cvPendingCoinScalar struct {
	invocation []byte
	shares     map[int][]byte
	ready      chan struct{}
}

type cvNetworkPoolSlotScalar struct {
	state          cvPoolSlotStateScalar
	poolWire       []byte
	certWire       []byte
	localShare     []byte
	localShareWire []byte
	shares         map[int][]byte
	sharesReady    chan struct{}
	certReady      chan struct{}
	certifying     bool
}

type cvPendingValidationScalar struct {
	requestWire []byte
	request     *cvValidationRequestScalar
	statement   []byte
	signatures  map[int][]byte
	ready       chan struct{}
}

type cvValidationRecordScalar struct {
	requestWire []byte
	// request is immutable after canonical validation; it avoids decoding the
	// same request again when a validation result arrives.
	request    *cvValidationRequestScalar
	statement  []byte
	resultWire []byte
	// Set only after result authentication; awaiters reuse this immutable value.
	result      *cvValidationResultScalar
	resultReady chan struct{}
}

// cvValidationResultWireSeenScalar records only results that completed the full
// authentication path. It is used to discard exact retransmissions without
// allowing an unauthenticated wire to bypass validation.
type cvValidationResultWireSeenScalar struct {
	sender    int
	statement string
}

type cvCertifiedValidationScalar struct {
	request     *cvValidationRequestScalar
	certificate *cvValidationCertificateScalar
}

type cvPendingDecisionScalar struct {
	statement   []byte
	shares      map[int][]byte
	certificate []byte
	ready       chan struct{}
}

type cvPendingScalarSharesScalar struct {
	aggregate *cvAggregateScalar
	outputs   map[int]*cvScalarShareOutputScalar
	wires     map[int][]byte
	ready     chan struct{}
}

type cvVerifiedComponentScalar struct {
	ref        cvComponentRefScalar
	leafDigest []byte
	payload    []byte
	leaf       *cvLeafScalar
}

type cvVerifiedComponentCallScalar struct {
	ref  cvComponentRefScalar
	leaf *cvLeafScalar
	err  error
	done chan struct{}
}

type cvAPDBNetworkServiceScalar struct {
	ctx           context.Context
	cancel        context.CancelFunc
	cfg           cvAPDBNetworkServiceConfigScalar
	transport     agreementTransport
	auth          cvNetworkEnvelopeSealer
	holderStore   *cvAPDBHolderStoreScalar
	apdbSigner    *tblsThresholdSigner
	controlSigner *tblsThresholdSigner
	coinSigner    *tblsThresholdSigner
	inbox         <-chan Message

	mu                     sync.Mutex
	experimentMu           sync.Mutex
	verifiedCatalogMu      sync.Mutex
	pendingLocks           map[string]*cvAPDBPendingLockScalar
	pendingComponents      map[string]*cvAPDBPendingRecoveryScalar
	pendingAggregates      map[string]*cvAPDBPendingRecoveryScalar
	pendingCoins           map[string]*cvPendingCoinScalar
	localCoinShares        map[string][]byte
	coinShareReplies       map[string]map[int]struct{}
	coinShareReplyInFlight map[string]map[int]struct{}
	poolSlots              map[int]*cvNetworkPoolSlotScalar
	eligibleProposers      map[int]struct{}
	// Sorted eligibility snapshot reused by the candidate validation path.
	eligibleProposerSample              []int
	eligibilityValue                    []byte
	eligibilityCoin                     *cvCoinOutputScalar
	validatorSample                     []int
	agreementPublicContextCache         *cvAgreementPublicContextScalar
	pendingValidation                   map[string]*cvPendingValidationScalar
	validationRecords                   map[string]*cvValidationRecordScalar
	validationInFlight                  map[string]struct{}
	validationOneShot                   map[int][]byte
	validationLocalShares               map[string][]byte
	validationLocalShareWires           map[string][]byte
	validationRequestStatements         map[string]string
	validationResultWires               map[string]cvValidationResultWireSeenScalar
	validationSignatureWires            map[string]int
	certifiedValidation                 map[int]*cvCertifiedValidationScalar
	certifiedReady                      map[int]chan struct{}
	pendingDecisions                    map[string]*cvPendingDecisionScalar
	decisionLocalShares                 map[string][]byte
	decisionLocalShareWires             map[string][]byte
	decisionCertificates                map[string][]byte
	verifiedHandoffWire                 []byte
	acceptedHandoff                     []byte
	handoffReady                        chan struct{}
	localScalarOutputs                  map[string][]byte
	scalarAggregates                    map[string]*cvAggregateScalar
	pendingScalarShares                 map[string]*cvPendingScalarSharesScalar
	pendingLaneACKsScalar               *cvPendingLaneACKsScalar
	componentRefsScalar                 map[int]cvComponentRefScalar
	verifiedComponentsScalar            map[int]cvVerifiedComponentScalar
	verifiedComponentCalls              map[int]*cvVerifiedComponentCallScalar
	rejectedComponentsScalar            map[int]struct{}
	verifiedCatalogScalar               []cvComponentRefScalar
	verifiedCatalogPrewarm              bool
	localComponentRefScalar             []byte
	dealerPayloadsScalar                map[string][]byte
	dealerPayloadHintStates             map[string]*cvDealerPayloadHintStateScalar
	recoveryPrewarmScalar               bool
	recoveredPayloadsScalar             map[string]cvRecoveredPayloadEntryScalar
	recoveredPayloadCallsScalar         map[string]*cvRecoveredPayloadCallScalar
	aggregatePayloadsScalar             map[string]cvAggregatePayloadCacheEntryScalar
	aggregatePayloadResponsesScalar     map[string][]byte
	aggregatePayloadResponseCallsScalar map[string]*cvAggregatePayloadResponseCallScalar
	pendingAggregatePayloadScalar       map[string]*cvPendingAggregatePayloadPullScalar
	aggregateRecoveryCallsScalar        map[string]*cvAggregateRecoveryResponseCallScalar
	aggregateRecoveryActiveScalar       map[cvAggregateRecoveryRequestKeyScalar]bool
	componentRefUpdatesScalar           chan struct{}
	certifiedCandidatesScalar           map[string][]byte
	candidateACKWiresScalar             map[string][]byte
	candidateResponseWiresScalar        map[string][]byte
	candidateResponseCallsScalar        map[string]*cvCandidateResponseCallScalar
	candidateFanoutScalar               map[string]*cvCandidateFanoutStateScalar
	certifiedCandidateChScalar          chan *cvAgreementObjectScalar
	outbound                            chan cvOutboundMessageScalar
	priorityOutbound                    chan cvOutboundMessageScalar
	outboundWG                          sync.WaitGroup
	cryptoQueue                         chan cvCryptoJobScalar
	cryptoWG                            sync.WaitGroup
	recoveryQueue                       chan cvRecoveryJobScalar
	recoveryPriorityQueue               chan cvRecoveryJobScalar
	recoveryWG                          sync.WaitGroup
	recoveryRequestsInFlightScalar      map[string]struct{}
	componentRecoveryResponsesScalar    map[string][]byte
	componentRecoveryCallsScalar        map[string]*cvComponentRecoveryResponseCallScalar
	verifiedRecoveryLocksScalar         map[string]*cvAPDBLockScalar
	processingLaneOffersScalar          map[[2]int]struct{}
	processingCandidatesScalar          map[string]struct{}
	candidateDigestByProposerScalar     map[int]string
	candidateOriginsScalar              map[string]map[int]struct{}
	candidateFetchWaitersScalar         map[string]map[int]struct{}
	experimentMetrics                   cvServiceExperimentMetricsScalar
	done                                chan struct{}
}

func newCVAPDBNetworkServiceScalar(
	ctx context.Context, cfg cvAPDBNetworkServiceConfigScalar, transport agreementTransport, router *cvSAPVSSRouter,
	auth cvNetworkEnvelopeSealer, holderStore *cvAPDBHolderStoreScalar,
	apdbSigner, controlSigner, coinSigner *tblsThresholdSigner,
) (*cvAPDBNetworkServiceScalar, error) {
	if ctx == nil || cfg.SID == "" || cfg.Epoch == 0 || cfg.Epoch > uint64(^uint(0)>>1) || cfg.LocalNode < 0 ||
		transport == nil || router == nil || auth == nil || len(cfg.ExpectedContext) != 32 ||
		cfg.TotalShards != len(cfg.OldRoster) || cfg.DataShards <= 0 || cfg.DataShards > cfg.TotalShards ||
		cfg.ShardBytes < 0 || cfg.MaximumPayload <= 0 ||
		!equalInts(cfg.OldRoster, sortedUnique(cfg.OldRoster)) ||
		!equalInts(cfg.NewRoster, sortedUnique(cfg.NewRoster)) ||
		!cvScalarSignerHasRole(apdbSigner, cvScalarRoleAPDB) ||
		!cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) ||
		!cvScalarSignerHasRole(coinSigner, cvScalarRoleCoin) ||
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
		contextWire, contextErr := cvLeafContextScalarCanonicalBytes(cfg.LeafContext)
		contextDigest, digestErr := cvLeafContextDigestScalar(cfg.LeafContext)
		if contextErr != nil || len(contextWire) == 0 || cfg.LeafContext.SID != cfg.SID || cfg.LeafContext.Epoch != cfg.Epoch ||
			digestErr != nil || !bytes.Equal(contextDigest, cfg.ExpectedContext) ||
			cvValidateReceiverMaterialForLeafScalar(cfg.LeafContext, cfg.Receivers) != nil ||
			cvValidateValidatorMaterialForLeafScalar(cfg.LeafContext, cfg.Validators) != nil {
			return nil, fmt.Errorf("invalid CV V2 network validation material")
		}
	}
	isOld := cvMemberInRosterScalar(cfg.LocalNode, cfg.OldRoster)
	isNew := cvMemberInRosterScalar(cfg.LocalNode, cfg.NewRoster)
	if (!isOld && !isNew) || (isOld && holderStore == nil) {
		return nil, fmt.Errorf("invalid CV V2 APDB network service local role")
	}
	inbox, err := router.Receive(cfg.LocalNode)
	if err != nil {
		return nil, err
	}
	serviceContext, cancel := context.WithCancel(ctx)
	service := &cvAPDBNetworkServiceScalar{
		ctx: serviceContext, cancel: cancel, cfg: cfg, transport: transport, auth: auth,
		holderStore: holderStore, apdbSigner: apdbSigner, controlSigner: controlSigner, coinSigner: coinSigner, inbox: inbox,
		pendingLocks:                        make(map[string]*cvAPDBPendingLockScalar),
		pendingComponents:                   make(map[string]*cvAPDBPendingRecoveryScalar),
		pendingAggregates:                   make(map[string]*cvAPDBPendingRecoveryScalar),
		pendingCoins:                        make(map[string]*cvPendingCoinScalar),
		localCoinShares:                     make(map[string][]byte, 2),
		coinShareReplies:                    make(map[string]map[int]struct{}, 2),
		coinShareReplyInFlight:              make(map[string]map[int]struct{}, 2),
		poolSlots:                           make(map[int]*cvNetworkPoolSlotScalar, cfg.Params.proposerSampleSize),
		eligibleProposers:                   make(map[int]struct{}, cfg.Params.proposerSampleSize),
		pendingValidation:                   make(map[string]*cvPendingValidationScalar),
		validationRecords:                   make(map[string]*cvValidationRecordScalar),
		validationInFlight:                  make(map[string]struct{}),
		validationOneShot:                   make(map[int][]byte),
		validationLocalShares:               make(map[string][]byte),
		validationLocalShareWires:           make(map[string][]byte),
		validationRequestStatements:         make(map[string]string),
		validationResultWires:               make(map[string]cvValidationResultWireSeenScalar),
		validationSignatureWires:            make(map[string]int),
		certifiedValidation:                 make(map[int]*cvCertifiedValidationScalar),
		certifiedReady:                      make(map[int]chan struct{}),
		pendingDecisions:                    make(map[string]*cvPendingDecisionScalar),
		decisionLocalShares:                 make(map[string][]byte),
		decisionLocalShareWires:             make(map[string][]byte),
		decisionCertificates:                make(map[string][]byte),
		handoffReady:                        make(chan struct{}, 1),
		localScalarOutputs:                  make(map[string][]byte),
		scalarAggregates:                    make(map[string]*cvAggregateScalar),
		pendingScalarShares:                 make(map[string]*cvPendingScalarSharesScalar),
		componentRefsScalar:                 make(map[int]cvComponentRefScalar, cfg.Params.poolSize),
		verifiedComponentsScalar:            make(map[int]cvVerifiedComponentScalar, cfg.Params.poolSize),
		verifiedComponentCalls:              make(map[int]*cvVerifiedComponentCallScalar),
		rejectedComponentsScalar:            make(map[int]struct{}),
		aggregatePayloadsScalar:             make(map[string]cvAggregatePayloadCacheEntryScalar, cfg.Params.proposerSampleSize),
		aggregatePayloadResponsesScalar:     make(map[string][]byte, cvAggregatePayloadResponseCacheCapacityScalar),
		aggregatePayloadResponseCallsScalar: make(map[string]*cvAggregatePayloadResponseCallScalar),
		pendingAggregatePayloadScalar:       make(map[string]*cvPendingAggregatePayloadPullScalar),
		aggregateRecoveryCallsScalar:        make(map[string]*cvAggregateRecoveryResponseCallScalar),
		aggregateRecoveryActiveScalar:       make(map[cvAggregateRecoveryRequestKeyScalar]bool),
		componentRefUpdatesScalar:           make(chan struct{}, 1),
		certifiedCandidatesScalar:           make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateACKWiresScalar:             make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateResponseWiresScalar:        make(map[string][]byte, cfg.Params.proposerSampleSize),
		candidateResponseCallsScalar:        make(map[string]*cvCandidateResponseCallScalar),
		candidateFanoutScalar:               make(map[string]*cvCandidateFanoutStateScalar),
		certifiedCandidateChScalar:          make(chan *cvAgreementObjectScalar, cfg.Params.proposerSampleSize),
		outbound:                            make(chan cvOutboundMessageScalar, cvOutboundQueueCapacityScalar(len(cfg.OldRoster)+len(cfg.NewRoster))),
		priorityOutbound:                    make(chan cvOutboundMessageScalar, cvPriorityOutboundQueueCapacityScalar(len(cfg.OldRoster)+len(cfg.NewRoster))),
		cryptoQueue:                         make(chan cvCryptoJobScalar, cvCryptoQueueCapacityScalar(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryQueue:                       make(chan cvRecoveryJobScalar, cvRecoveryQueueCapacityScalar(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryPriorityQueue:               make(chan cvRecoveryJobScalar, cvRecoveryPriorityQueueCapacityScalar(len(cfg.OldRoster)+len(cfg.NewRoster))),
		recoveryRequestsInFlightScalar:      make(map[string]struct{}),
		componentRecoveryResponsesScalar:    make(map[string][]byte),
		componentRecoveryCallsScalar:        make(map[string]*cvComponentRecoveryResponseCallScalar),
		verifiedRecoveryLocksScalar:         make(map[string]*cvAPDBLockScalar, 256),
		processingLaneOffersScalar:          make(map[[2]int]struct{}, len(cfg.OldRoster)),
		processingCandidatesScalar:          make(map[string]struct{}, cfg.Params.proposerSampleSize),
		candidateDigestByProposerScalar:     make(map[int]string, cfg.Params.proposerSampleSize),
		candidateOriginsScalar:              make(map[string]map[int]struct{}, cfg.Params.proposerSampleSize),
		candidateFetchWaitersScalar:         make(map[string]map[int]struct{}, cfg.Params.proposerSampleSize),
		experimentMetrics: cvServiceExperimentMetricsScalar{
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
		go service.runCryptoWorkerScalar()
	}
	recoveryWorkers := cvRecoveryServiceWorkers(len(cfg.OldRoster) + len(cfg.NewRoster))
	service.recoveryWG.Add(recoveryWorkers)
	for range recoveryWorkers {
		go service.runRecoveryWorkerScalar()
	}
	go service.run()
	return service, nil
}

func cvOutboundQueueCapacityScalar(committeeSize int) int {
	capacity := committeeSize * 32
	if capacity < 128 {
		return 128
	}
	if capacity > 4096 {
		return 4096
	}
	return capacity
}

func cvPriorityOutboundQueueCapacityScalar(committeeSize int) int {
	capacity := committeeSize * 8
	if capacity < 64 {
		return 64
	}
	if capacity > 1024 {
		return 1024
	}
	return capacity
}

func cvCryptoQueueCapacityScalar(committeeSize int) int {
	capacity := committeeSize * 2
	if capacity < 64 {
		return 64
	}
	if capacity > 2048 {
		return 2048
	}
	return capacity
}

func cvRecoveryQueueCapacityScalar(committeeSize int) int {
	capacity := committeeSize * 4
	if capacity < 64 {
		capacity = 64
	}
	if capacity > 1024 {
		capacity = 1024
	}
	return capacity
}

func cvRecoveryPriorityQueueCapacityScalar(committeeSize int) int {
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

func (s *cvAPDBNetworkServiceScalar) runCryptoWorkerScalar() {
	defer s.cryptoWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.cryptoQueue:
			s.runCryptoJobScalar(job)
		}
	}
}

func (s *cvAPDBNetworkServiceScalar) runRecoveryWorkerScalar() {
	defer s.recoveryWG.Done()
	for {
		// Drain completed payload responses before ordinary recovery work so a
		// holder request cannot delay an already-returned shard.
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.recoveryPriorityQueue:
			started := time.Now()
			s.runRecoveryJobScalar(job)
			s.recordRecoveryWorkerMetricsScalar(job, started)
			continue
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.recoveryPriorityQueue:
			started := time.Now()
			s.runRecoveryJobScalar(job)
			s.recordRecoveryWorkerMetricsScalar(job, started)
		case job := <-s.recoveryQueue:
			started := time.Now()
			s.runRecoveryJobScalar(job)
			s.recordRecoveryWorkerMetricsScalar(job, started)
		}
	}
}

func (s *cvAPDBNetworkServiceScalar) recordRecoveryWorkerMetricsScalar(job cvRecoveryJobScalar, started time.Time) {
	s.experimentMu.Lock()
	s.experimentMetrics.recoveryJobs++
	s.experimentMetrics.recoveryWorkerLatency += time.Since(started)
	if !job.queuedAt.IsZero() {
		s.experimentMetrics.recoveryQueueWaitLatency += started.Sub(job.queuedAt)
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) enqueueRecoveryJobScalar(job cvRecoveryJobScalar) bool {
	if job.queuedAt.IsZero() {
		job.queuedAt = time.Now()
	}
	queue := s.recoveryQueue
	if job.kind == cvRecoveryPayloadResponseScalar {
		queue = s.recoveryPriorityQueue
	}
	select {
	case <-s.ctx.Done():
		return false
	case queue <- job:
		return true
	}
}

// claimRecoveryRequestScalar suppresses duplicate holder work while an identical
// request is already queued or being handled. The sender's normal retry path
// remains responsible for retransmission if the first response is lost.
func (s *cvAPDBNetworkServiceScalar) claimRecoveryRequestScalar(key string) bool {
	if s == nil || key == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recoveryRequestsInFlightScalar == nil {
		s.recoveryRequestsInFlightScalar = make(map[string]struct{})
	}
	if _, exists := s.recoveryRequestsInFlightScalar[key]; exists {
		return false
	}
	s.recoveryRequestsInFlightScalar[key] = struct{}{}
	return true
}

func (s *cvAPDBNetworkServiceScalar) releaseRecoveryRequestScalar(key string) {
	if s == nil || key == "" {
		return
	}
	s.mu.Lock()
	delete(s.recoveryRequestsInFlightScalar, key)
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) cachedComponentRecoveryResponseScalar(key string) []byte {
	if s == nil || key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Entries are immutable after insertion. sendAsync copies at the queue
	// boundary, so returning the cached slice avoids a redundant full-response
	// allocation on every cache hit.
	return s.componentRecoveryResponsesScalar[key]
}

func (s *cvAPDBNetworkServiceScalar) recordComponentRecoveryCacheScalar(hit bool) {
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

func (s *cvAPDBNetworkServiceScalar) cacheComponentRecoveryResponseScalar(key string, response []byte) {
	if s == nil || key == "" || len(response) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.componentRecoveryResponsesScalar == nil {
		s.componentRecoveryResponsesScalar = make(map[string][]byte)
	}
	if _, exists := s.componentRecoveryResponsesScalar[key]; exists {
		return
	}
	if len(s.componentRecoveryResponsesScalar) >= cvComponentRecoveryResponseCacheCapacityScalar {
		return
	}
	s.componentRecoveryResponsesScalar[key] = append([]byte(nil), response...)
}

func (s *cvAPDBNetworkServiceScalar) runRecoveryJobScalar(job cvRecoveryJobScalar) {
	if job.kind == cvRecoveryDealerRequestScalar {
		defer s.releaseRecoveryRequestScalar(job.dedupeKey)
	}
	switch job.kind {
	case cvRecoveryPrepareDealerScalar:
		payload := job.payload
		if len(payload) == 0 {
			payload, _ = s.dealerPayloadScalar(job.instanceDigest)
		}
		if len(job.instanceDigest) == 32 && len(payload) > 0 {
			_ = s.dealerPayloadResponseScalar(job.instanceDigest, payload)
		}
	case cvRecoveryDealerRequestScalar:
		if cached := s.cachedComponentRecoveryResponseScalar(job.responseCacheKey); len(cached) > 0 {
			s.recordComponentRecoveryCacheScalar(true)
			_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreScalar, cached, func(err error) {
				if err == nil {
					s.recordComponentRecoveryResponseSentScalar(0, 0, len(cached))
				}
			})
			return
		}
		s.recordComponentRecoveryCacheScalar(false)
		var lock *cvAPDBLockScalar
		s.mu.Lock()
		lock = s.verifiedRecoveryLocksScalar[job.responseCacheKey]
		s.mu.Unlock()
		if lock == nil {
			var err error
			lock, err = cvDecodeAPDBLockScalar(job.msg.Body)
			if err != nil || cvVerifyAPDBLockScalar(lock, s.apdbSigner) != nil {
				return
			}
			s.mu.Lock()
			if len(s.verifiedRecoveryLocksScalar) < 256 {
				s.verifiedRecoveryLocksScalar[job.responseCacheKey] = lock
			}
			s.mu.Unlock()
		}
		if payload, ok := s.dealerPayloadScalar(lock.InstanceDigest); ok {
			if cvComponentDealerResponseModeScalar() == cvComponentDealerResponseDropScalar {
				return
			}
			if response := s.dealerPayloadResponseScalar(lock.InstanceDigest, payload); len(response) > 0 {
				hintsBytes := s.dealerPayloadHintBytesScalar(lock.InstanceDigest)
				_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverPayloadScalar, response, func(err error) {
					if err == nil {
						s.recordComponentRecoveryResponseSentScalar(len(payload), hintsBytes, 0)
					}
				})
				return
			}
		}
		var response []byte
		var responseErr error
		var call *cvComponentRecoveryResponseCallScalar
		s.mu.Lock()
		call = s.componentRecoveryCallsScalar[job.responseCacheKey]
		if call == nil && len(s.componentRecoveryCallsScalar) < cvComponentRecoveryResponseCacheCapacityScalar {
			call = &cvComponentRecoveryResponseCallScalar{ready: make(chan struct{})}
			s.componentRecoveryCallsScalar[job.responseCacheKey] = call
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
				_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreScalar, response, func(err error) {
					if err == nil {
						s.recordComponentRecoveryResponseSentScalar(0, 0, len(response))
					}
				})
			}
			return
		}
		s.mu.Unlock()
		response, responseErr = cvHandleAPDBRecoveryLockScalar(s.cfg.SID, s.cfg.Epoch, job.msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, lock, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore)
		if responseErr == nil {
			s.cacheComponentRecoveryResponseScalar(job.responseCacheKey, response)
		}
		if call != nil {
			s.mu.Lock()
			call.response, call.err = response, responseErr
			delete(s.componentRecoveryCallsScalar, job.responseCacheKey)
			close(call.ready)
			s.mu.Unlock()
		}
		if responseErr == nil {
			_ = s.sendAsync(job.msg.From, cvTagAPDBRecoverStoreScalar, response, func(err error) {
				if err == nil {
					s.recordComponentRecoveryResponseSentScalar(0, 0, len(response))
				}
			})
		}
	case cvRecoveryPayloadResponseScalar:
		started := time.Now()
		response, err := cvDecodeAPDBPayloadResponseScalar(job.msg.Body, s.cfg.MaximumPayload)
		if err != nil {
			return
		}
		pending := s.lookupRecovery(string(response.InstanceDigest), false)
		if pending == nil {
			s.recordComponentRecoveryLateRecvBytesScalar(job.msg.WireBytes)
			return
		}
		if pending.collector.complete() {
			s.recordComponentRecoveryLateRecvBytesScalar(job.msg.WireBytes)
			return
		}
		s.recordRecoveryBytesScalar(pending.purpose, false, job.msg.WireBytes)
		if complete, addErr := pending.collector.addDecodedPayloadOwned(response); addErr == nil && complete {
			cvNotifyAPDBScalar(pending.ready)
		}
		s.experimentMu.Lock()
		s.experimentMetrics.receiverPayloadDecodeLatency += time.Since(started)
		s.experimentMu.Unlock()
	case cvRecoveryAggregateRequestScalar:
		digest := job.requestDigest
		if digest == "" {
			digest = string(hashBytes(job.msg.Body))
		}
		requestKey := cvAggregateRecoveryRequestKeyScalar{receiver: job.msg.From, digest: digest}
		if s.aggregateRecoveryRequestCanceledScalar(requestKey) {
			s.finishAggregateRecoveryRequestScalar(requestKey)
			return
		}
		started := time.Now()
		response, err := s.aggregateRecoveryResponseDigestScalar(job.msg.From, job.msg.Body, digest)
		s.recordAggregateRecoveryResponseScalar(time.Since(started))
		if err != nil || s.aggregateRecoveryRequestCanceledScalar(requestKey) {
			s.finishAggregateRecoveryRequestScalar(requestKey)
			return
		}
		err = s.sendAsyncConditionalScalar(job.msg.From, cvTagAggregateRecoverStoreScalar, response,
			func() bool { return !s.aggregateRecoveryRequestCanceledScalar(requestKey) },
			func(error) { s.finishAggregateRecoveryRequestScalar(requestKey) })
		if err != nil {
			s.finishAggregateRecoveryRequestScalar(requestKey)
		}
	case cvRecoveryAggregatePayloadRequestScalar:
		s.handleAggregatePayloadPullRequestScalar(job.msg)
	}
}

func (s *cvAPDBNetworkServiceScalar) registerAggregateRecoveryRequestScalar(key cvAggregateRecoveryRequestKeyScalar) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.aggregateRecoveryActiveScalar[key]; exists {
		return false
	}
	s.aggregateRecoveryActiveScalar[key] = false
	return true
}

func (s *cvAPDBNetworkServiceScalar) cancelAggregateRecoveryRequestScalar(key cvAggregateRecoveryRequestKeyScalar) {
	s.mu.Lock()
	if _, active := s.aggregateRecoveryActiveScalar[key]; active {
		s.aggregateRecoveryActiveScalar[key] = true
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) aggregateRecoveryRequestCanceledScalar(key cvAggregateRecoveryRequestKeyScalar) bool {
	s.mu.Lock()
	canceled := s.aggregateRecoveryActiveScalar[key]
	s.mu.Unlock()
	return canceled
}

func (s *cvAPDBNetworkServiceScalar) finishAggregateRecoveryRequestScalar(key cvAggregateRecoveryRequestKeyScalar) {
	s.mu.Lock()
	delete(s.aggregateRecoveryActiveScalar, key)
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) aggregateRecoveryResponseDigestScalar(
	receiver int, request []byte, digest string,
) ([]byte, error) {
	if s == nil || !cvMemberInRosterScalar(receiver, s.cfg.NewRoster) || s.holderStore == nil {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request")
	}
	if digest == "" {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery request digest")
	}
	key := digest

	s.mu.Lock()
	if call := s.aggregateRecoveryCallsScalar[key]; call != nil {
		s.mu.Unlock()
		s.recordAggregateRecoveryCacheScalar(true)
		select {
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-call.ready:
			return call.response, call.err
		}
	}
	if len(s.aggregateRecoveryCallsScalar) >= cvAggregateRecoveryResponseCacheCapacityScalar {
		s.mu.Unlock()
		s.recordAggregateRecoveryCacheScalar(false)
		return cvHandleAggregateRecoveryRequestScalar(s.cfg.SID, s.cfg.Epoch, receiver, s.cfg.LocalNode,
			s.cfg.OldRoster, s.cfg.NewRoster, request, s.cfg.ExpectedContext, s.cfg.TotalShards,
			s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
	}
	call := &cvAggregateRecoveryResponseCallScalar{ready: make(chan struct{})}
	s.aggregateRecoveryCallsScalar[key] = call
	s.mu.Unlock()
	s.recordAggregateRecoveryCacheScalar(false)

	response, err := cvHandleAggregateRecoveryRequestScalar(s.cfg.SID, s.cfg.Epoch, receiver, s.cfg.LocalNode,
		s.cfg.OldRoster, s.cfg.NewRoster, request, s.cfg.ExpectedContext, s.cfg.TotalShards,
		s.cfg.ShardBytes, s.holderStore, s.apdbSigner, s.controlSigner)
	s.mu.Lock()
	call.response, call.err = response, err
	if err != nil {
		delete(s.aggregateRecoveryCallsScalar, key)
	}
	close(call.ready)
	s.mu.Unlock()
	return response, err
}

func (s *cvAPDBNetworkServiceScalar) recordAggregateRecoveryCacheScalar(hit bool) {
	s.experimentMu.Lock()
	if hit {
		s.experimentMetrics.aggregateRecoveryCacheHits++
	} else {
		s.experimentMetrics.aggregateRecoveryCacheMisses++
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordAggregateRecoveryResponseScalar(elapsed time.Duration) {
	s.experimentMu.Lock()
	s.experimentMetrics.aggregateRecoveryResponseLatency += elapsed
	s.experimentMetrics.aggregateRecoveryResponseRequests++
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) rememberVerifiedAggregatePayloadScalar(instanceDigest, root, payload []byte) error {
	if s == nil || len(instanceDigest) != 32 || len(root) != 32 || len(payload) == 0 || len(payload) > s.cfg.MaximumPayload {
		return fmt.Errorf("invalid verified CV V2 aggregate payload cache entry")
	}
	key := string(instanceDigest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.aggregatePayloadsScalar[key]; ok {
		if !bytes.Equal(existing.root, root) || !bytes.Equal(existing.payload, payload) {
			return fmt.Errorf("conflicting verified CV V2 aggregate payload cache entry")
		}
		return nil
	}
	if len(s.aggregatePayloadsScalar) >= cvAggregateRecoveryResponseCacheCapacityScalar {
		return fmt.Errorf("verified CV V2 aggregate payload cache is full")
	}
	s.aggregatePayloadsScalar[key] = cvAggregatePayloadCacheEntryScalar{
		root: append([]byte(nil), root...), payload: append([]byte(nil), payload...),
	}
	return nil
}

func (s *cvAPDBNetworkServiceScalar) cachedAggregatePayloadScalar(handoff *cvHandoffScalar) ([]byte, bool) {
	if s == nil || handoff == nil || len(handoff.Header.APDBInstance) != 32 || len(handoff.ARC.Root) != 32 {
		return nil, false
	}
	s.mu.Lock()
	entry, ok := s.aggregatePayloadsScalar[string(handoff.Header.APDBInstance)]
	s.mu.Unlock()
	if !ok || !bytes.Equal(entry.root, handoff.ARC.Root) {
		return nil, false
	}
	digest, err := cvAggregatePayloadDigestScalar(entry.payload)
	if err != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
		return nil, false
	}
	return append([]byte(nil), entry.payload...), true
}

func cvAggregatePayloadPullEnabledScalar() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_AGGREGATE_PAYLOAD_PULL"))) {
	case "0", "false", "off", "disabled":
		return false
	default:
		return true
	}
}

func (s *cvAPDBNetworkServiceScalar) aggregatePayloadPullProvidersScalar(handoff *cvHandoffScalar) []int {
	if s == nil || handoff == nil {
		return nil
	}
	s.mu.Lock()
	providers := append([]int{handoff.Header.ProposerID}, s.validatorSample...)
	s.mu.Unlock()
	providers = sortedUnique(providers)
	filtered := providers[:0]
	for _, provider := range providers {
		if cvMemberInRosterScalar(provider, s.cfg.OldRoster) {
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

func (s *cvAPDBNetworkServiceScalar) validatePulledAggregatePayloadScalar(
	handoff *cvHandoffScalar, payload []byte, bindingCheck func([]byte) error,
) error {
	if s == nil || handoff == nil || len(payload) == 0 {
		return fmt.Errorf("invalid pulled CV V2 aggregate payload")
	}
	digest, err := cvAggregatePayloadDigestScalar(payload)
	if err != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
		return fmt.Errorf("pulled CV V2 aggregate payload digest mismatch")
	}
	encoded, err := cvAPDBEncodeSizedScalar(
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

func (s *cvAPDBNetworkServiceScalar) tryAggregatePayloadPullScalar(
	ctx context.Context, handoff *cvHandoffScalar, requestWire []byte, bindingCheck func([]byte) error,
) ([]byte, bool, error) {
	if !cvAggregatePayloadPullEnabledScalar() {
		return nil, false, nil
	}
	if payload, ok := s.cachedAggregatePayloadScalar(handoff); ok {
		if err := s.validatePulledAggregatePayloadScalar(handoff, payload, bindingCheck); err == nil {
			return payload, true, nil
		}
	}
	providers := s.aggregatePayloadPullProvidersScalar(handoff)
	if len(providers) == 0 {
		return nil, false, nil
	}
	provider := providers[0]
	pending := &cvPendingAggregatePayloadPullScalar{
		allowed: provider, responses: make(chan cvAggregatePayloadPullResponseScalar, 1),
	}
	key := string(handoff.ARC.InstanceDigest)
	s.mu.Lock()
	if s.pendingAggregatePayloadScalar[key] != nil {
		s.mu.Unlock()
		return nil, false, fmt.Errorf("CV V2 aggregate payload pull already active")
	}
	s.pendingAggregatePayloadScalar[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingAggregatePayloadScalar[key] == pending {
			delete(s.pendingAggregatePayloadScalar, key)
		}
		s.mu.Unlock()
	}()
	wireBytes, err := s.sendMeasured(provider, cvTagAggregatePayloadGetScalar, requestWire)
	if err != nil {
		return nil, false, nil
	}
	s.recordRecoveryBytesScalar(cvRecoveryNewAggregateScalar, true, wireBytes)
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
		s.recordRecoveryBytesScalar(cvRecoveryNewAggregateScalar, false, response.wireBytes)
		if err := s.validatePulledAggregatePayloadScalar(handoff, response.payload, bindingCheck); err != nil {
			return nil, false, nil
		}
		return response.payload, true, nil
	}
}

func (s *cvAPDBNetworkServiceScalar) handleAggregatePayloadPullRequestScalar(msg Message) {
	if s == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) ||
		!cvMemberInRosterScalar(msg.From, s.cfg.NewRoster) {
		return
	}
	handoff, err := cvAuthorizeAggregateRecoveryRequestScalar(
		msg.Body, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner,
	)
	if err != nil {
		return
	}
	payload, ok := s.cachedAggregatePayloadScalar(handoff)
	if !ok {
		return
	}
	key := string(handoff.ARC.InstanceDigest)
	s.mu.Lock()
	response := s.aggregatePayloadResponsesScalar[key]
	call := s.aggregatePayloadResponseCallsScalar[key]
	creator := false
	if len(response) == 0 && call == nil && len(s.aggregatePayloadResponseCallsScalar) < cvAggregatePayloadResponseCacheCapacityScalar {
		call = &cvAggregatePayloadResponseCallScalar{ready: make(chan struct{})}
		if s.aggregatePayloadResponseCallsScalar == nil {
			s.aggregatePayloadResponseCallsScalar = make(map[string]*cvAggregatePayloadResponseCallScalar)
		}
		s.aggregatePayloadResponseCallsScalar[key] = call
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
		response, encodeErr = cvAggregatePayloadResponseScalarCanonicalBytes(
			handoff.ARC.InstanceDigest, payload, s.cfg.MaximumPayload,
		)
		if encodeErr != nil {
			if call != nil {
				s.mu.Lock()
				call.err = encodeErr
				delete(s.aggregatePayloadResponseCallsScalar, key)
				close(call.ready)
				s.mu.Unlock()
			}
			return
		}
		s.mu.Lock()
		if s.aggregatePayloadResponsesScalar == nil {
			s.aggregatePayloadResponsesScalar = make(map[string][]byte)
		}
		if len(s.aggregatePayloadResponsesScalar) < cvAggregatePayloadResponseCacheCapacityScalar {
			s.aggregatePayloadResponsesScalar[key] = append([]byte(nil), response...)
		}
		if call != nil {
			call.response = response
			delete(s.aggregatePayloadResponseCallsScalar, key)
			close(call.ready)
		}
		s.mu.Unlock()
	}
	_ = s.sendAsyncMeasuredScalar(msg.From, cvTagAggregatePayloadScalar, response, func(wireBytes int, sendErr error) {
		if sendErr == nil {
			s.recordRecoveryBytesScalar(cvRecoveryNewAggregateScalar, true, wireBytes)
		}
	})
}

func (s *cvAPDBNetworkServiceScalar) handleAggregatePayloadPullResponseScalar(msg Message) {
	instanceDigest, payload, err := cvDecodeAggregatePayloadResponseScalar(msg.Body, s.cfg.MaximumPayload)
	if err != nil {
		return
	}
	s.mu.Lock()
	pending := s.pendingAggregatePayloadScalar[string(instanceDigest)]
	s.mu.Unlock()
	if pending == nil || pending.allowed != msg.From {
		return
	}
	response := cvAggregatePayloadPullResponseScalar{
		from: msg.From, payload: append([]byte(nil), payload...), wireBytes: msg.WireBytes,
	}
	select {
	case pending.responses <- response:
	default:
	}
}

func (s *cvAPDBNetworkServiceScalar) runCryptoJobScalar(job cvCryptoJobScalar) {
	switch job.kind {
	case cvCryptoJobLaneOfferScalar:
		key := [2]int{job.msg.From, job.msg.To}
		defer func() {
			s.mu.Lock()
			delete(s.processingLaneOffersScalar, key)
			s.mu.Unlock()
		}()
		s.handleLaneOfferScalar(job.msg)
	case cvCryptoJobCertifiedCandidateScalar:
		digest := job.digest
		if digest == "" {
			digest = cvCertifiedCandidateDigestScalar(job.msg.Body)
		}
		defer func() {
			s.mu.Lock()
			delete(s.processingCandidatesScalar, digest)
			s.mu.Unlock()
		}()
		s.processCertifiedCandidateDigestScalar(job.msg, digest)
	}
}

func (s *cvAPDBNetworkServiceScalar) enqueueLaneOfferScalar(msg Message) {
	key := [2]int{msg.From, msg.To}
	s.mu.Lock()
	if _, duplicate := s.processingLaneOffersScalar[key]; duplicate {
		s.mu.Unlock()
		return
	}
	s.processingLaneOffersScalar[key] = struct{}{}
	s.mu.Unlock()
	select {
	case s.cryptoQueue <- cvCryptoJobScalar{kind: cvCryptoJobLaneOfferScalar, msg: msg}:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingLaneOffersScalar, key)
		s.mu.Unlock()
	}
}

func (s *cvAPDBNetworkServiceScalar) runOutbound() {
	defer s.outboundWG.Done()
	for {
		// Drain control replies first. Candidate ACKs are intentionally kept
		// separate from bulk recovery/candidate traffic so delivery confirmation
		// cannot be delayed behind large payload writes.
		select {
		case message := <-s.priorityOutbound:
			s.runOutboundMessageScalar(message)
			continue
		default:
		}
		select {
		case <-s.ctx.Done():
			return
		case message := <-s.priorityOutbound:
			s.runOutboundMessageScalar(message)
		case message := <-s.outbound:
			s.runOutboundMessageScalar(message)
		}
	}
}

func (s *cvAPDBNetworkServiceScalar) runOutboundMessageScalar(message cvOutboundMessageScalar) {
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
func (s *cvAPDBNetworkServiceScalar) sendAsync(to int, tag string, payload []byte, onResult func(error)) error {
	return s.sendAsyncConditionalScalar(to, tag, payload, nil, onResult)
}

func (s *cvAPDBNetworkServiceScalar) sendAsyncMeasuredScalar(
	to int, tag string, payload []byte, onMeasured func(int, error),
) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid measured asynchronous CV V2 send")
	}
	message := cvOutboundMessageScalar{
		to: to, tag: tag, payload: append([]byte(nil), payload...), onMeasured: onMeasured,
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.outbound <- message:
		return nil
	}
}

func (s *cvAPDBNetworkServiceScalar) sendAsyncConditionalScalar(
	to int, tag string, payload []byte, shouldSend func() bool, onResult func(error),
) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid asynchronous CV V2 send")
	}
	message := cvOutboundMessageScalar{
		to: to, tag: tag, payload: append([]byte(nil), payload...), shouldSend: shouldSend, onResult: onResult,
	}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.outbound <- message:
		return nil
	}
}

func (s *cvAPDBNetworkServiceScalar) sendPriorityAsync(to int, tag string, payload []byte, onResult func(error)) error {
	if s == nil || s.ctx == nil || tag == "" || len(payload) == 0 {
		return fmt.Errorf("invalid priority asynchronous CV V2 send")
	}
	message := cvOutboundMessageScalar{to: to, tag: tag, payload: append([]byte(nil), payload...), onResult: onResult}
	select {
	case <-s.ctx.Done():
		return s.ctx.Err()
	case s.priorityOutbound <- message:
		return nil
	}
}

func cvControlRetryDelayScalar(attempt int) time.Duration {
	delay := cvControlRetryIntervalScalar
	for i := 0; i < attempt && delay < 2*time.Second; i++ {
		delay *= 2
	}
	if delay > 2*time.Second {
		return 2 * time.Second
	}
	return delay
}

// cvDecisionRetryBudgetScalar bounds how long decision finalization keeps
// requesting missing shares; the same knob widens the post-success linger so
// a decided node keeps answering decision-share requests for stragglers.
func cvDecisionRetryBudgetScalar() time.Duration {
	budget := arlDurationFromEnv("RLADKR_DECISION_RETRY_BUDGET_MS", 30*time.Second)
	if budget < 5*time.Second {
		return 5 * time.Second
	}
	if budget > 120*time.Second {
		return 120 * time.Second
	}
	return budget
}

// cvDecisionResponderGraceScalar optionally extends the success-path linger so
// decision-share responders outlive slow finalizers. Zero (default) keeps
// the recover-shard grace as the only linger window.
func cvDecisionResponderGraceScalar() time.Duration {
	grace := arlDurationFromEnv("RLADKR_DECISION_RESPONDER_GRACE_MS", 0)
	if grace > 120*time.Second {
		return 120 * time.Second
	}
	return grace
}

func (s *cvAPDBNetworkServiceScalar) EligibilityCoin(ctx context.Context) (*cvCoinOutputScalar, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	invocation, err := cvEligibilityCoinInvocationScalar(s.cfg.SID, s.cfg.Epoch)
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

func (s *cvAPDBNetworkServiceScalar) ContributorCoin(
	ctx context.Context, pool *cvPoolScalar, certificate *cvPoolCertificateScalar,
) (*cvCoinOutputScalar, error) {
	if s == nil {
		return nil, fmt.Errorf("nil CV V2 network service")
	}
	if _, err := s.validatePool(pool); err != nil {
		return nil, err
	}
	if err := cvVerifyPoolCertificateScalar(pool, certificate, s.controlSigner); err != nil {
		return nil, fmt.Errorf("CV V2 contributor coin requires PoolCert: %w", err)
	}
	invocation, err := cvContributorCoinInvocationScalar(pool.ContextDigest, pool.ProposerID, pool.Digest)
	if err != nil {
		return nil, err
	}
	return s.runCoin(ctx, invocation)
}

func (s *cvAPDBNetworkServiceScalar) setEligibilityCoin(output *cvCoinOutputScalar) error {
	invocation, err := cvEligibilityCoinInvocationScalar(s.cfg.SID, s.cfg.Epoch)
	if err != nil || cvVerifyCoinOutputScalar(output, invocation, s.coinSigner) != nil {
		return fmt.Errorf("invalid CV V2 network eligibility coin")
	}
	proposers, validators, err := cvDeriveEligibilitySamplesScalar(
		s.cfg.OldRoster, output.Value, s.cfg.Params.proposerSampleSize, s.cfg.Params.validatorSampleSize,
	)
	if err != nil {
		return err
	}
	coinWire, err := cvCoinOutputScalarCanonicalBytes(output)
	if err != nil {
		return err
	}
	coin, err := cvDecodeCoinOutputScalar(coinWire)
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
	validatorPrewarmMode := cvValidatorPrewarmModeFromEnvScalar(len(s.cfg.OldRoster))
	if proposerEligible && !s.verifiedCatalogPrewarm {
		s.verifiedCatalogPrewarm = true
		prewarmCatalog = true
	}
	if validatorSampled && !proposerEligible && !s.recoveryPrewarmScalar {
		switch validatorPrewarmMode {
		case cvValidatorPrewarmRecoverScalar:
			s.recoveryPrewarmScalar = true
			prewarmRecovery = true
		case cvValidatorPrewarmFullScalar:
			if !s.verifiedCatalogPrewarm {
				s.verifiedCatalogPrewarm = true
				prewarmCatalog = true
			}
		}
	}
	s.mu.Unlock()
	if prewarmCatalog {
		go func() { _, _ = s.AwaitVerifiedComponentCatalogScalar(s.ctx) }()
	}
	if prewarmRecovery {
		go s.prewarmComponentRecoveryScalar()
	}
	return nil
}

func (s *cvAPDBNetworkServiceScalar) CertifyPool(ctx context.Context, pool *cvPoolScalar) (*cvPoolCertificateScalar, error) {
	if s == nil || ctx == nil || pool == nil || pool.ProposerID != s.cfg.LocalNode {
		return nil, fmt.Errorf("invalid CV V2 pool certification caller")
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return nil, err
	}
	statement, err := cvPoolCertificateStatementScalar(pool.ContextDigest, pool.ProposerID, pool.Digest)
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
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertScalarDomain, statement)
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
		cvNotifyAPDBScalar(slot.sharesReady)
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
	_ = s.sendFanoutMeasuredScalar(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolOfferScalar, poolWire)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsScalar; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-slot.sharesReady:
			goto recoverCertificate
		case <-time.After(cvControlRetryDelayScalar(attempt)):
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
		_ = s.sendFanoutMeasuredScalar(missing, -1, cvTagPoolOfferScalar, poolWire)
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
	recovered, err := s.controlSigner.Recover(cvPoolCertScalarDomain, statement, shares)
	if err != nil {
		return nil, err
	}
	certificate := &cvPoolCertificateScalar{PoolDigest: append([]byte(nil), pool.Digest...), Certificate: recovered}
	if err := cvVerifyPoolCertificateScalar(pool, certificate, s.controlSigner); err != nil {
		return nil, err
	}
	certWire, err := cvPoolCertificateScalarCanonicalBytes(certificate)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if err := slot.state.observeCertificate(certificate); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	slot.certWire = append([]byte(nil), certWire...)
	cvNotifyAPDBScalar(slot.certReady)
	s.mu.Unlock()
	_ = s.sendFanoutMeasuredScalar(s.cfg.OldRoster, s.cfg.LocalNode, cvTagPoolCertScalar, certWire)
	return certificate, nil
}

func (s *cvAPDBNetworkServiceScalar) AwaitCertifiedPool(ctx context.Context, proposer int) (*cvPoolScalar, *cvPoolCertificateScalar, error) {
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
	pool, err := cvDecodePoolScalar(poolWire, s.cfg.Params)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := cvDecodePoolCertificateScalar(certWire)
	if err != nil || cvVerifyPoolCertificateScalar(pool, certificate, s.controlSigner) != nil {
		return nil, nil, fmt.Errorf("invalid CV V2 certified pool state")
	}
	return pool, certificate, nil
}

func (s *cvAPDBNetworkServiceScalar) CertifyAggregate(
	ctx context.Context, request *cvValidationRequestScalar,
) (*cvValidationCertificateScalar, error) {
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
	if err := s.validateKnownComponentRefsScalar(request.Pool.Components); err != nil {
		return nil, err
	}
	requestWire, canonicalLatency, err := cvValidateValidationRequestPublicAfterComponentValidationScalar(
		request, s.cfg.ExpectedContext, s.cfg.Params, eligible,
		s.apdbSigner, s.controlSigner, s.coinSigner,
	)
	if err != nil {
		return nil, err
	}
	statement, err := cvValidationStatementScalar(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingValidationScalar{requestWire: append([]byte(nil), requestWire...), request: request,
		statement: statement, signatures: make(map[int][]byte), ready: make(chan struct{}, 1)}
	s.mu.Lock()
	if _, exists := s.pendingValidation[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV V2 aggregate certification already active")
	}
	s.pendingValidation[key] = pending
	record := s.validationRecords[key]
	if record == nil {
		record = &cvValidationRecordScalar{requestWire: append([]byte(nil), requestWire...), request: request, statement: append([]byte(nil), statement...), resultReady: make(chan struct{}, 1)}
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

	firstWave, deferredWave := cvValidationRequestWavesScalar(
		validatorSample, s.cfg.Params.validatorThreshold, request.Header.ProposerID,
	)
	if len(firstWave) < s.cfg.Params.validatorThreshold {
		return nil, fmt.Errorf("invalid CV V2 validation request wave")
	}
	networkStarted := time.Now()
	firstWaveComplete, err := cvSendValidationRequestWavesScalar(
		ctx, s.ctx, pending.ready, firstWave, deferredWave, cvValidationFirstWaveGraceScalar(),
		func(recipients []int) {
			_ = s.sendFanoutMeasuredScalar(recipients, -1, cvTagValidationRequestScalar, requestWire)
		},
	)
	if err != nil {
		return nil, err
	}
	if firstWaveComplete {
		goto buildCertificate
	}
	for attempt := 0; attempt < cvControlRetryMaxAttemptsScalar; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto buildCertificate
		case <-time.After(cvControlRetryDelayScalar(attempt)):
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
			_ = s.sendFanoutMeasuredScalar(missing, -1, cvTagValidationRequestScalar, requestWire)
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
	certificate, buildTimings, err := cvBuildValidationCertificateModeScalar(
		&request.Header, validatorSample, s.cfg.Params.validatorThreshold, signatures, s.cfg.Validators, false,
	)
	s.recordCertificateFormationScalar(cvCertificateValidationScalar, time.Since(formationStarted))
	s.recordValidationProfileScalar(
		canonicalLatency, networkWaitLatency, 0, buildTimings.AggregateVerify,
	)
	if err != nil {
		return nil, err
	}
	resultWire, err := cvValidationResultScalarCanonicalBytes(
		&cvValidationResultScalar{Statement: statement, Certificate: *certificate}, validatorSample,
	)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), resultWire...)
	cvNotifyAPDBScalar(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationScalar{request: request, certificate: certificate}
	cvNotifyAPDBScalar(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
	if err := s.publishValidationResultScalar(resultWire); err != nil {
		return nil, err
	}
	return certificate, nil
}

func (s *cvAPDBNetworkServiceScalar) publishValidationResultScalar(resultWire []byte) error {
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
		if err := s.sendPriorityAsync(member, cvTagValidationResultScalar, resultWire, nil); err != nil {
			return err
		}
	}
	return nil
}

func cvValidationFirstWaveGraceScalar() time.Duration {
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
	return cvValidationFirstWaveExtraScalar
}

func CVValidationFirstWaveGrace() time.Duration {
	return cvValidationFirstWaveGraceScalar()
}

func cvValidationRequestWavesScalar(
	validatorSample []int, threshold, proposer int,
) ([]int, []int) {
	if threshold <= 0 || threshold > len(validatorSample) || proposer < 0 ||
		len(sortedUnique(validatorSample)) != len(validatorSample) {
		return nil, nil
	}
	ordered := cvRotatedAggregateRecoveryFirstWaveScalar(validatorSample, len(validatorSample), proposer)
	firstCount := threshold + cvValidationFirstWaveExtraScalar
	if firstCount > len(ordered) {
		firstCount = len(ordered)
	}
	return append([]int(nil), ordered[:firstCount]...), append([]int(nil), ordered[firstCount:]...)
}

func cvSendValidationRequestWavesScalar(
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

func (s *cvAPDBNetworkServiceScalar) AwaitCertifiedValidationScalar(
	ctx context.Context, proposer int,
) (*cvValidationRequestScalar, *cvValidationCertificateScalar, error) {
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

func (s *cvAPDBNetworkServiceScalar) certifiedReadyLocked(proposer int) chan struct{} {
	ready := s.certifiedReady[proposer]
	if ready == nil {
		ready = make(chan struct{}, 1)
		s.certifiedReady[proposer] = ready
	}
	return ready
}

func (s *cvAPDBNetworkServiceScalar) AwaitValidationResult(
	ctx context.Context, request *cvValidationRequestScalar,
) (*cvValidationCertificateScalar, error) {
	if s == nil || ctx == nil || request == nil {
		return nil, fmt.Errorf("invalid CV V2 validation-result wait")
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	s.mu.Unlock()
	statement, err := cvValidationStatementScalar(validatorSample, &request.Header)
	if err != nil {
		return nil, err
	}
	key := string(statement)
	s.mu.Lock()
	record := s.validationRecords[key]
	if record == nil {
		wire, encodeErr := cvValidationRequestScalarCanonicalBytes(request, s.cfg.Params)
		if encodeErr != nil {
			s.mu.Unlock()
			return nil, encodeErr
		}
		record = &cvValidationRecordScalar{requestWire: wire, request: request, statement: append([]byte(nil), statement...), resultReady: make(chan struct{}, 1)}
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
	decoded, err := cvDecodeValidationResultScalar(resultWire, validatorSample)
	if err != nil || !bytes.Equal(decoded.Statement, statement) ||
		cvVerifyValidationCertificateScalar(&decoded.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
		return nil, fmt.Errorf("invalid CV V2 validation result state")
	}
	return &decoded.Certificate, nil
}

func (s *cvAPDBNetworkServiceScalar) FinalizeDecision(
	ctx context.Context, decided *cvAgreementObjectScalar,
) (*cvHandoffScalar, error) {
	if s == nil || ctx == nil || decided == nil || s.cfg.DecisionStore == nil ||
		!cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, fmt.Errorf("invalid CV V2 decision finalization input")
	}
	statement, err := cvDecisionStatementScalar(s.cfg.ExpectedContext, &decided.Header, &decided.ARC)
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
	shareWire, err := cvDecisionShareScalarCanonicalBytes(&cvDecisionShareScalar{Statement: statement, Signature: localShare})
	if err != nil {
		return nil, err
	}
	key := string(statement)
	pending := &cvPendingDecisionScalar{statement: statement, shares: map[int][]byte{
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
		cvNotifyAPDBScalar(pending.ready)
	}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingDecisions[key] == pending {
			delete(s.pendingDecisions, key)
		}
		s.mu.Unlock()
	}()
	// Use a wall-clock retry budget so CPU scheduling skew cannot exhaust a
	// small attempt count while an honest quorum is still responding.
	budget := cvDecisionRetryBudgetScalar()
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
			s.sendPriorityFanoutScalar(missing, -1, cvTagDecisionShareScalar, shareWire)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			// Threshold notification is advisory; the locked check below observes it.
		default:
		}
		s.mu.Lock()
		shareCount = len(pending.shares)
		hasCertificate = len(pending.certificate) != 0
		s.mu.Unlock()
		if hasCertificate || shareCount >= s.controlSigner.Threshold() {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsScalar && time.Now().After(budgetDeadline) {
			return nil, fmt.Errorf(
				"CV V2 decision finalization reached %d shares, need %d (budget %s)",
				shareCount, s.controlSigner.Threshold(), budget,
			)
		}
		timer := time.NewTimer(cvControlRetryDelayScalar(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			// Threshold notification is advisory; the next iteration rechecks it.
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
		decCert, err = s.controlSigner.Recover(cvDecisionCertificateScalarDomain, statement, shares)
	}
	if err == nil && !s.controlSigner.VerifyRecovered(cvDecisionCertificateScalarDomain, statement, decCert) {
		err = fmt.Errorf("invalid recovered CV V2 decision certificate")
	}
	s.recordCertificateFormationScalar(cvCertificateDecisionScalar, time.Since(formationStarted))
	if err != nil {
		return nil, err
	}
	handoff := &cvHandoffScalar{
		ContextDigest: append([]byte(nil), s.cfg.ExpectedContext...), Header: decided.Header,
		ARC: decided.ARC, DecCert: decCert,
	}
	if err := cvVerifyHandoffScalar(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner); err != nil {
		return nil, err
	}
	handoffWire, err := cvHandoffScalarCanonicalBytes(handoff)
	if err != nil {
		return nil, err
	}
	recipients := sortedUnique(append(append([]int(nil), s.cfg.OldRoster...), s.cfg.NewRoster...))
	s.sendFanoutMeasuredScalar(recipients, s.cfg.LocalNode, cvTagHandoffScalar, handoffWire)
	return handoff, nil
}

func (s *cvAPDBNetworkServiceScalar) AwaitHandoff(ctx context.Context) (*cvHandoffScalar, error) {
	if s == nil || ctx == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.NewRoster) {
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
	handoff, err := cvDecodeHandoffScalar(wire)
	if err != nil || cvVerifyHandoffScalar(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return nil, fmt.Errorf("invalid CV V2 accepted handoff")
	}
	return handoff, nil
}

func (s *cvAPDBNetworkServiceScalar) RecoverAndExchangeScalarShare(
	ctx context.Context, handoff *cvHandoffScalar,
) (*cvAggregateScalar, fr.Element, *cvScalarShareOutputScalar, bls12381.G1Affine, error) {
	if s == nil || ctx == nil || handoff == nil || s.cfg.LeafContext == nil || s.cfg.Receivers == nil ||
		s.cfg.ScalarStore == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 receiver recovery input")
	}
	requestWire, err := cvAggregateRecoveryRequestScalarCanonicalBytes(
		&cvAggregateRecoveryRequestScalar{Handoff: *handoff},
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	payload, err := s.RecoverAggregate(ctx, requestWire, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestScalar(recovered)
		if digestErr != nil || !bytes.Equal(digest, handoff.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 recovered aggregate payload mismatch")
		}
		return nil
	})
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	aggregate, err := cvDecodeAggregateScalar(payload, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadScalar(&handoff.Header, payload, aggregate) != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("invalid CV V2 recovered aggregate")
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[s.cfg.LocalNode]
	secret, hasSecret := s.cfg.Receivers.localEncryptionSecrets[s.cfg.LocalNode]
	if !ok || !hasSecret {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf("missing local CV V2 receiver secret")
	}
	scalar, output, decryptTimings, err := cvDecryptAggregateShareMeasuredScalar(
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
	outputWire, err := cvScalarShareOutputScalarCanonicalBytesAfterValidation(output)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	key := string(aggregate.Digest)
	pending := &cvPendingScalarSharesScalar{aggregate: aggregate, outputs: map[int]*cvScalarShareOutputScalar{
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
		cvNotifyAPDBScalar(pending.ready)
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
			s.sendFanoutMeasuredScalar(missing, -1, cvTagAggregateShareScalar, outputWire)
		}
		select {
		case <-ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			// Threshold notification is advisory; the locked check below observes it.
		default:
		}
		s.mu.Lock()
		outputCount = len(pending.outputs)
		s.mu.Unlock()
		if outputCount >= s.cfg.Params.newShareThreshold {
			break
		}
		if attempt >= cvControlRetryMaxAttemptsScalar {
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, fmt.Errorf(
				"CV V2 scalar-share exchange reached %d outputs, need %d",
				outputCount, s.cfg.Params.newShareThreshold,
			)
		}
		timer := time.NewTimer(cvControlRetryDelayScalar(attempt))
		select {
		case <-ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, ctx.Err()
		case <-s.ctx.Done():
			_ = timer.Stop()
			return nil, fr.Element{}, nil, bls12381.G1Affine{}, s.ctx.Err()
		case <-pending.ready:
			_ = timer.Stop()
			// Threshold notification is advisory; the next iteration rechecks it.
		case <-timer.C:
		}
	}

	s.mu.Lock()
	outputs := make([]*cvScalarShareOutputScalar, 0, len(pending.outputs))
	for _, share := range pending.outputs {
		outputs = append(outputs, share)
	}
	s.mu.Unlock()
	publicKey, err := cvRecoverThresholdPublicKeyAfterValidationScalar(
		outputs, aggregate, s.cfg.LeafContext, s.cfg.Params, s.cfg.Receivers,
	)
	if err != nil {
		return nil, fr.Element{}, nil, bls12381.G1Affine{}, err
	}
	return aggregate, scalar, output, publicKey, nil
}

func (s *cvAPDBNetworkServiceScalar) validatePool(pool *cvPoolScalar) ([]byte, error) {
	if pool == nil || !bytes.Equal(pool.ContextDigest, s.cfg.ExpectedContext) {
		return nil, fmt.Errorf("CV V2 pool context mismatch")
	}
	s.mu.Lock()
	_, eligible := s.eligibleProposers[pool.ProposerID]
	s.mu.Unlock()
	if !eligible {
		return nil, fmt.Errorf("CV V2 pool proposer is not eligible")
	}
	wire, err := cvPoolScalarCanonicalBytes(pool, s.cfg.Params)
	if err != nil {
		return nil, err
	}
	if err := s.validateKnownComponentRefsScalar(pool.Components); err != nil {
		return nil, fmt.Errorf("invalid CV V2 pool component: %w", err)
	}
	return wire, nil
}

func (s *cvAPDBNetworkServiceScalar) validateKnownComponentRefsScalar(refs []cvComponentRefScalar) error {
	s.mu.Lock()
	knownRefs := make(map[int]cvComponentRefScalar, len(refs))
	for _, ref := range refs {
		if known, ok := s.componentRefsScalar[ref.Header.DealerID]; ok {
			knownRefs[ref.Header.DealerID] = known
		}
	}
	s.mu.Unlock()
	for _, ref := range refs {
		known, ok := knownRefs[ref.Header.DealerID]
		if ok && equalComponentRefsScalar(known, ref) {
			continue
		}
		if ok {
			return fmt.Errorf("CV V2 component reference conflicts with verified cache")
		}
		if err := cvValidateComponentRefScalar(ref, s.apdbSigner); err != nil {
			return err
		}
	}
	return nil
}

func (s *cvAPDBNetworkServiceScalar) poolSlotLocked(proposer int) *cvNetworkPoolSlotScalar {
	slot := s.poolSlots[proposer]
	if slot == nil {
		slot = &cvNetworkPoolSlotScalar{
			shares: make(map[int][]byte), sharesReady: make(chan struct{}, 1), certReady: make(chan struct{}, 1),
		}
		s.poolSlots[proposer] = slot
	}
	return slot
}

// Coin runs either scalar protocol threshold-coin invocation among the old committee.
// The invocation itself is domain separated by cvEligibilityCoinInvocationScalar
// or cvContributorCoinInvocationScalar before reaching this method.
func (s *cvAPDBNetworkServiceScalar) runCoin(ctx context.Context, invocation []byte) (*cvCoinOutputScalar, error) {
	if s == nil || ctx == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) ||
		!cvScalarSignerHasRole(s.coinSigner, cvScalarRoleCoin) {
		return nil, fmt.Errorf("invalid CV V2 network coin input")
	}
	digest, err := cvCoinInvocationDigestScalar(invocation)
	if err != nil {
		return nil, err
	}
	localSignature, err := s.coinSigner.SignShare(s.cfg.LocalNode, cvScalarCoinDomain, digest)
	if err != nil {
		return nil, err
	}
	message, err := cvCoinShareScalarCanonicalBytes(&cvCoinShareScalar{InvocationDigest: digest, Signature: localSignature})
	if err != nil {
		return nil, err
	}
	pending := &cvPendingCoinScalar{invocation: append([]byte(nil), invocation...), shares: make(map[int][]byte), ready: make(chan struct{}, 1)}
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
		cvNotifyAPDBScalar(pending.ready)
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
		_ = s.sendFanoutMeasuredScalar(recipients, s.cfg.LocalNode, cvTagCoinShareScalar, message)
		s.recordCoinFanoutLatencyScalar(time.Since(started))
	}
	sendShare(s.cfg.OldRoster)
	for attempt := 0; attempt < cvControlRetryMaxAttemptsScalar; attempt++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-pending.ready:
			goto recovered
		case <-time.After(cvControlRetryDelayScalar(attempt)):
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
	certificate, err := s.coinSigner.Recover(cvScalarCoinDomain, digest, shares)
	if err != nil {
		return nil, err
	}
	return cvBuildCoinOutputScalar(invocation, certificate, s.coinSigner)
}

func (s *cvAPDBNetworkServiceScalar) Close() error {
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

func (s *cvAPDBNetworkServiceScalar) Lock(ctx context.Context, encoded *cvAPDBEncodedScalar) (*cvAPDBLockScalar, error) {
	return s.lockForPurposeScalar(ctx, encoded, false)
}

func (s *cvAPDBNetworkServiceScalar) LockAggregate(ctx context.Context, encoded *cvAPDBEncodedScalar) (*cvAPDBLockScalar, error) {
	return s.lockForPurposeScalar(ctx, encoded, true)
}

func (s *cvAPDBNetworkServiceScalar) lockForPurposeScalar(
	ctx context.Context, encoded *cvAPDBEncodedScalar, aggregate bool,
) (*cvAPDBLockScalar, error) {
	if s == nil || ctx == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) || encoded == nil ||
		s.cfg.ShardBytes <= 0 ||
		encoded.totalShards != s.cfg.TotalShards || encoded.dataShards != s.cfg.DataShards ||
		encoded.shardBytes != s.cfg.ShardBytes {
		return nil, fmt.Errorf("invalid CV V2 network LockPD input")
	}
	collector, err := newCVAPDBLockCollectorScalar(encoded, s.cfg.OldRoster, s.apdbSigner)
	if err != nil {
		return nil, err
	}
	key := string(encoded.instanceDigest)
	pending := &cvAPDBPendingLockScalar{collector: collector, ready: make(chan struct{}, 1), aggregate: aggregate}
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
	fanoutDone := make(chan []cvFanoutSendResultScalar, 1)
	storeTag := cvTagAPDBStoreScalar
	if aggregate {
		storeTag = cvTagAggregateAPDBStoreScalar
	}
	go func() {
		results := s.sendRecipientPayloadFanoutContextMeasuredScalar(
			lockCtx, holders, storeTag, offers,
		)
		for _, result := range results {
			if result.err == nil {
				s.recordDispersalBytesScalar(aggregate, true, result.wireBytes)
			}
		}
		fanoutDone <- results
	}()
	var results []cvFanoutSendResultScalar
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
		s.recordAggregateOfferSendLatencyScalar(time.Since(started))
	}
	{
		formationStarted := time.Now()
		lock, recoverErr := collector.RecoverLock()
		if aggregate {
			s.recordCertificateFormationScalar(cvCertificateARCScalar, time.Since(formationStarted))
		}
		return lock, recoverErr
	}
}

func (s *cvAPDBNetworkServiceScalar) RecoverComponent(
	ctx context.Context, lock *cvAPDBLockScalar, bindingCheck func([]byte) error,
) ([]byte, error) {
	payload, _, err := s.recoverComponentForPurpose(ctx, lock, bindingCheck, cvRecoveryUnclassifiedScalar, -1)
	return payload, err
}

// recoverComponentForPurpose additionally returns the uncompressed-point
// sidecar a dealer attached to its payload response; callers that decode the
// recovered leaf pass it to cvDecodeLeafScalarWithHints, others discard it.
func (s *cvAPDBNetworkServiceScalar) recoverComponentForPurpose(
	ctx context.Context, lock *cvAPDBLockScalar, bindingCheck func([]byte) error, purpose cvRecoveryPurposeScalar,
	dealerID int,
) ([]byte, []byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster) {
		return nil, nil, fmt.Errorf("invalid CV V2 component recovery caller")
	}
	started := time.Now()
	if purpose != cvRecoveryUnclassifiedScalar {
		defer func() { s.recordRecoveryLatencyScalar(purpose, time.Since(started)) }()
	}
	request, err := cvAPDBLockScalarCanonicalBytes(lock)
	if err != nil {
		return nil, nil, err
	}
	collector, err := newCVAPDBRecoveryCollectorScalar(lock, s.cfg.OldRoster, s.cfg.DataShards, s.cfg.ShardBytes,
		s.cfg.MaximumPayload, s.apdbSigner, bindingCheck)
	if err != nil {
		return nil, nil, err
	}
	recipients := collector.RequestRecipients()
	firstWave := cvRecoveryFirstWaveScalar(
		recipients, s.cfg.DataShards+cvRecoveryFirstWaveHoldersScalar, s.cfg.LocalNode, dealerID,
	)
	waves := []cvRecoveryRequestWaveScalar{{
		recipients: firstWave, responseGrace: cvRecoveryResponseGraceScalar,
	}}
	if cvComponentRecoveryScheduleScalar() == cvComponentRecoveryDealerFirstScalar &&
		cvMemberInRosterScalar(dealerID, recipients) {
		holderWave := make([]int, 0, len(firstWave)-1)
		for _, recipient := range firstWave {
			if recipient != dealerID {
				holderWave = append(holderWave, recipient)
			}
		}
		waves = []cvRecoveryRequestWaveScalar{
			{recipients: []int{dealerID}, responseGrace: cvComponentDirectGraceForCommitteeScalar(len(s.cfg.OldRoster)), waitAfterSend: true,
				onGraceWait: func(elapsed time.Duration) { s.recordComponentDirectGraceWaitScalar(elapsed) }},
			{recipients: holderWave, responseGrace: cvRecoveryResponseGraceScalar},
		}
	}
	payload, err := s.runRecoveryWithSchedule(ctx, cvTagAPDBRecoverGetScalar, request, string(lock.InstanceDigest),
		collector, false, purpose, waves)
	if err != nil {
		return nil, nil, err
	}
	return payload, collector.RecoveredHints(), nil
}

func (s *cvAPDBNetworkServiceScalar) RecoverAggregate(
	ctx context.Context, requestWire []byte, bindingCheck func([]byte) error,
) ([]byte, error) {
	if s == nil || ctx == nil || !cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.NewRoster) {
		return nil, fmt.Errorf("invalid CV V2 aggregate recovery caller")
	}
	collector, err := newCVAggregateRecoveryCollectorScalar(requestWire, s.cfg.ExpectedContext, s.cfg.OldRoster,
		s.cfg.DataShards, s.cfg.ShardBytes, s.cfg.MaximumPayload, s.apdbSigner, s.controlSigner, bindingCheck)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	defer func() { s.recordRecoveryLatencyScalar(cvRecoveryNewAggregateScalar, time.Since(started)) }()
	request, err := cvDecodeAggregateRecoveryRequestScalar(requestWire)
	if err != nil {
		return nil, err
	}
	if payload, ok, pullErr := s.tryAggregatePayloadPullScalar(ctx, &request.Handoff, requestWire, bindingCheck); pullErr != nil {
		return nil, pullErr
	} else if ok {
		return payload, nil
	}
	receiverIndex := sort.SearchInts(s.cfg.NewRoster, s.cfg.LocalNode)
	firstWave := cvRotatedAggregateRecoveryFirstWaveScalar(
		collector.RequestRecipients(), collector.dataShards+cvAggregateRecoveryFirstWaveExtraScalar, receiverIndex,
	)
	payload, err := s.runRecoveryWithWave(ctx, cvTagAggregateRecoverGetScalar, requestWire,
		string(collector.lock.InstanceDigest), collector, true, cvRecoveryNewAggregateScalar,
		firstWave, cvRecoveryResponseGraceScalar)
	if err == nil {
		s.cancelLateAggregateRecoveryScalar(requestWire)
	}
	return payload, err
}

func (s *cvAPDBNetworkServiceScalar) runRecoveryWithWave(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorScalar, aggregate bool, purpose cvRecoveryPurposeScalar,
	firstWave []int, responseGrace time.Duration,
) ([]byte, error) {
	return s.runRecoveryWithSchedule(ctx, requestTag, request, key, collector, aggregate, purpose,
		[]cvRecoveryRequestWaveScalar{{recipients: firstWave, responseGrace: responseGrace}})
}

func (s *cvAPDBNetworkServiceScalar) runRecoveryWithSchedule(
	ctx context.Context, requestTag string, request []byte, key string,
	collector *cvAPDBRecoveryCollectorScalar, aggregate bool, purpose cvRecoveryPurposeScalar,
	waves []cvRecoveryRequestWaveScalar,
) ([]byte, error) {
	pending := &cvAPDBPendingRecoveryScalar{collector: collector, ready: make(chan struct{}, 1), purpose: purpose}
	if err := s.registerRecovery(key, pending, aggregate); err != nil {
		return nil, err
	}
	defer s.unregisterRecovery(key, pending, aggregate)
	ready, err := cvSendRecoveryRequestsWithScheduleScalar(
		ctx, s.ctx, pending.ready, collector.RequestRecipients(), collector.dataShards,
		cvControlRetryMaxAttemptsScalar, cvControlRetryDelayScalar, waves,
		func(recipients []int) []cvFanoutSendResultScalar {
			return s.sendFanoutMeasuredScalar(recipients, -1, requestTag, request)
		},
		func(result cvFanoutSendResultScalar) {
			s.recordRecoveryBytesScalar(purpose, true, result.wireBytes)
		},
	)
	if err != nil {
		return nil, err
	}
	if ready {
		return s.recoverAndRecordComponentSourceScalar(collector, purpose)
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-pending.ready:
		return s.recoverAndRecordComponentSourceScalar(collector, purpose)
	}
}

func (s *cvAPDBNetworkServiceScalar) recoverAndRecordComponentSourceScalar(
	collector *cvAPDBRecoveryCollectorScalar, purpose cvRecoveryPurposeScalar,
) ([]byte, error) {
	payload, direct, err := collector.recoverWithSource()
	if err != nil || (purpose != cvRecoveryProposerCatalogScalar && purpose != cvRecoveryValidatorComponentScalar) {
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
	cvRecoveryFirstWaveHoldersScalar        = 3
	cvAggregateRecoveryFirstWaveExtraScalar = 3
	cvRecoveryResponseGraceScalar           = 500 * time.Millisecond
	cvComponentDirectGraceDefaultScalar     = 250 * time.Millisecond
	cvComponentDirectGraceLargeScalar       = 500 * time.Millisecond
	cvComponentRecoveryHedgedScalar         = "hedged"
	cvComponentRecoveryDealerFirstScalar    = "dealer-first"
	cvComponentDealerResponseNormalScalar   = "normal"
	cvComponentDealerResponseDropScalar     = "drop"
)

func cvComponentRecoveryScheduleScalar() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_RECOVERY_SCHEDULE")),
		cvComponentRecoveryHedgedScalar) {
		return cvComponentRecoveryHedgedScalar
	}
	return cvComponentRecoveryDealerFirstScalar
}

func cvComponentDirectGraceScalar() time.Duration {
	return durationEnvMs("RLADKR_COMPONENT_DIRECT_GRACE_MS", cvComponentDirectGraceDefaultScalar)
}

func cvComponentDirectGraceForCommitteeScalar(n int) time.Duration {
	fallback := cvComponentDirectGraceDefaultScalar
	if n >= 32 {
		fallback = cvComponentDirectGraceLargeScalar
	}
	return durationEnvMs("RLADKR_COMPONENT_DIRECT_GRACE_MS", fallback)
}

func cvComponentDealerResponseModeScalar() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_DEALER_RESPONSE")),
		cvComponentDealerResponseDropScalar) {
		return cvComponentDealerResponseDropScalar
	}
	return cvComponentDealerResponseNormalScalar
}

func cvComponentPayloadCompressionEnabledScalar() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_COMPONENT_PAYLOAD_COMPRESSION"))) {
	case "0", "false", "off", "disabled":
		return false
	default:
		return true
	}
}

// CVComponentRecoverySchedule reports the active component request schedule.
func CVComponentRecoverySchedule() string { return cvComponentRecoveryScheduleScalar() }

// CVComponentDirectGrace reports how long dealer-first waits before requesting fragments.
func CVComponentDirectGrace() time.Duration { return cvComponentDirectGraceScalar() }

// CVComponentDirectGraceForCommittee reports the active dealer-first grace,
// including the larger default used by committees of at least 32 nodes.
func CVComponentDirectGraceForCommittee(n int) time.Duration {
	return cvComponentDirectGraceForCommitteeScalar(n)
}

// CVComponentDealerResponseMode reports the experiment-only dealer fault mode.
func CVComponentDealerResponseMode() string { return cvComponentDealerResponseModeScalar() }

// CVComponentPayloadCompressionEnabled reports whether dealer payload
// responses use the compatible compressed transport representation.
func CVComponentPayloadCompressionEnabled() bool { return cvComponentPayloadCompressionEnabledScalar() }

func cvRotatedAggregateRecoveryFirstWaveScalar(recipients []int, count, rotateBy int) []int {
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

func (s *cvAPDBNetworkServiceScalar) cancelLateAggregateRecoveryScalar(request []byte) {
	wire, err := cvAggregateRecoveryCancelScalarCanonicalBytes(request)
	if err != nil {
		return
	}
	for _, holder := range s.cfg.OldRoster {
		_ = s.sendPriorityAsync(holder, cvTagAggregateRecoverCancelScalar, wire, nil)
	}
}

// cvRecoveryFirstWaveScalar orders a dealer-anchored, requester-rotated subset of
// the recipients so the dealer's single payload response lands first while
// concurrent requesters spread their shard fallback over different holders.
func cvRecoveryFirstWaveScalar(recipients []int, count, rotateBy, dealer int) []int {
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

func cvSendRecoveryRequestsWithRetryScalar(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, send func([]int) []cvFanoutSendResultScalar,
	onSuccess func(cvFanoutSendResultScalar),
) (bool, error) {
	return cvSendRecoveryRequestsWithWavesScalar(
		ctx, serviceCtx, ready, recipients, dataShards, maxRetries, retryDelay, nil, 0, send, onSuccess,
	)
}

func cvSendRecoveryRequestsWithWavesScalar(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, firstWave []int, responseGrace time.Duration,
	send func([]int) []cvFanoutSendResultScalar,
	onSuccess func(cvFanoutSendResultScalar),
) (bool, error) {
	return cvSendRecoveryRequestsWithScheduleScalar(
		ctx, serviceCtx, ready, recipients, dataShards, maxRetries, retryDelay,
		[]cvRecoveryRequestWaveScalar{{recipients: firstWave, responseGrace: responseGrace}}, send, onSuccess,
	)
}

type cvRecoveryRequestWaveScalar struct {
	recipients    []int
	responseGrace time.Duration
	waitAfterSend bool
	onGraceWait   func(time.Duration)
}

func cvSendRecoveryRequestsWithScheduleScalar(
	ctx, serviceCtx context.Context, ready <-chan struct{}, recipients []int, dataShards, maxRetries int,
	retryDelay func(int) time.Duration, waves []cvRecoveryRequestWaveScalar,
	send func([]int) []cvFanoutSendResultScalar,
	onSuccess func(cvFanoutSendResultScalar),
) (bool, error) {
	succeeded := make(map[int]struct{}, len(recipients))
	allowed := make(map[int]struct{}, len(recipients))
	for _, recipient := range recipients {
		allowed[recipient] = struct{}{}
	}
	trackWave := func(targets []int) int {
		newlySucceeded := 0
		results := send(targets)
		byRecipient := make(map[int]cvFanoutSendResultScalar, len(results))
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
		byRecipient := make(map[int]cvFanoutSendResultScalar, len(results))
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

func (s *cvAPDBNetworkServiceScalar) run() {
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

type cvValidatorPrewarmModeScalar int

const (
	cvValidatorPrewarmOffScalar cvValidatorPrewarmModeScalar = iota
	cvValidatorPrewarmRecoverScalar
	cvValidatorPrewarmFullScalar
)

// cvValidatorPrewarmModeScalar selects validator preparation before requests.
func cvValidatorPrewarmModeFromEnvScalar(rosterSize int) cvValidatorPrewarmModeScalar {
	switch strings.TrimSpace(strings.ToLower(os.Getenv("RLADKR_VALIDATOR_PREWARM"))) {
	case "full":
		return cvValidatorPrewarmFullScalar
	case "recover":
		return cvValidatorPrewarmRecoverScalar
	case "off":
		return cvValidatorPrewarmOffScalar
	default:
		// Large committees prewarm payloads and verify only on request.
		if rosterSize > 128 {
			return cvValidatorPrewarmRecoverScalar
		}
		return cvValidatorPrewarmFullScalar
	}
}

type cvRecoveredPayloadCallScalar struct {
	done    chan struct{}
	payload []byte
	hints   []byte
	err     error
}

// cvRecoveredPayloadEntryScalar caches a recovered payload together with any
// uncompressed-point sidecar so a later verified decode reuses both.
type cvRecoveredPayloadEntryScalar struct {
	payload []byte
	hints   []byte
}

// cacheRecoveredPayloadLockedScalar takes ownership of collector-owned immutable
// slices. The caller must hold s.mu and must not mutate them after this call.
func (s *cvAPDBNetworkServiceScalar) cacheRecoveredPayloadLockedScalar(
	key string, payload, hints []byte,
) {
	if s.recoveredPayloadsScalar == nil {
		s.recoveredPayloadsScalar = make(map[string]cvRecoveredPayloadEntryScalar, len(s.cfg.OldRoster))
	}
	if len(s.recoveredPayloadsScalar) < len(s.cfg.OldRoster) {
		s.recoveredPayloadsScalar[key] = cvRecoveredPayloadEntryScalar{payload: payload, hints: hints}
	}
}

func cvRecoveredComponentPayloadKeyScalar(ref cvComponentRefScalar) string {
	// These fields are fixed-width after cvValidateComponentRefScalar. Including
	// both payload and APDB bindings prevents an equivocating dealer from
	// sharing a cache/singleflight entry across conflicting component refs.
	return string(hashBytes(
		[]byte("ARL-CV-V2/recovered-component-payload-cache"),
		ref.Header.Instance, ref.Header.PayloadDigest, ref.Lock.Root,
	))
}

// recoveredComponentPayloadScalar returns an authenticated immutable payload,
// consulting verified and recovered caches before the network.
func (s *cvAPDBNetworkServiceScalar) recoveredComponentPayloadScalar(
	ctx context.Context, ref cvComponentRefScalar, purpose cvRecoveryPurposeScalar,
) ([]byte, []byte, error) {
	key := cvRecoveredComponentPayloadKeyScalar(ref)
	s.mu.Lock()
	if entry, ok := s.verifiedComponentsScalar[ref.Header.DealerID]; ok &&
		equalComponentRefsScalar(entry.ref, ref) && len(entry.payload) > 0 {
		payload := entry.payload
		s.mu.Unlock()
		return payload, nil, nil
	}
	if entry, ok := s.recoveredPayloadsScalar[key]; ok {
		payload, hints := entry.payload, entry.hints
		s.mu.Unlock()
		return payload, hints, nil
	}
	if call := s.recoveredPayloadCallsScalar[key]; call != nil {
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
	call := &cvRecoveredPayloadCallScalar{done: make(chan struct{})}
	if s.recoveredPayloadCallsScalar == nil {
		s.recoveredPayloadCallsScalar = make(map[string]*cvRecoveredPayloadCallScalar, 8)
	}
	s.recoveredPayloadCallsScalar[key] = call
	s.mu.Unlock()

	payload, hints, err := s.recoverComponentForPurpose(ctx, &ref.Lock, func(recovered []byte) error {
		if !bytes.Equal(cvComponentPayloadDigestScalar(recovered), ref.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 component payload mismatch")
		}
		return nil
	}, purpose, ref.Header.DealerID)

	s.mu.Lock()
	call.payload, call.hints, call.err = payload, hints, err
	delete(s.recoveredPayloadCallsScalar, key)
	if err == nil {
		s.cacheRecoveredPayloadLockedScalar(key, payload, hints)
	}
	close(call.done)
	s.mu.Unlock()
	return payload, hints, err
}

// prewarmComponentRecoveryScalar caches payloads; validation remains on demand.
func (s *cvAPDBNetworkServiceScalar) prewarmComponentRecoveryScalar() {
	workers := make(chan struct{}, 4)
	var group sync.WaitGroup
	defer group.Wait()
	seen := make(map[int]struct{}, len(s.cfg.OldRoster))
	for {
		s.mu.Lock()
		pending := make([]cvComponentRefScalar, 0, len(s.componentRefsScalar))
		for dealer, ref := range s.componentRefsScalar {
			if _, done := seen[dealer]; done {
				continue
			}
			seen[dealer] = struct{}{}
			if _, verified := s.verifiedComponentsScalar[dealer]; verified {
				continue
			}
			pending = append(pending, ref)
		}
		updates := s.componentRefUpdatesScalar
		complete := len(seen) >= len(s.cfg.OldRoster)
		s.mu.Unlock()
		if complete {
			return
		}
		for _, ref := range pending {
			group.Add(1)
			workers <- struct{}{}
			go func(ref cvComponentRefScalar) {
				defer func() { <-workers; group.Done() }()
				_, _, _ = s.recoveredComponentPayloadScalar(s.ctx, ref, cvRecoveryValidatorComponentScalar)
			}(ref)
		}
		select {
		case <-s.ctx.Done():
			return
		case <-updates:
		}
	}
}

// cacheDealerPayloadScalar retains this node's own locked component payload so the
// dealer can serve authenticated full-payload recovery responses.
func (s *cvAPDBNetworkServiceScalar) cacheDealerPayloadScalar(instanceDigest, payload []byte) {
	if s == nil || len(instanceDigest) != 32 || len(payload) == 0 || len(payload) > s.cfg.MaximumPayload {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dealerPayloadsScalar == nil {
		s.dealerPayloadsScalar = make(map[string][]byte, 8)
	}
	jobPayload := []byte(nil)
	if cached, exists := s.dealerPayloadsScalar[string(instanceDigest)]; !exists && len(s.dealerPayloadsScalar) < 64 {
		s.dealerPayloadsScalar[string(instanceDigest)] = append([]byte(nil), payload...)
	} else if !exists && len(cached) == 0 {
		// Keep the old behavior when the bounded cache is full: the prepare job
		// still receives an owned payload and can build its response once.
		jobPayload = append([]byte(nil), payload...)
	}
	if s.dealerPayloadHintStates == nil {
		s.dealerPayloadHintStates = make(map[string]*cvDealerPayloadHintStateScalar, 8)
	}
	if s.dealerPayloadHintStates[string(instanceDigest)] == nil {
		s.dealerPayloadHintStates[string(instanceDigest)] = &cvDealerPayloadHintStateScalar{ready: make(chan struct{})}
	}
	go s.enqueueRecoveryJobScalar(cvRecoveryJobScalar{kind: cvRecoveryPrepareDealerScalar,
		instanceDigest: append([]byte(nil), instanceDigest...), payload: jobPayload})
}

func (s *cvAPDBNetworkServiceScalar) dealerPayloadScalar(instanceDigest []byte) ([]byte, bool) {
	if s == nil || len(instanceDigest) != 32 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, ok := s.dealerPayloadsScalar[string(instanceDigest)]
	if !ok {
		return nil, false
	}
	return payload, true
}

// cvDealerPayloadHintStateScalar memoizes the uncompressed-point attachment for
// one cached dealer payload. Recording replays the exact consumer decode, so
// it costs one full verification per component, once, off the request path.
type cvDealerPayloadHintStateScalar struct {
	once     sync.Once
	ready    chan struct{}
	hints    []byte
	response []byte
}

func (s *cvAPDBNetworkServiceScalar) dealerPayloadHintBytesScalar(instanceDigest []byte) int {
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

// dealerPayloadResponseScalar returns a cached full-payload response, computing
// hints and canonical encoding once per instance. A nil result means the
// payload could not be encoded and callers may use the shard fallback.
func (s *cvAPDBNetworkServiceScalar) dealerPayloadResponseScalar(instanceDigest, payload []byte) []byte {
	if s == nil || len(instanceDigest) != 32 || len(payload) == 0 {
		return nil
	}
	s.mu.Lock()
	if s.dealerPayloadHintStates == nil {
		s.dealerPayloadHintStates = make(map[string]*cvDealerPayloadHintStateScalar, 8)
	}
	state := s.dealerPayloadHintStates[string(instanceDigest)]
	if state == nil {
		state = &cvDealerPayloadHintStateScalar{ready: make(chan struct{})}
		s.dealerPayloadHintStates[string(instanceDigest)] = state
	}
	s.mu.Unlock()
	state.once.Do(func() {
		hintStarted := time.Now()
		defer close(state.ready)
		if cvPayloadHintsEnabledScalar() && s.cfg.LeafContext != nil && s.cfg.Receivers != nil && s.cfg.Validators != nil {
			state.hints = cvRecordLeafDeferredHintsScalar(payload, s.cfg.LeafContext, s.cfg.Receivers, s.cfg.Validators)
		}
		if len(state.hints) > cvMaxPayloadHintsBytesScalar(s.cfg.MaximumPayload) {
			state.hints = nil
		}
		s.experimentMu.Lock()
		s.experimentMetrics.dealerHintBuildLatency += time.Since(hintStarted)
		s.experimentMu.Unlock()
		encodeStarted := time.Now()
		payloadResponse := &cvAPDBPayloadResponseScalar{
			InstanceDigest: instanceDigest, Payload: payload, Hints: state.hints,
		}
		response, err := cvAPDBPayloadResponseScalarCanonicalBytes(payloadResponse)
		if cvComponentPayloadCompressionEnabledScalar() {
			response, err = cvAPDBPayloadResponseScalarTransportBytes(payloadResponse)
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

func (s *cvAPDBNetworkServiceScalar) dispatch(msg Message) {
	s.recordTagBytesScalar(msg.Tag, false, msg.WireBytes)
	switch msg.Tag {
	case cvTagAPDBStoreScalar, cvTagAggregateAPDBStoreScalar:
		if s.holderStore == nil {
			return
		}
		response, err := cvHandleAPDBStoreOfferScalar(s.cfg.SID, s.cfg.Epoch, msg.From, s.cfg.LocalNode,
			s.cfg.OldRoster, msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes, s.holderStore, s.apdbSigner)
		if err == nil {
			responseTag := cvTagAPDBStoredShareScalar
			if msg.Tag == cvTagAggregateAPDBStoreScalar {
				responseTag = cvTagAggregateARCShareScalar
			}
			_ = s.sendAsync(msg.From, responseTag, response, nil)
		}
	case cvTagAPDBStoredShareScalar, cvTagAggregateARCShareScalar:
		response, err := cvDecodeAPDBStoredShareScalar(msg.Body)
		if err != nil {
			return
		}
		pending := s.lookupLock(string(response.InstanceDigest))
		if pending != nil {
			if pending.aggregate != (msg.Tag == cvTagAggregateARCShareScalar) {
				return
			}
			s.recordDispersalBytesScalar(pending.aggregate, false, msg.WireBytes)
			if complete, addErr := pending.collector.AddDecodedStoredShare(msg.From, response, msg.Body); addErr == nil && complete {
				cvNotifyAPDBScalar(pending.ready)
			}
		}
	case cvTagAPDBRecoverGetScalar:
		if s.holderStore == nil {
			return
		}
		requestDigest := hashBytes(msg.Body)
		dedupeKey := fmt.Sprintf("%d:%x", msg.From, requestDigest)
		responseCacheKey := fmt.Sprintf("%x", requestDigest)
		if !s.claimRecoveryRequestScalar(dedupeKey) {
			return
		}
		if !s.enqueueRecoveryJobScalar(cvRecoveryJobScalar{kind: cvRecoveryDealerRequestScalar, msg: msg, dedupeKey: dedupeKey, responseCacheKey: responseCacheKey}) {
			s.releaseRecoveryRequestScalar(dedupeKey)
		}
	case cvTagAPDBRecoverPayloadScalar:
		_ = s.enqueueRecoveryJobScalar(cvRecoveryJobScalar{kind: cvRecoveryPayloadResponseScalar, msg: msg})
	case cvTagAggregatePayloadGetScalar:
		_ = s.enqueueRecoveryJobScalar(cvRecoveryJobScalar{kind: cvRecoveryAggregatePayloadRequestScalar, msg: msg})
	case cvTagAggregatePayloadScalar:
		s.handleAggregatePayloadPullResponseScalar(msg)
	case cvTagAggregateRecoverGetScalar:
		if s.holderStore == nil {
			return
		}
		requestKey := cvAggregateRecoveryRequestKeyScalar{receiver: msg.From, digest: string(hashBytes(msg.Body))}
		if !s.registerAggregateRecoveryRequestScalar(requestKey) {
			return
		}
		if !s.enqueueRecoveryJobScalar(cvRecoveryJobScalar{kind: cvRecoveryAggregateRequestScalar, msg: msg, requestDigest: requestKey.digest}) {
			s.finishAggregateRecoveryRequestScalar(requestKey)
		}
	case cvTagAggregateRecoverCancelScalar:
		digest, err := cvDecodeAggregateRecoveryCancelScalar(msg.Body)
		if err == nil {
			s.cancelAggregateRecoveryRequestScalar(cvAggregateRecoveryRequestKeyScalar{receiver: msg.From, digest: digest})
		}
	case cvTagAPDBRecoverStoreScalar, cvTagAggregateRecoverStoreScalar:
		store, err := cvDecodeAPDBStoreScalar(msg.Body, s.cfg.TotalShards, s.cfg.ShardBytes)
		if err != nil {
			return
		}
		aggregate := msg.Tag == cvTagAggregateRecoverStoreScalar
		pending := s.lookupRecovery(string(store.InstanceDigest), aggregate)
		if pending != nil {
			if pending.collector.complete() {
				if !aggregate {
					s.recordComponentRecoveryLateRecvBytesScalar(msg.WireBytes)
				}
				return
			}
			s.recordRecoveryBytesScalar(pending.purpose, false, msg.WireBytes)
			if complete, addErr := pending.collector.AddDecodedStore(msg.From, store, msg.Body); addErr == nil {
				if complete {
					cvNotifyAPDBScalar(pending.ready)
				}
			}
		} else if !aggregate {
			s.recordComponentRecoveryLateRecvBytesScalar(msg.WireBytes)
		}
	case cvTagCoinShareScalar:
		share, err := cvDecodeCoinShareScalar(msg.Body)
		if err != nil || !cvScalarSignerHasRole(s.coinSigner, cvScalarRoleCoin) {
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
			msg.From, cvScalarCoinDomain, share.InvocationDigest, share.Signature,
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
				cvNotifyAPDBScalar(pending.ready)
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
			err := s.sendAsync(peer, cvTagCoinShareScalar, reply, func(sendErr error) {
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
	case cvTagPoolOfferScalar:
		s.handlePoolOffer(msg)
	case cvTagPoolCertShareScalar:
		s.handlePoolCertificateShare(msg)
	case cvTagPoolCertScalar:
		s.handlePoolCertificate(msg)
	case cvTagValidationRequestScalar:
		s.handleValidationRequest(msg)
	case cvTagValidationSignatureScalar:
		s.handleValidationSignature(msg)
	case cvTagValidationResultScalar:
		s.handleValidationResult(msg)
	case cvTagDecisionShareScalar:
		s.handleDecisionShare(msg)
	case cvTagHandoffScalar:
		s.handleHandoff(msg)
	case cvTagAggregateShareScalar:
		s.handleAggregateShare(msg)
	case cvTagLaneOfferScalar:
		s.enqueueLaneOfferScalar(msg)
	case cvTagLaneACKScalar:
		s.handleLaneACKScalar(msg)
	case cvTagComponentRefScalar:
		s.handleComponentRefScalar(msg)
	case cvTagCertifiedCandidateScalar:
		s.enqueueCertifiedCandidateScalar(msg)
	case cvTagCertifiedCandidateACKScalar:
		digest, err := cvDecodeCertifiedCandidateACKScalar(msg.Body)
		if err == nil {
			s.markCertifiedCandidateACKScalar(digest, msg.From)
		}
	case cvTagCertifiedCandidateACKProbeScalar:
		s.handleCertifiedCandidateACKProbeScalar(msg)
	case cvTagCertifiedCandidateAnnounceScalar:
		s.handleCertifiedCandidateAnnounceScalar(msg)
	case cvTagCertifiedCandidateFetchScalar:
		s.handleCertifiedCandidateFetchScalar(msg)
	case cvTagCertifiedCandidateResponseScalar:
		s.handleCertifiedCandidateResponseScalar(msg)
	}
}

func (s *cvAPDBNetworkServiceScalar) handleLaneOfferScalar(msg Message) {
	if s.cfg.Receivers == nil || s.cfg.LeafContext == nil {
		return
	}
	receiverIndex, ok := s.cfg.Receivers.receiverIndex[msg.To]
	secret, secretOK := s.cfg.Receivers.localEncryptionSecrets[msg.To]
	identitySecret, identityOK := s.cfg.Receivers.localIdentitySecrets[msg.To]
	if !ok || !secretOK || !identityOK {
		return
	}
	offer, err := cvDecodeReceiverLaneOfferBeforeVerificationScalar(msg.Body, s.cfg.LeafContext, msg.From, msg.To,
		receiverIndex, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1])
	if err != nil {
		return
	}
	evidence, _, _, err := cvVerifyDecryptAndSignACKAfterPointDecodingScalar(
		s.cfg.LeafContext, msg.From, offer, &s.cfg.Receivers.encryptionPublicKeys[receiverIndex-1],
		secret, s.cfg.Receivers.identityPublicKeys[receiverIndex-1], identitySecret,
	)
	if err != nil {
		return
	}
	message := &cvLaneACKMessageScalar{DealerID: msg.From, ReceiverID: msg.To, ReceiverIndex: receiverIndex,
		OfferDigest: cvLaneOfferDigestScalar(msg.Body), Evidence: *evidence}
	wire, err := cvLaneACKMessageScalarCanonicalBytes(message, s.cfg.LeafContext)
	if err == nil {
		_ = s.send(msg.From, cvTagLaneACKScalar, wire)
	}
}

func (s *cvAPDBNetworkServiceScalar) handleLaneACKScalar(msg Message) {
	s.mu.Lock()
	pending := s.pendingLaneACKsScalar
	s.mu.Unlock()
	if pending == nil {
		return
	}
	message, err := cvDecodeLaneACKMessageScalar(msg.Body, s.cfg.LeafContext)
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
		wire, _ := cvReceiverLaneOfferScalarCanonicalBytesAfterValidation(
			s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[offerIndex],
		)
		wantOfferDigest = cvLaneOfferDigestScalar(wire)
	}
	if offerIndex < 0 || offerIndex >= len(pending.offers) || !bytes.Equal(message.OfferDigest, wantOfferDigest) {
		return
	}
	if err := cvVerifyACKAfterLocalOwnershipValidationScalar(
		s.cfg.LeafContext, s.cfg.LocalNode, pending.offers[message.ReceiverIndex-1],
		s.cfg.Receivers.identityPublicKeys[message.ReceiverIndex-1], &message.Evidence); err != nil {
		return
	}
	s.mu.Lock()
	if s.pendingLaneACKsScalar != pending || pending.frozen {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.acks[message.ReceiverIndex]; !duplicate {
		pending.acks[message.ReceiverIndex] = &message.Evidence
	}
	if len(pending.acks) >= pending.quorum {
		cvNotifyAPDBScalar(pending.ready)
	}
	if len(pending.acks) == len(s.cfg.NewRoster) {
		cvNotifyAPDBScalar(pending.allReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handlePoolOffer(msg Message) {
	s.mu.Lock()
	if slot := s.poolSlots[msg.From]; slot != nil && bytes.Equal(slot.poolWire, msg.Body) && len(slot.localShareWire) != 0 {
		shareWire := append([]byte(nil), slot.localShareWire...)
		s.mu.Unlock()
		_ = s.sendAsync(msg.From, cvTagPoolCertShareScalar, shareWire, nil)
		return
	}
	s.mu.Unlock()
	pool, err := cvDecodePoolScalar(msg.Body, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From {
		return
	}
	poolWire, err := s.validatePool(pool)
	if err != nil {
		return
	}
	statement, err := cvPoolCertificateStatementScalar(pool.ContextDigest, pool.ProposerID, pool.Digest)
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
		localShare, signErr := s.controlSigner.SignShare(s.cfg.LocalNode, cvPoolCertScalarDomain, statement)
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
	shareWire, err := cvPoolCertificateShareScalarCanonicalBytes(&cvPoolCertificateShareScalar{
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
		_ = s.sendAsync(pool.ProposerID, cvTagPoolCertShareScalar, shareWire, nil)
	}
}

func (s *cvAPDBNetworkServiceScalar) handlePoolCertificateShare(msg Message) {
	share, err := cvDecodePoolCertificateShareScalar(msg.Body)
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
	statement, err := cvPoolCertificateStatementScalar(s.cfg.ExpectedContext, share.ProposerID, share.PoolDigest)
	s.mu.Unlock()
	if err != nil || !s.controlSigner.VerifyShare(msg.From, cvPoolCertScalarDomain, statement, share.Signature) {
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
		cvNotifyAPDBScalar(slot.sharesReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handlePoolCertificate(msg Message) {
	s.mu.Lock()
	if slot := s.poolSlots[msg.From]; slot != nil && slot.state.certSeen && bytes.Equal(slot.certWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	certificate, err := cvDecodePoolCertificateScalar(msg.Body)
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
	pool, err := cvDecodePoolScalar(poolWire, s.cfg.Params)
	if err != nil || pool.ProposerID != msg.From || cvVerifyPoolCertificateScalar(pool, certificate, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if slot.state.observeCertificate(certificate) == nil {
		slot.certWire = append([]byte(nil), msg.Body...)
		cvNotifyAPDBScalar(slot.certReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handleValidationRequest(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil || s.cfg.Validators == nil {
		return
	}
	requestKey := fmt.Sprintf("%d:%x", msg.From, hashBytes(msg.Body))
	s.mu.Lock()
	verifiedKey := s.validationRequestStatements[requestKey]
	localShareWire := append([]byte(nil), s.validationLocalShareWires[verifiedKey]...)
	_, inFlightFast := s.validationInFlight[verifiedKey]
	var cachedRequest *cvValidationRequestScalar
	var cachedCanonical []byte
	if verifiedKey != "" {
		if record := s.validationRecords[verifiedKey]; record != nil && bytes.Equal(record.requestWire, msg.Body) && record.request != nil {
			cachedRequest = record.request
			cachedCanonical = record.requestWire
		}
	}
	s.mu.Unlock()
	if len(localShareWire) != 0 {
		_ = s.sendPriorityAsync(msg.From, cvTagValidationSignatureScalar, localShareWire, nil)
		return
	}
	if verifiedKey != "" && inFlightFast {
		return
	}
	request, canonical := cachedRequest, cachedCanonical
	if request == nil {
		var err error
		request, canonical, err = cvDecodeValidationRequestScalarWithCanonical(msg.Body, s.cfg.Params)
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
	statement, err := cvValidationStatementScalar(validatorSample, &request.Header)
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
		if err := s.validateKnownComponentRefsScalar(request.Pool.Components); err != nil {
			return
		}
		if err := cvValidateValidationRequestPublicAfterComponentValidationScalarWithCanonical(request, canonical,
			s.cfg.ExpectedContext, s.cfg.Params, eligible, s.apdbSigner, s.controlSigner, s.coinSigner); err != nil {
			return
		}
		s.mu.Lock()
		record = s.validationRecords[key]
		if record == nil {
			record = &cvValidationRecordScalar{
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
		if !cvReserveValidationStatementScalar(
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
			_ = s.sendPriorityAsync(request.Header.ProposerID, cvTagValidationSignatureScalar, localShareWire, nil)
		} else {
			_ = s.sendValidationSignatureScalar(request.Header.ProposerID, statement, localShare)
		}
		return
	}
	if isValidator && !inFlight {
		go s.validateAndSignAggregate(request, statement, key)
	}
}

func (s *cvAPDBNetworkServiceScalar) validateAndSignAggregate(
	request *cvValidationRequestScalar, statement []byte, key string,
) {
	defer func() {
		s.mu.Lock()
		delete(s.validationInFlight, key)
		s.mu.Unlock()
	}()
	leaves, err := s.loadValidationLeavesScalar(request)
	if err != nil {
		return
	}
	aggregatePayload, _, err := s.recoverComponentForPurpose(s.ctx, &request.ARC, func(recovered []byte) error {
		digest, digestErr := cvAggregatePayloadDigestScalar(recovered)
		if digestErr != nil || !bytes.Equal(digest, request.Header.PayloadDigest) {
			return fmt.Errorf("CV V2 validation aggregate payload mismatch")
		}
		return nil
	}, cvRecoveryValidatorAggregateScalar, -1)
	if err != nil {
		return
	}
	aggregate, err := cvAVerVerifiedScalar(aggregatePayload, leaves, s.cfg.LeafContext, s.cfg.Params)
	if err != nil || cvVerifyAggregateHeaderPayloadScalar(&request.Header, aggregatePayload, aggregate) != nil {
		return
	}
	if err := s.rememberVerifiedAggregatePayloadScalar(request.ARC.InstanceDigest, request.ARC.Root, aggregatePayload); err != nil {
		return
	}
	s.mu.Lock()
	validatorSample := append([]int(nil), s.validatorSample...)
	reservedStatement := append([]byte(nil), s.validationOneShot[request.Header.ProposerID]...)
	s.mu.Unlock()
	if !bytes.Equal(reservedStatement, statement) {
		return
	}
	signature, err := cvSignValidationScalar(s.cfg.LocalNode, &request.Header, validatorSample, s.cfg.Validators)
	if err != nil {
		return
	}
	shareWire, err := cvValidationSignatureScalarCanonicalBytes(
		&cvValidationSignatureScalar{Statement: statement, Signature: signature},
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
	_ = s.sendPriorityAsync(request.Header.ProposerID, cvTagValidationSignatureScalar, shareWire, nil)
}

func (s *cvAPDBNetworkServiceScalar) sendValidationSignatureScalar(
	proposer int, statement, signature []byte,
) error {
	shareWire, err := cvValidationSignatureScalarCanonicalBytes(
		&cvValidationSignatureScalar{Statement: statement, Signature: signature},
	)
	if err != nil {
		return err
	}
	// Prioritize verified threshold shares over bulk recovery traffic.
	return s.sendPriorityAsync(proposer, cvTagValidationSignatureScalar, shareWire, nil)
}

func (s *cvAPDBNetworkServiceScalar) loadValidationLeavesScalar(
	request *cvValidationRequestScalar,
) ([]*cvLeafScalar, error) {
	if request == nil || len(request.SelectedIndices) != s.cfg.Params.componentCount {
		return nil, fmt.Errorf("invalid CV V2 validation leaf selection")
	}
	leaves := make([]*cvLeafScalar, len(request.SelectedIndices))
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
				leaves[index], errs[index] = s.verifiedComponentLeafScalar(
					s.ctx, request.Pool.Components[poolIndex], cvRecoveryValidatorComponentScalar,
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

func cvReserveValidationStatementScalar(reservations map[int][]byte, proposer int, statement []byte) bool {
	if reservations == nil || proposer < 0 || len(statement) != 32 {
		return false
	}
	if previous, exists := reservations[proposer]; exists {
		return bytes.Equal(previous, statement)
	}
	reservations[proposer] = append([]byte(nil), statement...)
	return true
}

func (s *cvAPDBNetworkServiceScalar) handleValidationSignature(msg Message) {
	wireDigest := string(hashBytes(msg.Body))
	s.mu.Lock()
	if sender, ok := s.validationSignatureWires[wireDigest]; ok && sender == msg.From {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	value, err := cvDecodeValidationSignatureScalar(msg.Body)
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
	valid := cvVerifyValidatorSignatureScalar(&publicKey,
		cvValidationCertificateScalarDomain, value.Statement, value.Signature)
	s.recordValidationProfileScalar(0, 0, time.Since(verifyStarted), 0)
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
		cvNotifyAPDBScalar(pending.ready)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handleValidationResult(msg Message) {
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
	result, err := cvDecodeValidationResultScalar(msg.Body, validatorSample)
	if err != nil {
		return
	}
	s.mu.Lock()
	record := s.validationRecords[string(result.Statement)]
	if record == nil || len(record.requestWire) == 0 {
		s.mu.Unlock()
		return
	}
	request := record.request
	recordStatement := append([]byte(nil), record.statement...)
	requestWire := append([]byte(nil), record.requestWire...)
	s.mu.Unlock()
	if request == nil {
		request, err = cvDecodeValidationRequestScalar(requestWire, s.cfg.Params)
	}
	if err != nil || request.Header.ProposerID != msg.From {
		return
	}
	if len(recordStatement) != 0 {
		if !bytes.Equal(recordStatement, result.Statement) {
			return
		}
		if cvVerifyValidationCertificateScalarWithStatement(&result.Certificate, recordStatement, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
			return
		}
	} else {
		wantStatement, statementErr := cvValidationStatementScalar(validatorSample, &request.Header)
		if statementErr != nil || !bytes.Equal(wantStatement, result.Statement) {
			return
		}
		if cvVerifyValidationCertificateScalar(&result.Certificate, &request.Header, validatorSample,
			s.cfg.Params.validatorThreshold, s.cfg.Validators) != nil {
			return
		}
	}
	s.mu.Lock()
	record.resultWire = append([]byte(nil), msg.Body...)
	record.result = result
	if s.validationResultWires == nil {
		s.validationResultWires = make(map[string]cvValidationResultWireSeenScalar)
	}
	if len(s.validationResultWires) < 256 {
		s.validationResultWires[wireDigest] = cvValidationResultWireSeenScalar{
			sender: msg.From, statement: string(result.Statement),
		}
	}
	cvNotifyAPDBScalar(record.resultReady)
	s.certifiedValidation[request.Header.ProposerID] = &cvCertifiedValidationScalar{request: request, certificate: &result.Certificate}
	cvNotifyAPDBScalar(s.certifiedReadyLocked(request.Header.ProposerID))
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handleDecisionShare(msg Message) {
	share, err := cvDecodeDecisionShareScalar(msg.Body)
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
			localShareWire, _ = cvDecisionShareScalarCanonicalBytes(
				&cvDecisionShareScalar{Statement: share.Statement, Signature: localShare},
			)
		}
		if len(localShareWire) != 0 {
			_ = s.sendPriorityAsync(msg.From, cvTagDecisionShareScalar, localShareWire, nil)
		}
		return
	}
	if !s.controlSigner.VerifyShare(
		msg.From, cvDecisionCertificateScalarDomain, share.Statement, share.Signature,
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
			cvNotifyAPDBScalar(pending.ready)
		}
	}
	s.mu.Unlock()
	if len(localShare) != 0 {
		if len(localShareWire) == 0 {
			localShareWire, _ = cvDecisionShareScalarCanonicalBytes(
				&cvDecisionShareScalar{Statement: share.Statement, Signature: localShare},
			)
		}
		if len(localShareWire) != 0 {
			_ = s.sendPriorityAsync(msg.From, cvTagDecisionShareScalar, localShareWire, nil)
		}
	}
}

func (s *cvAPDBNetworkServiceScalar) handleHandoff(msg Message) {
	isOld := cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.OldRoster)
	isNew := cvMemberInRosterScalar(s.cfg.LocalNode, s.cfg.NewRoster)
	if !isOld && !isNew {
		return
	}
	s.mu.Lock()
	if len(s.verifiedHandoffWire) != 0 && bytes.Equal(s.verifiedHandoffWire, msg.Body) {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	handoff, err := cvDecodeHandoffScalar(msg.Body)
	if err != nil || cvVerifyDecodedHandoffScalar(handoff, s.cfg.ExpectedContext, s.apdbSigner, s.controlSigner) != nil {
		return
	}
	s.mu.Lock()
	if len(s.verifiedHandoffWire) == 0 {
		s.verifiedHandoffWire = append([]byte(nil), msg.Body...)
	}
	if isOld {
		statement, statementErr := cvDecisionStatementScalar(
			s.cfg.ExpectedContext, &handoff.Header, &handoff.ARC,
		)
		if statementErr == nil {
			key := string(statement)
			if len(s.decisionCertificates[key]) == 0 {
				s.decisionCertificates[key] = append([]byte(nil), handoff.DecCert...)
			}
			if pending := s.pendingDecisions[key]; pending != nil && len(pending.certificate) == 0 {
				pending.certificate = append([]byte(nil), handoff.DecCert...)
				cvNotifyAPDBScalar(pending.ready)
			}
		}
	}
	if isNew && len(s.acceptedHandoff) == 0 {
		s.acceptedHandoff = append([]byte(nil), msg.Body...)
		cvNotifyAPDBScalar(s.handoffReady)
	}
	s.mu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) handleAggregateShare(msg Message) {
	if s.cfg.LeafContext == nil || s.cfg.Receivers == nil {
		return
	}
	// The aggregate digest is the fixed first field after the domain. Decode it
	// only after locating a currently active aggregate, so unknown digests are
	// never retained.
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvAggregateShareWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvAggregateShareWireDomainScalar)) {
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
		_ = s.sendAsync(msg.From, cvTagAggregateShareScalar, localWire, nil)
		return
	}
	output, err := cvDecodeScalarShareOutputScalar(
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
			cvNotifyAPDBScalar(pending.ready)
		}
		s.mu.Unlock()
	}
	_ = s.sendAsync(msg.From, cvTagAggregateShareScalar, localWire, nil)
}

func (s *cvAPDBNetworkServiceScalar) send(to int, tag string, payload []byte) error {
	_, err := s.sendMeasured(to, tag, payload)
	return err
}

func (s *cvAPDBNetworkServiceScalar) sendMeasured(to int, tag string, payload []byte) (int, error) {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, int(s.cfg.Epoch), payload)
	if err != nil {
		return 0, err
	}
	return s.sendEnvelopeMeasuredScalar(to, tag, envelope)
}

func (s *cvAPDBNetworkServiceScalar) sendEnvelopeMeasuredScalar(to int, tag string, envelope []byte) (int, error) {
	wire, err := s.auth.seal(s.cfg.LocalNode, to, tag, envelope)
	if err != nil {
		return 0, err
	}
	message := Message{From: s.cfg.LocalNode, To: to, Tag: tag, Body: wire}
	if err := s.transport.Send(message); err != nil {
		return 0, err
	}
	wireBytes := tcpMessageFrameFixedBytes + len(tag) + len(wire)
	s.recordTagBytesScalar(tag, true, wireBytes)
	return wireBytes, nil
}

// sendFanoutMeasuredScalar bounds goroutine count while allowing independent TCP
// destinations to make progress concurrently. It preserves the recipient set
// and returns only after every attempted send has completed.
func (s *cvAPDBNetworkServiceScalar) sendFanoutMeasuredScalar(
	recipients []int, excluded int, tag string, payload []byte,
) []cvFanoutSendResultScalar {
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
		results := make([]cvFanoutSendResultScalar, 0, len(targets))
		for _, target := range targets {
			results = append(results, cvFanoutSendResultScalar{recipient: target, err: err})
		}
		return results
	}
	parallel := cvFanoutMaxParallelScalar
	if parallel > len(targets) {
		parallel = len(targets)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultScalar, len(targets))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				wireBytes, err := s.sendEnvelopeMeasuredScalar(target, tag, envelope)
				results <- cvFanoutSendResultScalar{recipient: target, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultScalar, 0, len(targets))
	for result := range results {
		out = append(out, result)
	}
	return out
}

// sendPriorityFanoutScalar routes small threshold/control messages through the
// priority lane. The authenticated envelope and byte accounting remain the
// same as sendFanoutMeasuredScalar; only queue selection changes.
func (s *cvAPDBNetworkServiceScalar) sendPriorityFanoutScalar(recipients []int, excluded int, tag string, payload []byte) {
	for _, recipient := range recipients {
		if recipient == excluded {
			continue
		}
		_ = s.sendPriorityAsync(recipient, tag, payload, nil)
	}
}

// sendRecipientPayloadFanoutMeasuredScalar is the bounded-fanout equivalent for
// authenticated messages whose payload is intentionally recipient-specific.
func (s *cvAPDBNetworkServiceScalar) sendRecipientPayloadFanoutMeasuredScalar(
	recipients []int, tag string, payloads map[int][]byte,
) []cvFanoutSendResultScalar {
	if len(recipients) == 0 || len(payloads) == 0 {
		return nil
	}
	parallel := cvFanoutMaxParallelScalar
	if parallel > len(recipients) {
		parallel = len(recipients)
	}
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultScalar, len(recipients))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for recipient := range jobs {
				payload := payloads[recipient]
				wireBytes, err := s.sendMeasured(recipient, tag, payload)
				results <- cvFanoutSendResultScalar{recipient: recipient, wireBytes: wireBytes, err: err}
			}
		}()
	}
	for _, recipient := range recipients {
		jobs <- recipient
	}
	close(jobs)
	workers.Wait()
	close(results)
	out := make([]cvFanoutSendResultScalar, 0, len(recipients))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (s *cvAPDBNetworkServiceScalar) sendRecipientPayloadFanoutContextMeasuredScalar(
	ctx context.Context, recipients []int, tag string, payloads map[int][]byte,
) []cvFanoutSendResultScalar {
	if ctx == nil || len(recipients) == 0 || len(payloads) == 0 {
		return nil
	}
	parallel := min(cvFanoutMaxParallelScalar, len(recipients))
	jobs := make(chan int)
	results := make(chan cvFanoutSendResultScalar, len(recipients))
	var workers sync.WaitGroup
	for range parallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for recipient := range jobs {
				wireBytes, err := s.sendMeasured(recipient, tag, payloads[recipient])
				results <- cvFanoutSendResultScalar{recipient: recipient, wireBytes: wireBytes, err: err}
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
	out := make([]cvFanoutSendResultScalar, 0, len(recipients))
	for result := range results {
		out = append(out, result)
	}
	return out
}

func (s *cvAPDBNetworkServiceScalar) recordTagBytesScalar(tag string, sent bool, n int) {
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

func (s *cvAPDBNetworkServiceScalar) recordDispersalBytesScalar(aggregate, sent bool, n int) {
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

func (s *cvAPDBNetworkServiceScalar) recordRecoveryBytesScalar(purpose cvRecoveryPurposeScalar, sent bool, n int) {
	if s == nil || purpose == cvRecoveryUnclassifiedScalar || n <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvRecoveryProposerCatalogScalar:
		if sent {
			s.experimentMetrics.proposerRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.proposerRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorComponentScalar:
		if sent {
			s.experimentMetrics.validatorComponentRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorComponentRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryValidatorAggregateScalar:
		if sent {
			s.experimentMetrics.validatorAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.validatorAggregateRecoveryRecvBytes += uint64(n)
		}
	case cvRecoveryNewAggregateScalar:
		if sent {
			s.experimentMetrics.newAggregateRecoverySentBytes += uint64(n)
		} else {
			s.experimentMetrics.newAggregateRecoveryRecvBytes += uint64(n)
		}
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordRecoveryLatencyScalar(purpose cvRecoveryPurposeScalar, elapsed time.Duration) {
	if s == nil || purpose == cvRecoveryUnclassifiedScalar || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if purpose == cvRecoveryProposerCatalogScalar {
		s.experimentMetrics.proposerRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorComponentScalar {
		s.experimentMetrics.validatorComponentRecoveryLatency += elapsed
	} else if purpose == cvRecoveryValidatorAggregateScalar {
		s.experimentMetrics.validatorAggregateRecoveryLatency += elapsed
	} else if purpose == cvRecoveryNewAggregateScalar {
		s.experimentMetrics.newAggregateRecoveryLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordComponentRecoveryResponseSentScalar(payload, hints, fragment int) {
	if s == nil || payload < 0 || hints < 0 || fragment < 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.dealerPayloadSentBytes += uint64(payload)
	s.experimentMetrics.dealerHintSentBytes += uint64(hints)
	s.experimentMetrics.holderFragmentSentBytes += uint64(fragment)
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordComponentRecoveryLateRecvBytesScalar(wireBytes int) {
	if s == nil || wireBytes <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.componentRecoveryLateRecvBytes += uint64(wireBytes)
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordComponentDirectGraceWaitScalar(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.componentDirectGraceWait += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordCoinFanoutLatencyScalar(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.coinFanoutLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordAggregateOfferSendLatencyScalar(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	s.experimentMetrics.aggregateOfferSendLatency += elapsed
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordCandidateFanoutAttemptScalar(wait time.Duration, retry bool) {
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

func (s *cvAPDBNetworkServiceScalar) recordCandidateFanoutPeerLatencyScalar(elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	if elapsed > s.experimentMetrics.candidateFanoutMaxPeerLatency {
		s.experimentMetrics.candidateFanoutMaxPeerLatency = elapsed
	}
	s.experimentMu.Unlock()
}

type cvCertificatePurposeScalar uint8

const (
	cvCertificateARCScalar cvCertificatePurposeScalar = iota + 1
	cvCertificateValidationScalar
	cvCertificateDecisionScalar
)

func (s *cvAPDBNetworkServiceScalar) recordCertificateFormationScalar(purpose cvCertificatePurposeScalar, elapsed time.Duration) {
	if s == nil || elapsed <= 0 {
		return
	}
	s.experimentMu.Lock()
	switch purpose {
	case cvCertificateARCScalar:
		s.experimentMetrics.arcFormationLatency += elapsed
	case cvCertificateValidationScalar:
		s.experimentMetrics.validationCertificateLatency += elapsed
	case cvCertificateDecisionScalar:
		s.experimentMetrics.decisionCertificateLatency += elapsed
	}
	s.experimentMu.Unlock()
}

func (s *cvAPDBNetworkServiceScalar) recordValidationProfileScalar(
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

func (s *cvAPDBNetworkServiceScalar) experimentMetricsScalar() cvServiceExperimentMetricsScalar {
	if s == nil {
		return cvServiceExperimentMetricsScalar{}
	}
	s.experimentMu.Lock()
	defer s.experimentMu.Unlock()
	metrics := s.experimentMetrics
	metrics.tagSentBytes = cloneUint64MapScalar(metrics.tagSentBytes)
	metrics.tagRecvBytes = cloneUint64MapScalar(metrics.tagRecvBytes)
	return metrics
}

func cloneUint64MapScalar(input map[string]uint64) map[string]uint64 {
	output := make(map[string]uint64, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func (s *cvAPDBNetworkServiceScalar) registerLock(key string, pending *cvAPDBPendingLockScalar) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pendingLocks[key]; exists {
		return fmt.Errorf("CV V2 LockPD already active for instance")
	}
	s.pendingLocks[key] = pending
	return nil
}

func (s *cvAPDBNetworkServiceScalar) unregisterLock(key string, pending *cvAPDBPendingLockScalar) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingLocks[key] == pending {
		delete(s.pendingLocks, key)
	}
}

func (s *cvAPDBNetworkServiceScalar) lookupLock(key string) *cvAPDBPendingLockScalar {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocks[key]
}

func (s *cvAPDBNetworkServiceScalar) registerRecovery(key string, pending *cvAPDBPendingRecoveryScalar, aggregate bool) error {
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

func (s *cvAPDBNetworkServiceScalar) unregisterRecovery(key string, pending *cvAPDBPendingRecoveryScalar, aggregate bool) {
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

func (s *cvAPDBNetworkServiceScalar) lookupRecovery(key string, aggregate bool) *cvAPDBPendingRecoveryScalar {
	s.mu.Lock()
	defer s.mu.Unlock()
	if aggregate {
		return s.pendingAggregates[key]
	}
	return s.pendingComponents[key]
}

func cvNotifyAPDBScalar(ready chan struct{}) {
	select {
	case ready <- struct{}{}:
	default:
	}
}
