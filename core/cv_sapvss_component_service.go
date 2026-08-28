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

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const (
	cvComponentInitDomain            = "ARL-CV-sAPVSS/component-init"
	cvComponentAckDomain             = "ARL-CV-sAPVSS/component-ack"
	cvComponentGetDomain             = "ARL-CV-sAPVSS/component-get"
	cvComponentDealerSignatureDomain = "RL_CV_COMPONENT_DEALER"
)

type cvComponentInit struct {
	artifactWire []byte
	dealerSig    []byte
}

type cvComponentAck struct {
	dealer     int
	holder     int
	leafDigest []byte
	signature  []byte
}

type cvComponentGet struct {
	dealer     int
	leafDigest []byte
}

type cvPendingComponentLeaf struct {
	allowed    map[int]struct{}
	descriptor *cvComponentDescriptor
	values     chan cvComponentShard
}

type cvPendingComponentACKs struct {
	values   chan cvComponentAck
	accepted map[int]struct{}
}

type cvComponentRetrievalCall struct {
	done     chan struct{}
	accepted *cvVerifiedLeaf
	err      error
}

type cvPendingARCShare struct {
	values       chan cvARCShare
	certificates chan []byte
	accepted     map[int]struct{}
}

type cvPendingRecovery struct {
	rlo     *AggRLO
	allowed map[int]struct{}
	values  chan cvFreshShardArtifact
}

type cvReceivedReceipt struct {
	verified *cvVerifiedReceipt
}

type cvPendingReceiptExchange struct {
	agg           *cvAggregateTranscript
	receiverOrder []int
	values        chan cvReceivedReceipt
}

type cvReceiptPreparationCall struct {
	done    chan struct{}
	outputs *cvPreparedReceiptOutputs
	err     error
}

type apvssPendingLaneACKs struct {
	leaf   *cvLeaf
	values chan apvssLaneACK
}

type cvFreshArtifactStore interface {
	Put(sid string, epoch int, headerDigest []byte, holder int, shard []byte) error
	Read(sid string, epoch int, headerDigest []byte, holder int) ([]byte, error)
}

type cvComponentLeafCacheStore interface {
	Put(sid string, epoch, dealer, holder int, leafDigest, leaf []byte) error
	Read(sid string, epoch, dealer, holder int, leafDigest []byte) ([]byte, error)
}

type cvReconstructedLeafCacheJob struct {
	dealer     int
	leafDigest []byte
	leafWire   []byte
}

type cvComponentService struct {
	ctx                         context.Context
	cancel                      context.CancelFunc
	cfg                         Config
	leafCtx                     *cvLeafContext
	leafContextDigest           []byte
	localNode                   int
	transport                   agreementTransport
	networkAuth                 *cvNetworkAuthenticator
	store                       cvComponentLeafCacheStore
	shardStore                  *cvComponentShardStore
	freshStore                  cvFreshArtifactStore
	inbox                       <-chan Message
	oldMembers                  map[int]struct{}
	oldOrder                    []int
	localOldIndex               int
	receiverOrder               []int
	receiverIndex               map[int]int
	localReceiverSecrets        map[int]fr.Element
	localReceiverSigningSecrets map[int]fr.Element

	mu                           sync.Mutex
	aggregateBuildMu             sync.Mutex
	freshPersistMu               sync.Mutex
	pendingACKs                  map[string]*cvPendingComponentACKs
	pendingComponentStatements   map[string][]byte
	pendingLeaves                map[string]*cvPendingComponentLeaf
	componentRetrievals          map[string]*cvComponentRetrievalCall
	pendingARCs                  map[string]*cvPendingARCShare
	pendingRecoveries            map[string]*cvPendingRecovery
	pendingReceipts              *cvPendingReceiptExchange
	receiptPreparations          map[string]*cvReceiptPreparationCall
	pendingLaneACKs              map[string]*apvssPendingLaneACKs
	processingOffers             map[string]struct{}
	processingLaneOffers         map[string]struct{}
	componentStatementByDealer   map[int][]byte
	componentACKWires            map[string][]byte
	componentInitACKWires        map[string][]byte
	localARCShareByHeader        map[string][]byte
	localARCShareWires           map[string][]byte
	publishedReadyRoots          map[string]struct{}
	acceptedReadyRoots           map[string]struct{}
	acceptedReadyWires           map[int][]byte
	readyDescriptorsByRoot       map[string][]*cvComponentDescriptor
	pendingReadyCertificates     map[string]*cvComponentReadyCertificate
	pendingReadyWireDigests      map[string]struct{}
	pendingReadyOffers           map[string][]Message
	eligibilityShares            map[string]map[int][]byte
	eligibilityUpdates           chan struct{}
	readyCandidates              chan []*cvComponentDescriptor
	verifiedLeaves               map[string]*cvVerifiedLeaf
	aggregateCertificates        map[string][]byte
	verifiedAggregateCandidates  map[string]*cvVerifiedAggregateCandidate
	publishedCertifiedCandidates map[string]struct{}
	certifiedCandidates          chan *cvMaterializedAggregate
	verifiedAggregates           map[string]*cvAggregateTranscript
	verifiedAggregatesByRoot     map[string]*cvAggregateTranscript
	// verifiedDispersals is keyed by aggregate digest so candidates with
	// different ReadyCert roots but identical FirstKValid outputs share RS work.
	verifiedDispersals         map[string]*cvAggregateDispersal
	resolvedAggregateManifests map[string][]*cvComponentDescriptor
	persistedFreshArtifacts    map[string]struct{}
	componentDescriptors       map[int]*cvComponentDescriptor
	componentDescriptorWires   map[int][]byte
	laneOfferQueue             chan Message
	reconstructedCacheMode     string
	reconstructedCacheQueue    chan cvReconstructedLeafCacheJob
	laneWorkerWG               sync.WaitGroup
	backgroundWG               sync.WaitGroup
	done                       chan struct{}
}

func newCVComponentService(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContext,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouter,
	store *cvComponentLeafStore,
) (*cvComponentService, error) {
	return newCVComponentServiceWithReceivers(
		ctx, cfg, leafContext, localNode, transport, router, store, nil, nil, nil,
	)
}

func newCVComponentServiceWithReceivers(
	ctx context.Context,
	cfg Config,
	leafContext *cvLeafContext,
	localNode int,
	transport agreementTransport,
	router *cvSAPVSSRouter,
	store *cvComponentLeafStore,
	receiverOrder []int,
	localReceiverSecrets map[int]fr.Element,
	localReceiverSigningSecrets ...map[int]fr.Element,
) (*cvComponentService, error) {
	signingSecrets := localReceiverSecrets
	if len(localReceiverSigningSecrets) > 1 {
		return nil, fmt.Errorf("multiple local APVSS signing registries")
	}
	if len(localReceiverSigningSecrets) == 1 {
		signingSecrets = localReceiverSigningSecrets[0]
	}
	c := NormalizeConfig(cfg)
	if ctx == nil || leafContext == nil || transport == nil || router == nil || store == nil {
		return nil, fmt.Errorf("invalid CV-sAPVSS component service configuration")
	}
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if err := validateAPVSSProductionAdmission(c); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if _, ok := nodeSet(c.OldCommittee)[localNode]; !ok ||
		string(leafContext.sessionID) != c.SID || int(leafContext.epoch) != c.Epoch {
		return nil, fmt.Errorf("CV-sAPVSS component service context mismatch")
	}
	if err := cvValidateLeafContext(leafContext); err != nil {
		return nil, err
	}
	oldOrder := sortedUnique(c.OldCommittee)
	localOldIndex := sort.SearchInts(oldOrder, localNode)
	if localOldIndex >= len(oldOrder) || oldOrder[localOldIndex] != localNode {
		return nil, fmt.Errorf("CV-sAPVSS local component holder is outside old roster")
	}
	freshStore, err := newCVFreshShardStore(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	shardStore, err := newCVComponentShardStore(c.ArtifactCacheDir)
	if err != nil {
		return nil, err
	}
	receiverIndex := make(map[int]int, len(receiverOrder))
	if len(receiverOrder) > 0 {
		expectedOrder := sortedUnique(c.NewCommittee)
		if len(receiverOrder) != len(expectedOrder) {
			return nil, fmt.Errorf("APVSS receiver roster length mismatch")
		}
		for i := range receiverOrder {
			if receiverOrder[i] != expectedOrder[i] {
				return nil, fmt.Errorf("APVSS receiver roster order mismatch")
			}
			receiverIndex[receiverOrder[i]] = i + 1
		}
	}
	actorIDs := []int{localNode}
	localSecrets := make(map[int]fr.Element, len(localReceiverSecrets))
	localSigningSecrets := make(map[int]fr.Element, len(signingSecrets))
	for receiverID, secret := range localReceiverSecrets {
		signingSecret, signingOK := signingSecrets[receiverID]
		if _, ok := receiverIndex[receiverID]; !ok || secret.IsZero() || !signingOK || signingSecret.IsZero() || signingSecret.Equal(&secret) {
			return nil, fmt.Errorf("invalid local APVSS receiver %d", receiverID)
		}
		localSecrets[receiverID] = secret
		localSigningSecrets[receiverID] = signingSecret
		actorIDs = append(actorIDs, receiverID)
	}
	actorIDs = sortedUnique(actorIDs)
	var networkAuth *cvNetworkAuthenticator
	if c.StrictNetwork {
		networkAuth, err = newCVNetworkAuthenticator(
			c.runtime.lockSigner, receiverOrder, leafContext.receiverPublicKeys, localSecrets,
		)
		if err != nil {
			return nil, err
		}
	}
	serviceCtx, cancel := context.WithCancel(ctx)
	mergedInbox := make(chan Message, len(actorIDs)*64)
	laneQueueSize := len(c.OldCommittee) * len(localSecrets)
	if laneQueueSize < len(c.OldCommittee) {
		laneQueueSize = len(c.OldCommittee)
	}
	if laneQueueSize < 1 {
		laneQueueSize = 1
	}
	service := &cvComponentService{
		ctx:                          serviceCtx,
		cancel:                       cancel,
		cfg:                          c,
		leafCtx:                      leafContext,
		leafContextDigest:            append([]byte(nil), cvLeafContextDigest(leafContext)...),
		localNode:                    localNode,
		transport:                    transport,
		networkAuth:                  networkAuth,
		store:                        store,
		shardStore:                   shardStore,
		freshStore:                   freshStore,
		inbox:                        mergedInbox,
		oldMembers:                   nodeSet(c.OldCommittee),
		oldOrder:                     oldOrder,
		localOldIndex:                localOldIndex,
		receiverOrder:                append([]int(nil), receiverOrder...),
		receiverIndex:                receiverIndex,
		localReceiverSecrets:         localSecrets,
		localReceiverSigningSecrets:  localSigningSecrets,
		pendingACKs:                  make(map[string]*cvPendingComponentACKs),
		pendingComponentStatements:   make(map[string][]byte),
		pendingLeaves:                make(map[string]*cvPendingComponentLeaf),
		componentRetrievals:          make(map[string]*cvComponentRetrievalCall),
		pendingARCs:                  make(map[string]*cvPendingARCShare),
		pendingRecoveries:            make(map[string]*cvPendingRecovery),
		receiptPreparations:          make(map[string]*cvReceiptPreparationCall),
		pendingLaneACKs:              make(map[string]*apvssPendingLaneACKs),
		processingOffers:             make(map[string]struct{}),
		processingLaneOffers:         make(map[string]struct{}),
		componentStatementByDealer:   make(map[int][]byte),
		componentACKWires:            make(map[string][]byte),
		componentInitACKWires:        make(map[string][]byte),
		localARCShareByHeader:        make(map[string][]byte),
		localARCShareWires:           make(map[string][]byte),
		publishedReadyRoots:          make(map[string]struct{}),
		acceptedReadyRoots:           make(map[string]struct{}),
		acceptedReadyWires:           make(map[int][]byte),
		readyDescriptorsByRoot:       make(map[string][]*cvComponentDescriptor),
		pendingReadyCertificates:     make(map[string]*cvComponentReadyCertificate),
		pendingReadyWireDigests:      make(map[string]struct{}),
		pendingReadyOffers:           make(map[string][]Message),
		eligibilityShares:            make(map[string]map[int][]byte),
		eligibilityUpdates:           make(chan struct{}, 1),
		readyCandidates:              make(chan []*cvComponentDescriptor, len(c.OldCommittee)+1),
		verifiedLeaves:               make(map[string]*cvVerifiedLeaf),
		aggregateCertificates:        make(map[string][]byte),
		verifiedAggregateCandidates:  make(map[string]*cvVerifiedAggregateCandidate),
		publishedCertifiedCandidates: make(map[string]struct{}),
		certifiedCandidates:          make(chan *cvMaterializedAggregate, len(c.OldCommittee)+1),
		verifiedAggregates:           make(map[string]*cvAggregateTranscript),
		verifiedAggregatesByRoot:     make(map[string]*cvAggregateTranscript),
		verifiedDispersals:           make(map[string]*cvAggregateDispersal),
		resolvedAggregateManifests:   make(map[string][]*cvComponentDescriptor),
		persistedFreshArtifacts:      make(map[string]struct{}),
		componentDescriptors:         make(map[int]*cvComponentDescriptor),
		componentDescriptorWires:     make(map[int][]byte),
		laneOfferQueue:               make(chan Message, laneQueueSize),
		reconstructedCacheMode:       cvReconstructedLeafCacheMode(),
		done:                         make(chan struct{}),
	}
	if service.reconstructedCacheMode == "async" {
		service.reconstructedCacheQueue = make(
			chan cvReconstructedLeafCacheJob, cvReconstructedLeafCacheQueueCapacity(),
		)
		service.backgroundWG.Add(1)
		go service.runReconstructedLeafCacheWriter()
	}
	for _, actorID := range actorIDs {
		source, receiveErr := router.Receive(actorID)
		if receiveErr != nil {
			cancel()
			return nil, receiveErr
		}
		go func(inbox <-chan Message) {
			for {
				select {
				case <-serviceCtx.Done():
					return
				case msg, ok := <-inbox:
					if !ok {
						return
					}
					select {
					case mergedInbox <- msg:
					case <-serviceCtx.Done():
						return
					}
				}
			}
		}(source)
	}
	laneWorkers := cvLaneWorkers(laneQueueSize)
	if len(localSecrets) == 0 {
		laneWorkers = 0
	}
	service.laneWorkerWG.Add(laneWorkers)
	for worker := 0; worker < laneWorkers; worker++ {
		go service.runLaneOfferWorker()
	}
	go service.run()
	return service, nil
}

func (s *cvComponentService) Close() error {
	if s == nil {
		return nil
	}
	s.cancel()
	<-s.done
	s.laneWorkerWG.Wait()
	s.backgroundWG.Wait()
	return nil
}

func (s *cvComponentService) oldCommitteeOrder() []int {
	if s != nil && len(s.oldOrder) != 0 {
		return s.oldOrder
	}
	if s == nil {
		return nil
	}
	return sortedUnique(s.cfg.OldCommittee)
}

func (s *cvComponentService) localOldCommitteeIndex() int {
	order := s.oldCommitteeOrder()
	if len(s.oldOrder) != 0 && s.localOldIndex >= 0 && s.localOldIndex < len(order) &&
		order[s.localOldIndex] == s.localNode {
		return s.localOldIndex
	}
	return sort.SearchInts(order, s.localNode)
}

func (s *cvComponentService) CollectAPVSSLaneACKs(
	ctx context.Context,
	leaf *cvLeaf,
	witness *apvssDealerWitness,
) (*apvssLeafPrototype, error) {
	if ctx == nil || leaf == nil || witness == nil || leaf.dealerID != uint64(s.localNode) ||
		len(s.receiverOrder) != len(leaf.receivers) {
		return nil, fmt.Errorf("invalid APVSS lane ACK collection input")
	}
	if err := apvssValidateStructuralLeaf(s.leafCtx, leaf); err != nil {
		return nil, err
	}
	key := cvComponentKey(s.localNode, leaf.digest)
	pending := &apvssPendingLaneACKs{
		leaf: leaf, values: make(chan apvssLaneACK, len(s.receiverOrder)),
	}
	s.mu.Lock()
	if _, exists := s.pendingLaneACKs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("APVSS lane ACK collection already active")
	}
	s.pendingLaneACKs[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingLaneACKs, key)
		s.mu.Unlock()
	}()

	sent := s.sendAPVSSLaneOffers(leaf)
	threshold := len(s.receiverOrder) - s.leafCtx.sharingDegree
	if sent < threshold {
		return nil, fmt.Errorf("APVSS lane offer reached %d receivers, need %d", sent, threshold)
	}
	requiredACKs := threshold
	if s.cfg.APVSSBenchmarkWaitAllACKs {
		requiredACKs = len(s.receiverOrder)
	} else if s.cfg.APVSSBenchmarkFallbackCount > 0 {
		requiredACKs = len(s.receiverOrder) - s.cfg.APVSSBenchmarkFallbackCount
	}
	acks := make(map[int]apvssLaneACK, len(s.receiverOrder))
	for len(acks) < requiredACKs {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case ack := <-pending.values:
			acks[ack.receiverIndex] = ack
		}
	}
	assemble := func() (*apvssLeafPrototype, error) {
		ordered := make([]apvssLaneACK, 0, len(acks))
		for receiverIndex := 1; receiverIndex <= len(s.receiverOrder); receiverIndex++ {
			if ack, ok := acks[receiverIndex]; ok {
				ordered = append(ordered, ack)
			}
		}
		return apvssAssembleVerifiedPrototypeWithFallbackProfile(
			s.leafCtx, leaf, witness, ordered, s.cfg.APVSSFallbackProfile,
		)
	}
	if s.cfg.APVSSBenchmarkWaitAllACKs || s.cfg.APVSSBenchmarkFallbackCount > 0 {
		return assemble()
	}
	grace := cvAPVSSACKGrace()
	if grace <= 0 {
		return assemble()
	}
	timer := time.NewTimer(grace)
	defer timer.Stop()
	// This optimistic timer changes only performance: after it expires, the
	// existing exact fallback covers every receiver that has not ACKed.
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case ack := <-pending.values:
			acks[ack.receiverIndex] = ack
			if len(acks) == len(s.receiverOrder) {
				return assemble()
			}
		case <-timer.C:
			return assemble()
		}
	}
}

func cvAPVSSACKGrace() time.Duration {
	const defaultGrace = 500 * time.Millisecond
	raw := strings.TrimSpace(os.Getenv("RLADKR_APVSS_ACK_GRACE_MS"))
	if raw == "" {
		return defaultGrace
	}
	milliseconds, err := strconv.Atoi(raw)
	if err != nil || milliseconds < 0 {
		return defaultGrace
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func (s *cvComponentService) Disperse(ctx context.Context, leaf *cvLeaf) (*cvComponentDescriptor, error) {
	if ctx == nil || leaf == nil || leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("CV-sAPVSS component dealer does not match local node")
	}
	leafWire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		return nil, err
	}
	return s.disperseComponentWire(ctx, int(leaf.dealerID), leaf.digest, leafWire)
}

func (s *cvComponentService) DisperseAPVSS(
	ctx context.Context,
	prototype *apvssLeafPrototype,
) (*cvComponentDescriptor, error) {
	if ctx == nil || prototype == nil || prototype.leaf == nil ||
		prototype.leaf.dealerID != uint64(s.localNode) {
		return nil, fmt.Errorf("APVSS component dealer does not match local node")
	}
	leafWire, err := apvssLeafPrototypeCanonicalBytes(prototype)
	if err != nil {
		return nil, err
	}
	digest := hashBytes([]byte(apvssLeafDigestDomain), leafWire)
	if len(prototype.digest) > 0 && !bytes.Equal(prototype.digest, digest) {
		return nil, fmt.Errorf("APVSS component leaf digest mismatch")
	}
	prototype.digest = append([]byte(nil), digest...)
	return s.disperseComponentWire(ctx, int(prototype.leaf.dealerID), digest, leafWire)
}

func (s *cvComponentService) disperseComponentWire(
	ctx context.Context,
	dealer int,
	leafDigest, leafWire []byte,
) (*cvComponentDescriptor, error) {
	if ctx == nil || dealer != s.localNode || len(leafDigest) != 32 || len(leafWire) == 0 ||
		!bytes.Equal(leafDigest, cvComponentLeafPayloadDigest(leafWire)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component payload")
	}
	oldOrder := s.oldCommitteeOrder()
	dispersal, shards, err := cvDisperseComponent(
		leafWire, len(oldOrder), len(oldOrder)-2*s.cfg.FOld,
	)
	if err != nil {
		return nil, err
	}
	localIndex := s.localOldCommitteeIndex()
	if localIndex >= len(oldOrder) || oldOrder[localIndex] != s.localNode {
		return nil, fmt.Errorf("CV-sAPVSS local component holder is outside old roster")
	}
	localArtifactWire, err := cvComponentShardArtifactCanonicalBytes(&cvComponentShardArtifact{
		dealer: dealer, leafDigest: leafDigest, dispersal: *dispersal, shard: shards[localIndex],
	})
	if err != nil {
		return nil, err
	}
	if err := s.store.Put(s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, leafDigest, leafWire); err != nil {
		return nil, err
	}
	if err := s.shardStore.Put(s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, leafDigest, localArtifactWire); err != nil {
		return nil, err
	}
	statement, err := cvComponentStatementDigest(dealer, leafDigest, dispersal)
	if err != nil {
		return nil, err
	}
	if !s.claimComponentStatement(dealer, statement) {
		return nil, fmt.Errorf("CV-sAPVSS dealer attempted a conflicting component statement")
	}
	localHolderSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomain, statement,
	)
	if err != nil {
		return nil, err
	}
	dealerSig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentDealerSignatureDomain, statement,
	)
	if err != nil {
		return nil, err
	}
	key := cvComponentKey(dealer, leafDigest)
	pendingACKs := &cvPendingComponentACKs{
		values: make(chan cvComponentAck, len(s.cfg.OldCommittee)), accepted: make(map[int]struct{}, len(s.cfg.OldCommittee)),
	}
	s.mu.Lock()
	if _, exists := s.pendingACKs[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS component dispersal already active")
	}
	s.pendingACKs[key] = pendingACKs
	s.pendingComponentStatements[key] = append([]byte(nil), statement...)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pendingACKs, key)
		delete(s.pendingComponentStatements, key)
		s.mu.Unlock()
	}()

	sent := 0
	for index, holder := range oldOrder {
		if holder == s.localNode {
			continue
		}
		artifactWire, artifactErr := cvComponentShardArtifactCanonicalBytes(&cvComponentShardArtifact{
			dealer: dealer, leafDigest: leafDigest, dispersal: *dispersal, shard: shards[index],
		})
		if artifactErr != nil {
			continue
		}
		initWire, initErr := cvComponentInitCanonicalBytes(&cvComponentInit{artifactWire: artifactWire, dealerSig: dealerSig})
		if initErr != nil {
			continue
		}
		if s.send(holder, cvTagComponentInit, initWire) == nil {
			sent++
		}
	}
	threshold := len(s.cfg.OldCommittee) - s.cfg.FOld
	if sent+1 < threshold {
		return nil, fmt.Errorf("CV-sAPVSS component INIT reached %d holders, need %d", sent+1, threshold)
	}
	shares := map[int][]byte{s.localNode: append([]byte(nil), localHolderSig...)}
	for len(shares) < threshold {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case ack := <-pendingACKs.values:
			if _, duplicate := shares[ack.holder]; !duplicate {
				shares[ack.holder] = append([]byte(nil), ack.signature...)
			}
		}
	}
	certificate, err := s.cfg.runtime.lockSigner.Recover(
		cvComponentLockSignatureDomain, statement, shares,
	)
	if err != nil {
		return nil, err
	}
	descriptor := &cvComponentDescriptor{
		dealer: dealer, leafDigest: append([]byte(nil), leafDigest...),
		dispersal: *dispersal, certificate: certificate,
	}
	if err := cvValidateComponentDescriptor(s.cfg, descriptor); err != nil {
		return nil, err
	}
	descriptorWire, err := cvComponentDescriptorCanonicalBytes(descriptor)
	if err != nil {
		return nil, err
	}
	if err := s.acceptComponentDescriptorWire(descriptorWire); err != nil {
		return nil, err
	}
	s.sendMany(s.oldCommitteeOrder(), cvTagComponentCert, descriptorWire)
	return descriptor, nil
}

func (s *cvComponentService) CollectLocalComponentSet(
	ctx context.Context,
) ([]*cvComponentDescriptor, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS component collection context")
	}
	want := s.cfg.FOld + 1
	ready := len(s.cfg.OldCommittee) - s.cfg.FOld
	if s.cfg.Kappa != want || ready < want {
		return nil, fmt.Errorf("CV-sAPVSS component collection requires K=f_o+1")
	}
	s.maybePublishCanonicalReadyCertificate()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case selected := <-s.readyCandidates:
		return selected, nil
	}
}

func (s *cvComponentService) acceptComponentDescriptorWire(wire []byte) error {
	descriptor, err := cvDecodeAndValidateComponentDescriptor(s.cfg, wire)
	if err != nil {
		return err
	}
	return s.acceptValidatedComponentDescriptorWire(descriptor, wire)
}

// acceptValidatedComponentDescriptorWire is used only when the caller has
// just completed descriptor decode, canonical checks, and certificate
// verification (for example, the ReadyCert decoder).
func (s *cvComponentService) acceptValidatedComponentDescriptorWire(
	descriptor *cvComponentDescriptor, wire []byte,
) error {
	if descriptor == nil || len(wire) == 0 {
		return fmt.Errorf("invalid validated CV-sAPVSS component descriptor")
	}
	s.mu.Lock()
	added := false
	if existing, exists := s.componentDescriptors[descriptor.dealer]; !exists {
		s.componentDescriptors[descriptor.dealer] = descriptor
		if s.componentDescriptorWires == nil {
			s.componentDescriptorWires = make(map[int][]byte)
		}
		s.componentDescriptorWires[descriptor.dealer] = append([]byte(nil), wire...)
		added = true
	} else {
		existingWire := s.componentDescriptorWires[descriptor.dealer]
		var existingErr error
		if len(existingWire) == 0 {
			existingWire, existingErr = cvComponentDescriptorCanonicalBytes(existing)
		}
		if existingErr != nil || !bytes.Equal(existingWire, wire) {
			s.mu.Unlock()
			return fmt.Errorf("conflicting certified CV-sAPVSS component for dealer=%d", descriptor.dealer)
		}
	}
	s.mu.Unlock()
	if !added {
		return nil
	}
	s.maybePublishCanonicalReadyCertificate()
	s.retryPendingReadyCertificates()
	return nil
}

func (s *cvComponentService) maybePublishCanonicalReadyCertificate() {
	ready := len(s.cfg.OldCommittee) - s.cfg.FOld
	s.mu.Lock()
	if len(s.componentDescriptors) < ready {
		s.mu.Unlock()
		return
	}
	dealers := make([]int, 0, len(s.componentDescriptors))
	for dealer := range s.componentDescriptors {
		dealers = append(dealers, dealer)
	}
	sort.Ints(dealers)
	descriptors := make([]*cvComponentDescriptor, ready)
	descriptorWires := make([][]byte, ready)
	for i, dealer := range dealers[:ready] {
		descriptors[i] = s.componentDescriptors[dealer]
		// Cache entries are immutable after acceptance, so they remain safe to
		// use after releasing the service mutex.
		descriptorWires[i] = s.componentDescriptorWires[dealer]
	}
	s.mu.Unlock()
	certificate, wire, err := cvBuildComponentReadyCertificateWireFromValidatedWires(
		s.localNode, descriptors, descriptorWires,
	)
	if err != nil {
		return
	}
	key := fmt.Sprintf("%x", certificate.root)
	s.mu.Lock()
	if _, exists := s.publishedReadyRoots[key]; exists {
		s.mu.Unlock()
		return
	}
	s.publishedReadyRoots[key] = struct{}{}
	s.acceptedReadyRoots[key] = struct{}{}
	s.readyDescriptorsByRoot[key] = append([]*cvComponentDescriptor(nil), descriptors...)
	s.mu.Unlock()
	targets := make([]int, 0, len(s.cfg.OldCommittee)-1)
	for _, node := range s.oldCommitteeOrder() {
		if node != s.localNode {
			targets = append(targets, node)
		}
	}
	s.sendMany(targets, cvTagComponentReady, wire)
	select {
	case s.readyCandidates <- descriptors:
	case <-s.ctx.Done():
	}
}

func (s *cvComponentService) resolveReadyCertificate(certificate *cvComponentReadyCertificate) ([]*cvComponentDescriptor, error) {
	if certificate == nil || len(certificate.references) != len(s.cfg.OldCommittee)-s.cfg.FOld {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert")
	}
	s.mu.Lock()
	descriptors := make([]*cvComponentDescriptor, len(certificate.references))
	for i, reference := range certificate.references {
		descriptor := s.componentDescriptors[reference.dealer]
		descriptorWire := s.componentDescriptorWires[reference.dealer]
		var descriptorErr error
		if len(descriptorWire) == 0 {
			descriptorWire, descriptorErr = cvComponentDescriptorCanonicalBytes(descriptor)
		}
		if descriptorErr != nil || !bytes.Equal(descriptor.leafDigest, reference.leafDigest) ||
			!bytes.Equal(descriptorWire, reference.descriptorWire) {
			s.mu.Unlock()
			return nil, fmt.Errorf("unresolved CV-sAPVSS ReadyCert component")
		}
		descriptors[i] = descriptor
	}
	s.mu.Unlock()
	return descriptors, nil
}

func (s *cvComponentService) isCanonicalReadyPool(descriptors []*cvComponentDescriptor) bool {
	ready := len(s.cfg.OldCommittee) - s.cfg.FOld
	if len(descriptors) != ready {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.componentDescriptors) < ready {
		return false
	}
	dealers := make([]int, 0, len(s.componentDescriptors))
	for dealer := range s.componentDescriptors {
		dealers = append(dealers, dealer)
	}
	sort.Ints(dealers)
	for i, dealer := range dealers[:ready] {
		want := s.componentDescriptors[dealer]
		got := descriptors[i]
		wantWire, wantErr := cvComponentDescriptorCanonicalBytes(want)
		gotWire, gotErr := cvComponentDescriptorCanonicalBytes(got)
		if wantErr != nil || gotErr != nil || !bytes.Equal(wantWire, gotWire) {
			return false
		}
	}
	return true
}

func (s *cvComponentService) handleReadyCertificate(msg Message) {
	wireDigest := fmt.Sprintf("%x", hashBytes(msg.Body))
	s.mu.Lock()
	if cached := s.acceptedReadyWires[msg.From]; len(cached) != 0 && bytes.Equal(cached, msg.Body) {
		s.mu.Unlock()
		return
	}
	if _, pending := s.pendingReadyWireDigests[wireDigest]; pending {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	certificate, err := cvDecodeComponentReadyCertificate(msg.Body, s.cfg)
	if err != nil || certificate.proposer != msg.From {
		return
	}
	for _, reference := range certificate.references {
		if err := s.acceptValidatedComponentDescriptorWire(reference.descriptor, reference.descriptorWire); err != nil {
			return
		}
	}
	key := fmt.Sprintf("%x", certificate.root)
	descriptors, err := s.resolveReadyCertificate(certificate)
	if err != nil {
		s.mu.Lock()
		if len(s.pendingReadyWireDigests) < 256 {
			s.pendingReadyWireDigests[wireDigest] = struct{}{}
		}
		s.pendingReadyCertificates[key] = certificate
		s.mu.Unlock()
		return
	}
	if !s.isCanonicalReadyPool(descriptors) {
		return
	}
	s.mu.Lock()
	s.acceptedReadyRoots[key] = struct{}{}
	if s.acceptedReadyWires == nil {
		s.acceptedReadyWires = make(map[int][]byte)
	}
	if len(s.acceptedReadyWires[msg.From]) == 0 {
		s.acceptedReadyWires[msg.From] = append([]byte(nil), msg.Body...)
	}
	s.readyDescriptorsByRoot[key] = append([]*cvComponentDescriptor(nil), descriptors...)
	delete(s.pendingReadyCertificates, key)
	delete(s.pendingReadyWireDigests, wireDigest)
	s.mu.Unlock()
	s.retryPendingReadyOffers(key)
}

func (s *cvComponentService) retryPendingReadyCertificates() {
	s.mu.Lock()
	pending := make(map[string]*cvComponentReadyCertificate, len(s.pendingReadyCertificates))
	for key, certificate := range s.pendingReadyCertificates {
		pending[key] = certificate
	}
	s.mu.Unlock()
	for key, certificate := range pending {
		descriptors, err := s.resolveReadyCertificate(certificate)
		if err != nil {
			continue
		}
		if !s.isCanonicalReadyPool(descriptors) {
			s.mu.Lock()
			delete(s.pendingReadyCertificates, key)
			s.mu.Unlock()
			continue
		}
		s.mu.Lock()
		s.acceptedReadyRoots[key] = struct{}{}
		s.readyDescriptorsByRoot[key] = append([]*cvComponentDescriptor(nil), descriptors...)
		delete(s.pendingReadyCertificates, key)
		s.mu.Unlock()
		s.retryPendingReadyOffers(key)
	}
}

func (s *cvComponentService) retryPendingReadyOffers(key string) {
	s.mu.Lock()
	pending := append([]Message(nil), s.pendingReadyOffers[key]...)
	delete(s.pendingReadyOffers, key)
	s.mu.Unlock()
	for _, msg := range pending {
		msg := msg
		go s.handleAggregateOffer(msg)
	}
}

func (s *cvComponentService) claimComponentStatement(dealer int, statement []byte) bool {
	if dealer < 0 || len(statement) != 32 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.componentStatementByDealer[dealer]; len(existing) > 0 {
		return bytes.Equal(existing, statement)
	}
	s.componentStatementByDealer[dealer] = append([]byte(nil), statement...)
	return true
}

func (s *cvComponentService) Retrieve(
	ctx context.Context,
	descriptor *cvComponentDescriptor,
) (*cvLeaf, error) {
	accepted, err := s.getVerifiedComponent(ctx, descriptor)
	if err != nil {
		return nil, err
	}
	return accepted.leaf, nil
}

func (s *cvComponentService) retrieveComponentNetwork(
	ctx context.Context,
	descriptor *cvComponentDescriptor,
) (*cvVerifiedLeaf, error) {
	if ctx == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS component retrieval context")
	}
	if err := cvValidateNetworkComponentDescriptor(s.cfg, descriptor); err != nil {
		return nil, err
	}
	key := cvComponentKey(descriptor.dealer, descriptor.leafDigest)
	oldOrder := s.oldCommitteeOrder()
	pending := &cvPendingComponentLeaf{
		// Compact descriptors intentionally omit holder identities. Requests are
		// sent to the complete old roster and authenticated leaf responses are
		// accepted only after digest/dealer checks.
		allowed:    nodeSet(oldOrder),
		descriptor: descriptor,
		values:     make(chan cvComponentShard, len(oldOrder)),
	}
	s.mu.Lock()
	if _, exists := s.pendingLeaves[key]; exists {
		s.mu.Unlock()
		return nil, fmt.Errorf("CV-sAPVSS component retrieval already active")
	}
	s.pendingLeaves[key] = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingLeaves[key] == pending {
			delete(s.pendingLeaves, key)
		}
		s.mu.Unlock()
	}()
	requestWire, err := cvComponentGetCanonicalBytes(&cvComponentGet{
		dealer: descriptor.dealer, leafDigest: descriptor.leafDigest,
	})
	if err != nil {
		return nil, err
	}
	sent := s.sendMany(oldOrder, cvTagComponentGet, requestWire)
	if sent == 0 {
		return nil, fmt.Errorf("CV-sAPVSS component retrieval reached no certificate holder")
	}
	shards := make(map[int]cvComponentShard, descriptor.dispersal.dataShards)
	for len(shards) < descriptor.dispersal.dataShards {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case shard := <-pending.values:
			if _, exists := shards[shard.index]; !exists {
				shards[shard.index] = shard
			}
		}
	}
	leafWire, err := cvRecoverComponentWire(&descriptor.dispersal, len(oldOrder), shards)
	if err != nil {
		return nil, fmt.Errorf("recover CV-sAPVSS component: %w", err)
	}
	if !bytes.Equal(cvComponentLeafPayloadDigest(leafWire), descriptor.leafDigest) {
		return nil, fmt.Errorf("recovered CV-sAPVSS component leaf digest mismatch")
	}
	accepted, err := s.verifyComponentWire(descriptor.dealer, descriptor.leafDigest, leafWire)
	if err != nil {
		return nil, err
	}
	if s.reconstructedCacheMode == "sync" {
		if err := s.cacheReconstructedLeaf(descriptor.dealer, descriptor.leafDigest, leafWire); err != nil {
			return nil, err
		}
	}
	accepted, err = s.publishVerifiedLeaf(descriptor.dealer, descriptor.leafDigest, accepted)
	if err != nil {
		return nil, err
	}
	if s.reconstructedCacheMode != "sync" {
		if err := s.cacheReconstructedLeaf(descriptor.dealer, descriptor.leafDigest, leafWire); err != nil {
			return nil, err
		}
	}
	return accepted, nil
}

func (s *cvComponentService) run() {
	defer close(s.done)
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-s.inbox:
			if !ok {
				return
			}
			s.handle(msg)
		}
	}
}

func (s *cvComponentService) handle(msg Message) {
	switch msg.Tag {
	case cvTagComponentInit:
		s.handleInit(msg)
	case cvTagComponentAck:
		s.handleACK(msg)
	case cvTagComponentCert:
		_ = s.acceptComponentDescriptorWire(msg.Body)
	case cvTagComponentReady:
		s.handleReadyCertificate(msg)
	case cvTagEligibilityShare:
		s.handleEligibilityShare(msg)
	case cvTagComponentGet:
		s.handleGet(msg)
	case cvTagComponentLeaf:
		s.handleLeaf(msg)
	case cvTagAggregateManifest:
		s.handleAggregateOffer(msg)
	case cvTagARCShare:
		s.handleARCShare(msg)
	case cvTagARCCertificate:
		s.handleARCCertificate(msg)
	case cvTagRecoverGet:
		s.handleRecoverGet(msg)
	case cvTagRecoverShard:
		s.handleRecoverShard(msg)
	case cvTagReceipt:
		s.handleReceipt(msg)
	case apvssTagLaneOffer:
		s.enqueueAPVSSLaneOffer(msg)
	case apvssTagLaneACK:
		s.handleAPVSSLaneACK(msg)
	}
}

func (s *cvComponentService) enqueueAPVSSLaneOffer(msg Message) {
	key := fmt.Sprintf("%d/%d", msg.From, msg.To)
	s.mu.Lock()
	if _, exists := s.processingLaneOffers[key]; exists {
		s.mu.Unlock()
		return
	}
	s.processingLaneOffers[key] = struct{}{}
	s.mu.Unlock()
	select {
	case s.laneOfferQueue <- msg:
	case <-s.ctx.Done():
		s.mu.Lock()
		delete(s.processingLaneOffers, key)
		s.mu.Unlock()
	default:
		s.mu.Lock()
		delete(s.processingLaneOffers, key)
		s.mu.Unlock()
	}
}

func (s *cvComponentService) runLaneOfferWorker() {
	defer s.laneWorkerWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg := <-s.laneOfferQueue:
			s.handleAPVSSLaneOffer(msg)
		}
	}
}

func (s *cvComponentService) handleAPVSSLaneOffer(msg Message) {
	secret, local := s.localReceiverSecrets[msg.To]
	signingSecret, signingLocal := s.localReceiverSigningSecrets[msg.To]
	receiverIndex, registered := s.receiverIndex[msg.To]
	if !local || !signingLocal || !registered {
		return
	}
	offer, err := apvssDecodeLaneOffer(msg.Body, s.leafCtx, receiverIndex)
	if err != nil || offer.dealerID != uint64(msg.From) {
		return
	}
	leaf, err := apvssLaneOfferLeafView(s.leafCtx, offer)
	if err != nil {
		return
	}
	ack, err := apvssIssueVerifiedLaneACK(s.leafCtx, leaf, receiverIndex, secret, signingSecret)
	if err != nil {
		return
	}
	wire, err := apvssLaneACKMessageCanonicalBytes(&apvssLaneACKMessage{
		dealerID: offer.dealerID, leafDigest: offer.leafDigest, ack: ack,
	})
	if err == nil {
		_ = s.sendFrom(msg.To, msg.From, apvssTagLaneACK, wire)
	}
}

func (s *cvComponentService) sendAPVSSLaneOffers(leaf *cvLeaf) int {
	jobs := len(s.receiverOrder)
	workers := cvNetworkWorkers(jobs)
	if jobs == 0 || workers == 0 {
		return 0
	}
	indices := make(chan int)
	results := make(chan bool, jobs)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range indices {
				offer, err := apvssLaneOfferFromLeaf(leaf, index+1)
				if err == nil {
					var wire []byte
					wire, err = apvssLaneOfferCanonicalBytesTrusted(offer, s.leafContextDigest)
					if err == nil {
						err = s.sendFrom(
							s.localNode, s.receiverOrder[index], apvssTagLaneOffer, wire,
						)
					}
				}
				results <- err == nil
			}
		}()
	}
	for index := 0; index < jobs; index++ {
		indices <- index
	}
	close(indices)
	group.Wait()
	close(results)
	sent := 0
	for ok := range results {
		if ok {
			sent++
		}
	}
	return sent
}

func (s *cvComponentService) handleAPVSSLaneACK(msg Message) {
	s.mu.Lock()
	pending := make([]*apvssPendingLaneACKs, 0, len(s.pendingLaneACKs))
	for _, value := range s.pendingLaneACKs {
		pending = append(pending, value)
	}
	s.mu.Unlock()
	for _, collection := range pending {
		message, err := apvssDecodeLaneACKMessage(msg.Body, collection.leaf)
		if err != nil || message.dealerID != uint64(s.localNode) ||
			message.ack.receiverIndex <= 0 || message.ack.receiverIndex > len(s.receiverOrder) ||
			s.receiverOrder[message.ack.receiverIndex-1] != msg.From {
			continue
		}
		select {
		case collection.values <- message.ack:
		default:
		}
		return
	}
}

func (s *cvComponentService) ExchangeReceipts(
	ctx context.Context,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (map[int][]byte, map[int][]byte, []byte, error) {
	if ctx == nil || len(localSecrets) == 0 {
		return nil, nil, nil, fmt.Errorf("invalid CV-sAPVSS receipt exchange input")
	}
	pending := &cvPendingReceiptExchange{
		agg: agg, receiverOrder: append([]int(nil), receiverOrder...),
		values: make(chan cvReceivedReceipt, len(receiverOrder)*2),
	}
	s.mu.Lock()
	if s.pendingReceipts != nil {
		s.mu.Unlock()
		return nil, nil, nil, fmt.Errorf("CV-sAPVSS receipt exchange already active")
	}
	s.pendingReceipts = pending
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.pendingReceipts == pending {
			s.pendingReceipts = nil
		}
		s.mu.Unlock()
	}()
	prepared, err := s.waitReceiptPreparation(ctx, agg, receiverOrder, localSecrets)
	if err != nil {
		return nil, nil, nil, err
	}
	shares := prepared.shares
	localReceipts := prepared.receipts

	verified := make(map[int]*cvVerifiedReceipt, len(receiverOrder))
	receiptWires := make(map[int][]byte, len(receiverOrder))
	for receiverID, token := range prepared.verified {
		verified[receiverID] = token
		receiptWires[receiverID] = append([]byte(nil), token.wire...)
	}
	broadcast := func() {
		for _, wire := range localReceipts {
			s.sendMany(s.oldCommitteeOrder(), cvTagReceipt, wire)
		}
	}
	broadcast()
	threshold := s.leafCtx.sharingDegree + 1
	if len(verified) >= threshold {
		key, keyErr := cvThresholdPublicKeyFromVerifiedReceipts(s.leafCtx, agg, receiverOrder, verified)
		return shares, receiptWires, key, keyErr
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for len(verified) < threshold {
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, nil, nil, s.ctx.Err()
		case <-ticker.C:
			broadcast()
		case receipt := <-pending.values:
			token := receipt.verified
			if token != nil {
				if _, duplicate := verified[token.receiverID]; !duplicate {
					verified[token.receiverID] = token
					receiptWires[token.receiverID] = append([]byte(nil), token.wire...)
				}
			}
		}
	}
	key, err := cvThresholdPublicKeyFromVerifiedReceipts(s.leafCtx, agg, receiverOrder, verified)
	return shares, receiptWires, key, err
}

func (s *cvComponentService) StartReceiptPreparation(
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) {
	_, _ = s.receiptPreparationCall(agg, receiverOrder, localSecrets)
}

func (s *cvComponentService) receiptPreparationCall(
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (*cvReceiptPreparationCall, error) {
	if agg == nil || len(agg.digest) != 32 || len(localSecrets) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS receipt preparation input")
	}
	key := fmt.Sprintf("%x", agg.digest)
	s.mu.Lock()
	call := s.receiptPreparations[key]
	if call == nil {
		if cvPerfCountersEnabled {
			cvPerfCounters.receiptPrewarmStarts.Add(1)
		}
		call = &cvReceiptPreparationCall{done: make(chan struct{})}
		s.receiptPreparations[key] = call
		receiverOrderCopy := append([]int(nil), receiverOrder...)
		secretsCopy := make(map[int]fr.Element, len(localSecrets))
		for receiverID, secret := range localSecrets {
			secretsCopy[receiverID] = secret
		}
		s.backgroundWG.Add(1)
		go func() {
			defer s.backgroundWG.Done()
			outputs, prepareErr := cvPrepareLocalDecryptionOutputs(s.leafCtx, agg, receiverOrderCopy, secretsCopy)
			s.mu.Lock()
			call.outputs = outputs
			call.err = prepareErr
			close(call.done)
			s.mu.Unlock()
		}()
	} else if cvPerfCountersEnabled {
		cvPerfCounters.receiptPrewarmHits.Add(1)
	}
	s.mu.Unlock()
	return call, nil
}

func (s *cvComponentService) waitReceiptPreparation(
	ctx context.Context,
	agg *cvAggregateTranscript,
	receiverOrder []int,
	localSecrets map[int]fr.Element,
) (*cvPreparedReceiptOutputs, error) {
	call, err := s.receiptPreparationCall(agg, receiverOrder, localSecrets)
	if err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	case <-call.done:
		return call.outputs, call.err
	}
}

func (s *cvComponentService) handleReceipt(msg Message) {
	s.mu.Lock()
	pending := s.pendingReceipts
	s.mu.Unlock()
	if pending == nil {
		return
	}
	r := newCVWireReader(msg.Body)
	domain, err := r.bytes(len(cvReceiptDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvReceiptDomain)) {
		return
	}
	aggregateDigest, err := r.bytes(32)
	if err != nil || !bytes.Equal(aggregateDigest, pending.agg.digest) {
		return
	}
	receiverIndex, err := r.uint32()
	if err != nil || receiverIndex <= 0 || receiverIndex > len(pending.receiverOrder) {
		return
	}
	receiverID := pending.receiverOrder[receiverIndex-1]
	receipt, err := cvDecodeReceiptVerifiedAggregate(msg.Body, s.leafCtx, pending.agg, receiverIndex)
	if err != nil {
		return
	}
	received := cvReceivedReceipt{verified: &cvVerifiedReceipt{
		receiverID: receiverID, index: receiverIndex,
		wire: append([]byte(nil), msg.Body...), receipt: receipt,
	}}
	select {
	case pending.values <- received:
	default:
	}
}

func (s *cvComponentService) handleInit(msg Message) {
	initKey := string(cvComponentLeafPayloadDigest(msg.Body))
	s.mu.Lock()
	if cached := s.componentInitACKWires[initKey]; len(cached) != 0 {
		wire := append([]byte(nil), cached...)
		s.mu.Unlock()
		_ = s.send(msg.From, cvTagComponentAck, wire)
		return
	}
	s.mu.Unlock()
	init, err := cvDecodeComponentInit(msg.Body)
	if err != nil {
		return
	}
	oldOrder := s.oldCommitteeOrder()
	expectedIndex := s.localOldCommitteeIndex()
	if expectedIndex >= len(oldOrder) || oldOrder[expectedIndex] != s.localNode {
		return
	}
	artifact, err := cvDecodeComponentShardArtifact(init.artifactWire, msg.From, len(s.cfg.OldCommittee))
	if err != nil || artifact.dealer != msg.From || artifact.shard.index != expectedIndex {
		return
	}
	statement, err := cvComponentStatementDigest(artifact.dealer, artifact.leafDigest, &artifact.dispersal)
	if err != nil {
		return
	}
	s.mu.Lock()
	cachedACK := append([]byte(nil), s.componentACKWires[string(statement)]...)
	s.mu.Unlock()
	if len(cachedACK) != 0 {
		_ = s.send(artifact.dealer, cvTagComponentAck, cachedACK)
		return
	}
	if !s.cfg.runtime.lockSigner.VerifyShare(
		artifact.dealer, cvComponentDealerSignatureDomain, statement, init.dealerSig,
	) {
		return
	}
	if !s.claimComponentStatement(artifact.dealer, statement) {
		return
	}
	if err := s.shardStore.Put(s.cfg.SID, s.cfg.Epoch, artifact.dealer, s.localNode, artifact.leafDigest, init.artifactWire); err != nil {
		return
	}
	sig, err := s.cfg.runtime.lockSigner.SignShare(
		s.localNode, cvComponentLockSignatureDomain, statement,
	)
	if err != nil {
		return
	}
	ackWire, err := cvComponentAckCanonicalBytes(&cvComponentAck{
		dealer: artifact.dealer, holder: s.localNode, leafDigest: artifact.leafDigest, signature: sig,
	})
	if err == nil {
		s.mu.Lock()
		if s.componentACKWires == nil {
			s.componentACKWires = make(map[string][]byte)
		}
		s.componentACKWires[string(statement)] = append([]byte(nil), ackWire...)
		if s.componentInitACKWires == nil {
			s.componentInitACKWires = make(map[string][]byte)
		}
		s.componentInitACKWires[initKey] = append([]byte(nil), ackWire...)
		s.mu.Unlock()
		_ = s.send(artifact.dealer, cvTagComponentAck, ackWire)
	}
}

func (s *cvComponentService) handleACK(msg Message) {
	ack, err := cvDecodeComponentAck(msg.Body)
	if err != nil || ack.holder != msg.From || ack.dealer != s.localNode {
		return
	}
	key := cvComponentKey(ack.dealer, ack.leafDigest)
	s.mu.Lock()
	pending := s.pendingACKs[key]
	statement := append([]byte(nil), s.pendingComponentStatements[key]...)
	if pending != nil {
		if _, duplicate := pending.accepted[msg.From]; duplicate {
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()
	if len(statement) == 0 || !s.cfg.runtime.lockSigner.VerifyShare(
		ack.holder, cvComponentLockSignatureDomain, statement, ack.signature,
	) {
		return
	}
	if pending == nil {
		return
	}
	s.mu.Lock()
	if s.pendingACKs[key] != pending {
		s.mu.Unlock()
		return
	}
	if _, duplicate := pending.accepted[msg.From]; duplicate {
		s.mu.Unlock()
		return
	}
	pending.accepted[msg.From] = struct{}{}
	s.mu.Unlock()
	select {
	case pending.values <- *ack:
	default:
	}
}

func (s *cvComponentService) handleGet(msg Message) {
	request, err := cvDecodeComponentGet(msg.Body)
	if err != nil {
		return
	}
	artifactWire, err := s.shardStore.Read(
		s.cfg.SID, s.cfg.Epoch, request.dealer, s.localNode, request.leafDigest,
	)
	if err != nil {
		return
	}
	_ = s.send(msg.From, cvTagComponentLeaf, artifactWire)
}

func (s *cvComponentService) handleLeaf(msg Message) {
	oldOrder := s.oldCommitteeOrder()
	expectedIndex := sort.SearchInts(oldOrder, msg.From)
	if expectedIndex >= len(oldOrder) || oldOrder[expectedIndex] != msg.From {
		return
	}
	s.mu.Lock()
	pendingLeaves := make([]*cvPendingComponentLeaf, 0, len(s.pendingLeaves))
	for _, pending := range s.pendingLeaves {
		pendingLeaves = append(pendingLeaves, pending)
	}
	s.mu.Unlock()
	for _, pending := range pendingLeaves {
		if _, ok := pending.allowed[msg.From]; !ok || pending.descriptor == nil {
			continue
		}
		artifact, err := cvDecodeComponentShardArtifact(msg.Body, pending.descriptor.dealer, len(s.cfg.OldCommittee))
		if err != nil || !bytes.Equal(artifact.leafDigest, pending.descriptor.leafDigest) ||
			artifact.shard.index != expectedIndex ||
			!cvEqualComponentDispersal(&artifact.dispersal, &pending.descriptor.dispersal) {
			continue
		}
		select {
		case pending.values <- artifact.shard:
		default:
		}
		return
	}
}

func (s *cvComponentService) send(to int, tag string, payload []byte) error {
	return s.sendFrom(s.localNode, to, tag, payload)
}

func (s *cvComponentService) sendMany(to []int, tag string, payload []byte) int {
	return s.sendManyFrom(s.localNode, to, tag, payload)
}

func (s *cvComponentService) sendManyFrom(from int, to []int, tag string, payload []byte) int {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, s.cfg.Epoch, payload)
	if err != nil {
		return 0
	}
	if s.networkAuth == nil && cvPerfCountersEnabled && len(to) > 1 {
		cvPerfCounters.envelopeReuseSends.Add(uint64(len(to) - 1))
	}
	sent := 0
	for _, recipient := range to {
		wire, authErr := s.networkAuth.seal(from, recipient, tag, envelope)
		if authErr == nil && s.transport.Send(Message{From: from, To: recipient, Tag: tag, Body: wire}) == nil {
			sent++
		}
	}
	return sent
}

func (s *cvComponentService) localARCShare(headerDigest []byte) ([]byte, error) {
	if len(headerDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ARC header digest")
	}
	key := fmt.Sprintf("%x", headerDigest)
	persistedKey := fmt.Sprintf("%x/%d", headerDigest, s.localNode)
	s.freshPersistMu.Lock()
	_, persisted := s.persistedFreshArtifacts[persistedKey]
	s.freshPersistMu.Unlock()
	if !persisted {
		return nil, fmt.Errorf("CV-sAPVSS ARC share requires a persisted fresh artifact")
	}
	s.mu.Lock()
	if existing := s.localARCShareByHeader[key]; len(existing) > 0 {
		share := append([]byte(nil), existing...)
		s.mu.Unlock()
		return share, nil
	}
	s.mu.Unlock()
	share, err := s.cfg.runtime.lockSigner.SignShare(s.localNode, "RL_AGG_LOCK", headerDigest)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if existing := s.localARCShareByHeader[key]; len(existing) > 0 {
		share = append([]byte(nil), existing...)
	} else {
		s.localARCShareByHeader[key] = append([]byte(nil), share...)
	}
	s.mu.Unlock()
	return share, nil
}

func (s *cvComponentService) sendFrom(from, to int, tag string, payload []byte) error {
	envelope, err := cvEncodeNetworkEnvelope(s.cfg.SID, s.cfg.Epoch, payload)
	if err != nil {
		return err
	}
	wire, err := s.networkAuth.seal(from, to, tag, envelope)
	if err != nil {
		return err
	}
	return s.transport.Send(Message{From: from, To: to, Tag: tag, Body: wire})
}

func (s *cvComponentService) persistFreshArtifact(headerDigest []byte, wire []byte) error {
	if len(headerDigest) != 32 || len(wire) == 0 {
		return fmt.Errorf("invalid CV-sAPVSS fresh artifact persistence input")
	}
	key := fmt.Sprintf("%x/%d", headerDigest, s.localNode)
	s.freshPersistMu.Lock()
	defer s.freshPersistMu.Unlock()
	if _, exists := s.persistedFreshArtifacts[key]; exists {
		if cvPerfCountersEnabled {
			cvPerfCounters.freshArtifactSkips.Add(1)
		}
		return nil
	}
	if err := s.freshStore.Put(s.cfg.SID, s.cfg.Epoch, headerDigest, s.localNode, wire); err != nil {
		return err
	}
	s.persistedFreshArtifacts[key] = struct{}{}
	if cvPerfCountersEnabled {
		cvPerfCounters.freshArtifactWrites.Add(1)
	}
	return nil
}

func cvReconstructedLeafCacheMode() string {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_RECONSTRUCTED_LEAF_CACHE_MODE"))) {
	case "sync":
		return "sync"
	case "off":
		return "off"
	default:
		return "async"
	}
}

func cvReconstructedLeafCacheQueueCapacity() int {
	const defaultCapacity = 2
	raw := strings.TrimSpace(os.Getenv("RLADKR_RECONSTRUCTED_LEAF_CACHE_QUEUE"))
	capacity, err := strconv.Atoi(raw)
	if raw == "" || err != nil || capacity < 1 || capacity > 16 {
		return defaultCapacity
	}
	return capacity
}

func (s *cvComponentService) cacheReconstructedLeaf(
	dealer int,
	leafDigest, leafWire []byte,
) error {
	if dealer < 0 || len(leafDigest) != 32 || len(leafWire) == 0 ||
		!bytes.Equal(leafDigest, cvComponentLeafPayloadDigest(leafWire)) {
		return fmt.Errorf("invalid reconstructed CV-sAPVSS leaf cache input")
	}
	switch s.reconstructedCacheMode {
	case "sync":
		err := s.store.Put(s.cfg.SID, s.cfg.Epoch, dealer, s.localNode, leafDigest, leafWire)
		if cvPerfCountersEnabled {
			if err == nil {
				cvPerfCounters.reconstructedCacheWrites.Add(1)
			} else {
				cvPerfCounters.reconstructedCacheErrors.Add(1)
			}
		}
		return err
	case "off":
		return nil
	case "async":
		job := cvReconstructedLeafCacheJob{
			dealer: dealer, leafDigest: append([]byte(nil), leafDigest...),
			leafWire: append([]byte(nil), leafWire...),
		}
		select {
		case <-s.ctx.Done():
			return nil
		default:
		}
		select {
		case s.reconstructedCacheQueue <- job:
			if cvPerfCountersEnabled {
				cvPerfCounters.reconstructedCacheQueued.Add(1)
			}
		default:
			if cvPerfCountersEnabled {
				cvPerfCounters.reconstructedCacheDrops.Add(1)
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid reconstructed CV-sAPVSS leaf cache mode")
	}
}

func (s *cvComponentService) runReconstructedLeafCacheWriter() {
	defer s.backgroundWG.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case job := <-s.reconstructedCacheQueue:
			err := s.store.Put(
				s.cfg.SID, s.cfg.Epoch, job.dealer, s.localNode, job.leafDigest, job.leafWire,
			)
			if cvPerfCountersEnabled {
				if err == nil {
					cvPerfCounters.reconstructedCacheWrites.Add(1)
				} else {
					cvPerfCounters.reconstructedCacheErrors.Add(1)
				}
			}
		}
	}
}

func (s *cvComponentService) cacheVerifiedWire(
	dealer int,
	digest, canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	accepted, err := s.verifyComponentWire(dealer, digest, canonicalWire)
	if err != nil {
		return nil, err
	}
	return s.publishVerifiedLeaf(dealer, digest, accepted)
}

func (s *cvComponentService) verifyComponentWire(
	dealer int,
	digest, canonicalWire []byte,
) (*cvVerifiedLeaf, error) {
	if dealer < 0 || len(digest) != 32 || len(canonicalWire) == 0 ||
		!bytes.Equal(digest, cvComponentLeafPayloadDigest(canonicalWire)) {
		return nil, fmt.Errorf("invalid verified component wire")
	}
	var accepted *cvVerifiedLeaf
	var err error
	if apvssHasLeafWireDomain(canonicalWire) {
		prototype, decodeErr := apvssDecodeLeafPrototype(canonicalWire, s.leafCtx)
		if decodeErr != nil || prototype.leaf.dealerID != uint64(dealer) ||
			!bytes.Equal(prototype.digest, digest) {
			return nil, fmt.Errorf("invalid APVSS component leaf")
		}
		accepted, err = cvAcceptedDecodedAPVSSLeaf(s.leafCtx, prototype, canonicalWire)
	} else {
		leaf, decodeErr := cvDecodeLeaf(canonicalWire, s.leafCtx)
		if decodeErr != nil || leaf.dealerID != uint64(dealer) || !bytes.Equal(leaf.digest, digest) {
			return nil, fmt.Errorf("invalid CV-sAPVSS component leaf")
		}
		accepted, err = cvAcceptedLeaf(s.leafCtx, leaf, canonicalWire)
	}
	if err != nil {
		return nil, err
	}
	// The object remains local until publishVerifiedLeaf. Both decoders above
	// checked canonical encoding, digest, context, and the complete APVSS
	// validity predicate before the service seal is granted.
	accepted.serviceSealed = true
	return accepted, nil
}

func (s *cvComponentService) publishVerifiedLeaf(
	dealer int,
	digest []byte,
	accepted *cvVerifiedLeaf,
) (*cvVerifiedLeaf, error) {
	if err := s.cacheAcceptedLeaf(dealer, digest, accepted); err != nil {
		return nil, err
	}
	key := cvComponentKey(dealer, digest)
	s.mu.Lock()
	cached := s.verifiedLeaves[key]
	s.mu.Unlock()
	return cached, nil
}

func (s *cvComponentService) cacheAcceptedLeaf(
	dealer int,
	digest []byte,
	accepted *cvVerifiedLeaf,
) error {
	if accepted == nil || !bytes.Equal(accepted.leafDigest, digest) {
		return fmt.Errorf("invalid accepted CV-sAPVSS component cache entry")
	}
	key := cvComponentKey(dealer, digest)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.verifiedLeaves[key]; existing != nil {
		if !bytes.Equal(existing.canonicalWire, accepted.canonicalWire) {
			return fmt.Errorf("conflicting verified CV-sAPVSS component cache entry")
		}
		return nil
	}
	if len(s.verifiedLeaves) >= len(s.cfg.OldCommittee) {
		return fmt.Errorf("verified CV-sAPVSS component cache is full")
	}
	s.verifiedLeaves[key] = accepted
	return nil
}

func cvComponentKey(dealer int, digest []byte) string {
	return fmt.Sprintf("%d:%x", dealer, digest)
}

func cvDecodeAndValidateComponentDescriptor(cfg Config, wire []byte) (*cvComponentDescriptor, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	return cvDecodeAndValidateComponentDescriptorPrepared(&c, wire, nodeSet(c.OldCommittee))
}

// cvDecodeAndValidateComponentDescriptorPrepared is the batch form used when
// the caller has already normalized and validated c and prepared its runtime.
func cvDecodeAndValidateComponentDescriptorPrepared(
	c *Config, wire []byte, oldMembers map[int]struct{},
) (*cvComponentDescriptor, error) {
	if c == nil || len(oldMembers) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component descriptor configuration")
	}
	descriptor, err := cvDecodeComponentDescriptorWithRoster(wire, c.OldCommittee, oldMembers)
	if err != nil {
		return nil, err
	}
	if err := cvValidateDecodedNetworkComponentDescriptor(c, descriptor); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func cvComponentInitCanonicalBytes(init *cvComponentInit) ([]byte, error) {
	if init == nil || len(init.artifactWire) == 0 ||
		len(init.artifactWire) > cvMaxNetworkPayloadBytes || len(init.dealerSig) == 0 ||
		len(init.dealerSig) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentInitDomain))
	_ = cvWriteBytes(&wire, init.artifactWire)
	_ = cvWriteBytes(&wire, init.dealerSig)
	return wire.Bytes(), nil
}

func cvDecodeComponentInit(wire []byte) (*cvComponentInit, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentInitDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentInitDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT domain")
	}
	artifact, err := r.bytes(cvMaxNetworkPayloadBytes)
	if err != nil || len(artifact) == 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT artifact")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component INIT signature")
	}
	init := &cvComponentInit{artifactWire: artifact, dealerSig: sig}
	canonical, err := cvComponentInitCanonicalBytes(init)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component INIT")
	}
	return init, nil
}

func cvComponentAckCanonicalBytes(ack *cvComponentAck) ([]byte, error) {
	if ack == nil || ack.dealer < 0 || ack.holder < 0 || len(ack.leafDigest) != 32 ||
		len(ack.signature) == 0 || len(ack.signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentAckDomain))
	cvWriteUint64(&wire, uint64(ack.dealer))
	cvWriteUint64(&wire, uint64(ack.holder))
	_ = cvWriteBytes(&wire, ack.leafDigest)
	_ = cvWriteBytes(&wire, ack.signature)
	return wire.Bytes(), nil
}

func cvDecodeComponentAck(wire []byte) (*cvComponentAck, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentAckDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentAckDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK dealer")
	}
	holder, err := r.uint64()
	if err != nil || holder > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK holder")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK digest")
	}
	sig, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(sig) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component ACK signature")
	}
	ack := &cvComponentAck{dealer: int(dealer), holder: int(holder), leafDigest: digest, signature: sig}
	canonical, err := cvComponentAckCanonicalBytes(ack)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component ACK")
	}
	return ack, nil
}

func cvComponentGetCanonicalBytes(request *cvComponentGet) ([]byte, error) {
	if request == nil || request.dealer < 0 || len(request.leafDigest) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentGetDomain))
	cvWriteUint64(&wire, uint64(request.dealer))
	_ = cvWriteBytes(&wire, request.leafDigest)
	return wire.Bytes(), nil
}

func cvDecodeComponentGet(wire []byte) (*cvComponentGet, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentGetDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentGetDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET domain")
	}
	dealer, err := r.uint64()
	if err != nil || dealer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET dealer")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS component GET digest")
	}
	request := &cvComponentGet{dealer: int(dealer), leafDigest: digest}
	canonical, err := cvComponentGetCanonicalBytes(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS component GET")
	}
	return request, nil
}
