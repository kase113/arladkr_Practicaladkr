package core

import "time"

type AggHeader struct {
	SID             string
	Epoch           int
	Dealers         []int
	AggregateDigest []byte
	PayloadDigest   []byte
	FreshShardRoot  []byte
	MetadataHash    []byte
}

// AggLock is the recovered old-committee threshold certificate over AggHeader.
type AggLock struct {
	Threshold   int
	Certificate []byte
}

func (l AggLock) Ready() bool {
	return l.Threshold > 0 && len(l.Certificate) > 0
}

type APVSSAggregate struct {
	Provider        string
	Dealers         []int
	AggregateDigest []byte
}

// AggRLO is the materialized aggregate recovery-lock object decided by MVBA.
type AggRLO struct {
	Header    AggHeader
	Lock      AggLock
	Aggregate APVSSAggregate
	Digest    []byte
}

type NodeOutput struct {
	NodeID     int
	DecidedSet []int
	Latency    time.Duration
}

type EpochResult struct {
	AgreementMode string
	AblationMode  string
	CVAPVSSMode   string
	LockedSet     []int
	SampledSet    []int
	AggRLODealers []int

	RecoveredPayloads                       map[int][]byte
	RecoveredAggregate                      []byte
	AggRLODigest                            []byte
	AggRLOReadyLatency                      time.Duration
	AdmitAggAttempts                        int
	AdmitAggPasses                          int
	RecoverAggSuccess                       bool
	SetupLatency                            time.Duration
	DisperseLatency                         time.Duration
	DisperseLocalBuildLatency               time.Duration
	DisperseBroadcastLatency                time.Duration
	DisperseReadWaitLatency                 time.Duration
	DisperseTrustedReadyLatency             time.Duration
	DisperseAggregatePrewarmLatency         time.Duration
	LockAggLatency                          time.Duration
	LockAggReadyCandidatesLatency           time.Duration
	LockAggBuildAggregateLatency            time.Duration
	LockAggARCSharePrepareLatency           time.Duration
	LockAggARCShareAttachLatency            time.Duration
	LockAggCandidateCount                   int
	LockAggARCShareSignedCount              int
	LockAggShareSignLatency                 time.Duration
	LockAggCertRecoverLatency               time.Duration
	LockAggLocalAdmitLatency                time.Duration
	MVBAOnlyLatency                         time.Duration
	MVBAPeerWaitLatency                     time.Duration
	AgreeAggLatency                         time.Duration
	RecoverBarrierWaitLatency               time.Duration
	RecoverServiceGraceLatency              time.Duration
	RecoverLatency                          time.Duration
	RecoverOnlyLatency                      time.Duration
	RecoverVerifyLatency                    time.Duration
	RecoverCollectLatency                   time.Duration
	RecoverVerifyOnlyLatency                time.Duration
	RecoverMaterializeLatency               time.Duration
	DeriveLatency                           time.Duration
	TotalSentBytes                          uint64
	TotalRecvBytes                          uint64
	PhaseSentBytes                          map[string]uint64
	PhaseRecvBytes                          map[string]uint64
	NewShares                               map[int][]byte
	NewPublicKey                            []byte
	CVReceipts                              map[int][]byte
	CVComponentCount                        int
	CVARCHolderCount                        int
	CVRecoveredShardCount                   int
	CVVerifiedReceiptCount                  int
	CVSampling                              CVScalarSamplingReport
	CVLeafBuildLatency                      time.Duration
	CVComponentDisperseLatency              time.Duration
	CVComponentCollectionLatency            time.Duration
	CVEligibilityCoinLatency                time.Duration
	CVProposerSlotsLatency                  time.Duration
	CVCoinFanoutLatency                     time.Duration
	CVCandidateFanoutACKWaitLatency         time.Duration
	CVCandidateFanoutRetryWaitLatency       time.Duration
	CVCandidateFanoutMaxPeerLatency         time.Duration
	CVCandidateFanoutAttempts               int
	CVCandidateFanoutRetries                int
	CVAggregateDisperseLatency              time.Duration
	CVAggregateAgreementLatency             time.Duration
	CVRecoverShardLatency                   time.Duration
	CVReceiptLatency                        time.Duration
	CVAPVSSACKCount                         int
	CVAPVSSFallbackCount                    int
	CVAPVSSProofBytes                       int
	CVAPVSSLeafWireBytes                    int
	CVCompletedCandidateCount               int
	CVPoolWireBytes                         int
	CVValidationRequestWireBytes            int
	CVAgreementObjectWireBytes              int
	CVAggregatePayloadBytes                 int
	CVAggregateAPDBShardBytes               int
	CVPoolCertificateBytes                  int
	CVValidationCertificateBytes            int
	CVARCCertificateBytes                   int
	CVDecisionCertificateBytes              int
	CVHandoffWireBytes                      int
	CVProposerRecoverySentBytes             uint64
	CVProposerRecoveryRecvBytes             uint64
	CVProposerRecoveryLatency               time.Duration
	CVProposerCatalogVerificationLatency    time.Duration
	CVProposerCatalogScanCount              int
	CVProposerRejectedComponentCount        int
	CVDealerHintBuildLatency                time.Duration
	CVDealerResponseEncodeLatency           time.Duration
	CVDealerPayloadSentBytes                uint64
	CVDealerHintSentBytes                   uint64
	CVHolderFragmentSentBytes               uint64
	CVComponentRecoveryLateRecvBytes        uint64
	CVComponentDirectPayloadHits            uint64
	CVComponentFragmentRecoveries           uint64
	CVComponentDirectGraceWait              time.Duration
	CVReceiverPayloadValidationLatency      time.Duration
	CVRecoveryQueueWaitLatency              time.Duration
	CVRecoveryWorkerLatency                 time.Duration
	CVAggregateRecoveryCacheHits            uint64
	CVAggregateRecoveryCacheMisses          uint64
	CVComponentRecoveryCacheHits            uint64
	CVComponentRecoveryCacheMisses          uint64
	CVAggregateRecoveryResponseLatency      time.Duration
	CVAggregateRecoveryResponseRequests     uint64
	CVValidatorComponentRecoverySentBytes   uint64
	CVValidatorComponentRecoveryRecvBytes   uint64
	CVValidatorComponentRecoveryLatency     time.Duration
	CVValidatorAggregateRecoverySentBytes   uint64
	CVValidatorAggregateRecoveryRecvBytes   uint64
	CVValidatorAggregateRecoveryLatency     time.Duration
	CVNewAggregateRecoveryLatency           time.Duration
	CVARCFormationLatency                   time.Duration
	CVValidationCertificateFormationLatency time.Duration
	CVValidationCanonicalLatency            time.Duration
	CVValidationNetworkWaitLatency          time.Duration
	CVValidationSignatureVerifyLatency      time.Duration
	CVValidationAggregateVerifyLatency      time.Duration
	CVDecisionCertificateFormationLatency   time.Duration
	CVScalarBoundedDLogLatency              time.Duration
	CVBlindingGroupDecryptionLatency        time.Duration
	CVAggregateGateWaitLatency              time.Duration
	CVAggregateLeafLoadLatency              time.Duration
	CVAggregateBuildLatency                 time.Duration
	CVAggregateRSLatency                    time.Duration
	CVAggregateHeaderTokenLatency           time.Duration
	CVAggregateOfferSendLatency             time.Duration
	CVAggregateARCWaitLatency               time.Duration
	CVAggregateCertificateLatency           time.Duration

	PerNode []NodeOutput
}
