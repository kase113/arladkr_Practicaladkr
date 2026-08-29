package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"rladkr_go/core"
	"sort"
	"strconv"
	"strings"
	"time"
)

type runStat struct {
	latencyMs                             float64
	setupMs                               float64
	completedNodes                        float64
	decidedSetMean                        float64
	aggRLOReadyMs                         float64
	admitAggAttempts                      float64
	admitAggPasses                        float64
	recoverAggSuccess                     float64
	disperseMs                            float64
	disperseLocalBuildMs                  float64
	disperseBroadcastMs                   float64
	disperseReadWaitMs                    float64
	disperseTrustedReadyMs                float64
	disperseAggregatePrewarmMs            float64
	lockAggMs                             float64
	lockAggReadyCandidatesMs              float64
	lockAggBuildAggregateMs               float64
	lockAggARCSharePrepareMs              float64
	lockAggARCShareAttachMs               float64
	lockAggCandidateCount                 float64
	lockAggARCShareSignedCnt              float64
	lockAggShareSignMs                    float64
	lockAggCertRecoverMs                  float64
	lockAggLocalAdmitMs                   float64
	mvbaOnlyMs                            float64
	mvbaPeerWaitMs                        float64
	agreeAggMs                            float64
	recoverBarrierWaitMs                  float64
	recoverServiceGraceMs                 float64
	recoverMs                             float64
	recoverOnlyMs                         float64
	recoverVerifyMs                       float64
	recoverCollectMs                      float64
	recoverVerifyOnlyMs                   float64
	recoverMaterializeMs                  float64
	deriveMs                              float64
	phaseSentBytes                        map[string]float64
	phaseRecvBytes                        map[string]float64
	totalSentBytes                        float64
	totalRecvBytes                        float64
	consensusHash                         string
	cvComponentCount                      float64
	cvARCHolderCount                      float64
	cvRecoveredShardCount                 float64
	cvVerifiedReceiptCount                float64
	cvLeafBuildMs                         float64
	cvComponentDisperseMs                 float64
	cvComponentCollectionMs               float64
	cvEligibilityCoinMs                   float64
	cvProposerSlotsMs                     float64
	cvCoinFanoutMs                        float64
	cvCandidateFanoutACKWaitMs            float64
	cvCandidateFanoutRetryWaitMs          float64
	cvCandidateFanoutMaxPeerMs            float64
	cvCandidateFanoutAttempts             float64
	cvCandidateFanoutRetries              float64
	cvAggregateDisperseMs                 float64
	cvAggregateAgreementMs                float64
	cvAPVSSACKCount                       float64
	cvAPVSSFallbackCount                  float64
	cvAPVSSProofBytes                     float64
	cvAPVSSLeafWireBytes                  float64
	cvCompletedCandidates                 float64
	cvPoolWireBytes                       float64
	cvValidationRequestBytes              float64
	cvAgreementObjectBytes                float64
	cvAggregatePayloadBytes               float64
	cvAggregateAPDBBytes                  float64
	cvPoolCertificateBytes                float64
	cvValidationCertificateBytes          float64
	cvARCCertificateBytes                 float64
	cvDecisionCertificateBytes            float64
	cvHandoffWireBytes                    float64
	cvProposerRecoverySentBytes           float64
	cvProposerRecoveryRecvBytes           float64
	cvProposerRecoveryMs                  float64
	cvProposerCatalogVerificationMs       float64
	cvProposerCatalogScanCount            float64
	cvProposerRejectedCount               float64
	cvDealerHintBuildMs                   float64
	cvDealerResponseEncodeMs              float64
	cvDealerPayloadSentBytes              float64
	cvDealerHintSentBytes                 float64
	cvHolderFragmentSentBytes             float64
	cvComponentRecoveryLateRecvBytes      float64
	cvComponentDirectPayloadHits          float64
	cvComponentFragmentRecoveries         float64
	cvComponentDirectGraceWaitMs          float64
	cvReceiverPayloadValidationMs         float64
	cvRecoveryQueueWaitMs                 float64
	cvRecoveryWorkerMs                    float64
	cvAggregateRecoveryCacheHits          float64
	cvAggregateRecoveryCacheMisses        float64
	cvAggregateRecoveryResponseMs         float64
	cvAggregateRecoveryResponseRequests   float64
	cvValidatorComponentRecoverySentBytes float64
	cvValidatorComponentRecoveryRecvBytes float64
	cvValidatorComponentRecoveryMs        float64
	cvValidatorAggregateRecoverySentBytes float64
	cvValidatorAggregateRecoveryRecvBytes float64
	cvValidatorAggregateRecoveryMs        float64
	cvNewAggregateRecoveryMs              float64
	cvARCFormationMs                      float64
	cvValidationCertificateFormationMs    float64
	cvValidationCanonicalMs               float64
	cvValidationNetworkWaitMs             float64
	cvValidationSignatureVerifyMs         float64
	cvValidationAggregateVerifyMs         float64
	cvDecisionCertificateFormationMs      float64
	cvScalarBoundedDLogMs                 float64
	cvBlindingGroupDecryptionMs           float64
	cvAggregateGateWaitMs                 float64
	cvAggregateLeafLoadMs                 float64
	cvAggregateBuildMs                    float64
	cvAggregateRSMs                       float64
	cvAggregateHeaderTokenMs              float64
	cvAggregateOfferSendMs                float64
	cvAggregateARCWaitMs                  float64
	cvAggregateCertificateMs              float64
	cvRecoverShardMs                      float64
	cvReceiptMs                           float64
}

type benchResultInput struct {
	setupBundleDigest          string
	n                          int
	fOld                       int
	fNew                       int
	kappa                      int
	runs                       int
	timeoutMs                  int64
	apvssProvider              string
	apvssMode                  string
	apvssBackendStatus         string
	apvssFullProofProfile      string
	apvssFallbackProfile       string
	apvssForcedFallbackCount   int
	apvssWaitAllACKs           bool
	experimentalAPVSS          bool
	apvssOutput                string
	securityProfile            string
	deriveMode                 string
	arcMode                    string
	agreementPath              string
	cvAPVSSMode                string
	successRuns                int
	attemptedEpochs            int
	totalAttemptLatencyMs      float64
	totalAttemptServiceGraceMs float64
	localNodes                 []int
	requiredCompleted          int
	ablationMode               string
	commMetrics                bool
	cvSampling                 core.CVScalarSamplingReport
	cvSamplingEpochs           int
	cvSamplingUnionBound       string
	stats                      []runStat
}

func main() {
	var (
		n                        = flag.Int("n", 4, "number of old/new committee nodes")
		f                        = flag.Int("f", 1, "common default Byzantine threshold for both committees")
		fOld                     = flag.Int("f-old", -1, "old-committee Byzantine threshold (-1 = use --f)")
		fNew                     = flag.Int("f-new", -1, "new-committee Byzantine threshold (-1 = use --f)")
		cvProposerSample         = flag.Int("cv-proposer-sample", 3, "scalar CV eligibility proposer sample size")
		cvValidatorSample        = flag.Int("cv-validator-sample", 3, "scalar CV aggregate validator sample size")
		cvFailureTarget          = flag.String("cv-failure-target", "smoke", "scalar CV total sampling budget: smoke|original|high-assurance|1e-*|2^-*")
		kappa                    = flag.Int("kappa", 0, "aggregate dealer count (0 = f_old+1; other values are rejected)")
		runs                     = flag.Int("runs", 1, "number of benchmark runs (fresh-epoch mode requires 1)")
		epochs                   = flag.Int("epochs", 1, "number of epochs (fresh-epoch mode requires 1)")
		epochID                  = flag.Int("epoch", 1, "epoch identifier for this fresh run")
		transport                = flag.String("transport", "tcp-distributed", "agreement transport: tcp-distributed|tcp-loopback")
		bindHost                 = flag.String("bind-host", "0.0.0.0", "tcp bind host")
		basePort                 = flag.Int("base-port", 0, "deterministic base port for node listeners when >0")
		runTimeout               = flag.Duration("timeout", 90*time.Second, "timeout per epoch run")
		waitSPBCTimeout          = flag.Duration("wait-spbc-timeout", 30*time.Second, "MVBA/SPBC wait timeout")
		routeSendTimeout         = flag.Duration("route-send-timeout", 2*time.Second, "MVBA route send timeout")
		apvssMode                = flag.String("apvss-mode", core.APVSSModeACKFallback, "APVSS component validity: full-public-ve|ack-fallback")
		apvssFullProofProfile    = flag.String("apvss-full-proof-profile", core.APVSSFullProofExact, "full-public-ve proof: exact|compact-batch|field-congruent")
		apvssFallbackProfile     = flag.String("apvss-fallback-profile", core.APVSSFallbackFeldmanBatch, "APVSS fallback proof: feldman-batch-v1|exact-lane|compact-batch")
		allowExperimentalAPVSS   = flag.Bool("allow-experimental-apvss", false, "allow an APVSS proof profile that has not passed production admission")
		apvssForcedFallbackCount = flag.Int("apvss-forced-fallback-count", 0, "benchmark-only forced |I| (0 = natural ACK scheduling)")
		apvssWaitAllACKs         = flag.Bool("apvss-wait-all-acks", false, "benchmark-only wait for all receiver ACKs to produce |I|=0")
		precomputeRuntime        = flag.Bool("precompute-runtime", true, "prepare deterministic runtime/key material before protocol timing")
		startAt                  = flag.Int64("start-at", 0, "unix timestamp to synchronise start across nodes (0 = start immediately)")
		prepareOnly              = flag.Bool("prepare-only", false, "prepare deterministic runtime material and exit")
		ablationMode             = flag.String("ablation-mode", "none", "reserved result field; scalar CV only accepts none")
		commMetrics              = flag.Bool("comm-metrics", true, "enable protocol-layer communication byte counters")
		strictNetwork            = flag.Bool("strict-network", envBoolDefault("RLADKR_STRICT_NETWORK", true), "fail if benchmark config selects local/cache protocol shortcuts")
		cvPublicKeyDir           = flag.String("cv-public-key-dir", os.Getenv("RLADKR_CV_PUBLIC_KEY_DIR"), "CV public receiver registry directory")
		cvLocalSecretDir         = flag.String("cv-local-secret-dir", os.Getenv("RLADKR_CV_LOCAL_SECRET_DIR"), "CV local receiver secret directory")
		cvLocalReceiverRaw       = flag.String("cv-local-receiver-ids", os.Getenv("RLADKR_LOCAL_RECEIVER_IDS"), "comma-separated local new-committee receiver IDs")
		cvKeygenOnly             = flag.Bool("cv-keygen-only", false, "generate scalar CV key material and exit")
		cvKeygenEpoch            = flag.Int("cv-keygen-epoch", 1, "epoch bound into generated scalar CV key material")
	)
	flag.Parse()
	if *fOld < -1 || *fNew < -1 {
		fmt.Println("f-old and f-new must be non-negative or -1")
		return
	}
	oldFaults := *f
	newFaults := *f
	if *fOld >= 0 {
		oldFaults = *fOld
	}
	if *fNew >= 0 {
		newFaults = *fNew
	}
	effectiveKappa := core.NormalizeConfig(core.Config{
		FOld:  oldFaults,
		FNew:  newFaults,
		Kappa: *kappa,
	}).Kappa
	visited := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	if !visited["cv-keygen-epoch"] {
		*cvKeygenEpoch = *epochID
	}
	apvssFallbackProfileName := strings.ToLower(strings.TrimSpace(*apvssFallbackProfile))
	apvssFullProofProfileName := strings.ToLower(strings.TrimSpace(*apvssFullProofProfile))
	apvssModeName := core.NormalizeConfig(core.Config{APVSSMode: *apvssMode}).APVSSMode

	if *runs <= 0 {
		fmt.Println("runs must be positive")
		return
	}
	if *epochs <= 0 {
		*epochs = 1
	}
	if *epochID <= 0 {
		fmt.Fprintln(os.Stderr, "epoch must be positive")
		os.Exit(1)
	}

	old := make([]int, *n)
	newC := make([]int, *n)
	for i := 0; i < *n; i++ {
		old[i] = i
		newC[i] = *n + i
	}
	sampling, err := core.ResolveCVScalarSampling(*n, oldFaults, *cvFailureTarget, *cvProposerSample, *cvValidatorSample)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CV_V2_SAMPLING_ERROR err=%v\n", err)
		return
	}
	*cvProposerSample = sampling.ProposerSampleSize
	*cvValidatorSample = sampling.ValidatorSampleSize
	runTimeoutValue := *runTimeout
	if !visited["timeout"] {
		runTimeoutValue = defaultBenchRunTimeout(*n)
	}
	waitSPBCValue := *waitSPBCTimeout
	if !visited["wait-spbc-timeout"] {
		waitSPBCValue = defaultBenchWaitSPBCTimeout(*n)
	}
	routeSendValue := *routeSendTimeout
	if !visited["route-send-timeout"] {
		routeSendValue = defaultBenchRouteSendTimeout(*n)
	}
	localNodeIDs := readLocalNodeIDsEnv(*n)
	localReceiverIDs := readLocalReceiverIDs(*cvLocalReceiverRaw, *n, localNodeIDs)
	if *cvKeygenOnly {
		if *cvKeygenEpoch <= 0 {
			fmt.Fprintln(os.Stderr, "CV_V2_KEYGEN_ERROR epoch must be positive")
			os.Exit(1)
		}
		scalarKeyConfig := core.Config{
			SID: "rladkr-go-bench", Epoch: *cvKeygenEpoch,
			OldCommittee: old, NewCommittee: newC,
			FOld: oldFaults, FNew: newFaults,
			OldFaults: oldFaults, NewFaults: newFaults,
			Kappa:                effectiveKappa,
			CVProposerSampleSize: *cvProposerSample, CVValidatorSampleSize: *cvValidatorSample,
			CVSamplingFailureTarget: sampling.Target,
		}
		if err := core.GenerateCVScalarKeyMaterial(*cvPublicKeyDir, *cvLocalSecretDir, scalarKeyConfig); err != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_KEYGEN_ERROR err=%v\n", err)
			os.Exit(1)
		}
		scalarSetupBundleDigest, err := core.CVScalarSetupBundleDigest(*cvPublicKeyDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "CV_V2_KEYGEN_ERROR err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf(
			"CV_V2_KEYGEN_OK public_dir=%s secret_dir=%s receivers=%d epoch=%d setup_bundle_digest=%s\n",
			*cvPublicKeyDir, *cvLocalSecretDir, len(newC), *cvKeygenEpoch, scalarSetupBundleDigest,
		)
		return
	}
	if err := validateCVScalarBenchmarkShape(*runs, *epochs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	setupBundleDigest, err := core.CVScalarSetupBundleDigest(*cvPublicKeyDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "CV_V2_SETUP_VERIFY_ERROR err=%v\n", err)
		os.Exit(1)
	}
	requiredCompleted := requiredCompletedNodes(*n, oldFaults, localNodeIDs)
	epochBarrierDir := strings.TrimSpace(os.Getenv("RLADKR_EPOCH_BARRIER_DIR"))
	if *prepareOnly {
		cfg := core.NormalizeConfig(core.Config{
			SID:                         "rladkr-go-bench",
			Epoch:                       *epochID,
			OldCommittee:                old,
			NewCommittee:                newC,
			FOld:                        oldFaults,
			FNew:                        newFaults,
			OldFaults:                   oldFaults,
			NewFaults:                   newFaults,
			CVProposerSampleSize:        *cvProposerSample,
			CVValidatorSampleSize:       *cvValidatorSample,
			Kappa:                       effectiveKappa,
			AgreementTransport:          *transport,
			AgreementBindHost:           *bindHost,
			AgreementBasePort:           *basePort,
			WaitSPBCTimeout:             waitSPBCValue,
			RouteSendTimeout:            routeSendValue,
			APVSSMode:                   apvssModeName,
			APVSSFullProofProfile:       apvssFullProofProfileName,
			APVSSFallbackProfile:        apvssFallbackProfileName,
			AllowExperimentalAPVSS:      *allowExperimentalAPVSS,
			APVSSBenchmarkFallbackCount: *apvssForcedFallbackCount,
			APVSSBenchmarkWaitAllACKs:   *apvssWaitAllACKs,
			AblationMode:                *ablationMode,
			CommMetrics:                 *commMetrics,
			StrictNetwork:               *strictNetwork,
			LocalNodeIDs:                localNodeIDs,
			CVPublicKeyDir:              *cvPublicKeyDir,
			CVLocalSecretDir:            *cvLocalSecretDir,
			CVLocalReceiverIDs:          localReceiverIDs,
		})
		if err := core.PrepareRuntime(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "PREPARE_RUNTIME_ERROR err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf("PREPARE_RUNTIME_OK sid=%s epoch=%d n=%d\n", cfg.SID, cfg.Epoch, len(cfg.NewCommittee))
		return
	}

	successRuns := 0
	stats := make([]runStat, 0, *runs*(*epochs))
	attemptedEpochs := 0
	totalAttemptLatencyMs := 0.0
	totalAttemptServiceGraceMs := 0.0
	agreementPath := ""
	cvAPVSSMode := ""

	for i := 0; i < *runs; i++ {
		if i > 0 {
			time.Sleep(2 * time.Second)
		}
		runSuccess := true
		for epoch := 1; epoch <= *epochs; epoch++ {
			globalEpoch := *epochID + i*(*epochs) + epoch - 1
			cfg := core.NormalizeConfig(core.Config{
				SID:                         "rladkr-go-bench",
				Epoch:                       globalEpoch,
				OldCommittee:                old,
				NewCommittee:                newC,
				FOld:                        oldFaults,
				FNew:                        newFaults,
				OldFaults:                   oldFaults,
				NewFaults:                   newFaults,
				CVProposerSampleSize:        *cvProposerSample,
				CVValidatorSampleSize:       *cvValidatorSample,
				CVSamplingFailureTarget:     sampling.Target,
				Kappa:                       effectiveKappa,
				AgreementTransport:          *transport,
				AgreementBindHost:           *bindHost,
				AgreementBasePort:           *basePort,
				WaitSPBCTimeout:             waitSPBCValue,
				RouteSendTimeout:            routeSendValue,
				APVSSMode:                   apvssModeName,
				APVSSFullProofProfile:       apvssFullProofProfileName,
				APVSSFallbackProfile:        apvssFallbackProfileName,
				AllowExperimentalAPVSS:      *allowExperimentalAPVSS,
				APVSSBenchmarkFallbackCount: *apvssForcedFallbackCount,
				APVSSBenchmarkWaitAllACKs:   *apvssWaitAllACKs,
				AblationMode:                *ablationMode,
				CommMetrics:                 *commMetrics,
				StrictNetwork:               *strictNetwork,
				LocalNodeIDs:                localNodeIDs,
				CVPublicKeyDir:              *cvPublicKeyDir,
				CVLocalSecretDir:            *cvLocalSecretDir,
				CVLocalReceiverIDs:          localReceiverIDs,
			})
			totalStart := time.Now()
			attemptedEpochs++
			ctx, cancel := context.WithTimeout(context.Background(), runTimeoutValue)
			setupMs := 0.0
			if *precomputeRuntime {
				setupStart := time.Now()
				preparedCfg, prepErr := core.PrepareConfigRuntime(cfg)
				setupMs = float64(time.Since(setupStart).Microseconds()) / 1000.0
				if prepErr != nil {
					totalAttemptLatencyMs += float64(time.Since(totalStart).Microseconds()) / 1000.0
					cancel()
					fmt.Fprintf(os.Stderr, "EPOCH_SETUP_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, prepErr)
					runSuccess = false
					break
				}
				cfg = preparedCfg
			}
			if setupDir := strings.TrimSpace(os.Getenv("RLADKR_SETUP_READY_DIR")); setupDir != "" {
				if err := os.MkdirAll(setupDir, 0o700); err != nil {
					fmt.Fprintf(os.Stderr, "EPOCH_SETUP_MARKER_ERROR err=%v\n", err)
					runSuccess = false
					break
				}
				marker := filepath.Join(setupDir, fmt.Sprintf("node-%06d.ready", localNodeIDs[0]))
				if err := os.WriteFile(marker, []byte("ready\n"), 0o600); err != nil {
					fmt.Fprintf(os.Stderr, "EPOCH_SETUP_MARKER_ERROR err=%v\n", err)
					runSuccess = false
					break
				}
			}
			// Setup is deliberately completed before the distributed start barrier.
			// This keeps setup CPU/RAM out of the synchronized protocol launch.
			if *startAt > 0 {
				for time.Now().Unix() < *startAt {
					time.Sleep(100 * time.Millisecond)
				}
			}
			traceBenchMain(localNodeIDs, "before_runepoch", fmt.Sprintf("run=%d epoch=%d", i+1, globalEpoch))
			res, err := core.RunEpoch(ctx, cfg)
			outerAttemptLatencyMs := float64(time.Since(totalStart).Microseconds()) / 1000.0
			cancel()
			if err != nil {
				totalAttemptLatencyMs += outerAttemptLatencyMs
				fmt.Fprintf(os.Stderr, "EPOCH_RUN_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, err)
				runSuccess = false
				break
			}
			if agreementPath == "" {
				agreementPath = res.AgreementMode
				cvAPVSSMode = res.CVAPVSSMode
			} else if agreementPath != res.AgreementMode || cvAPVSSMode != res.CVAPVSSMode {
				fmt.Fprintf(os.Stderr, "EPOCH_MODE_MISMATCH run=%d epoch=%d agreement=%s cv=%s\n", i+1, globalEpoch, res.AgreementMode, res.CVAPVSSMode)
				runSuccess = false
				break
			}
			traceBenchMain(localNodeIDs, "after_runepoch", fmt.Sprintf("run=%d epoch=%d completed=%d", i+1, epoch, len(res.PerNode)))
			completed := float64(len(res.PerNode))
			if completed == 0 {
				completed = float64(*n)
			}
			if int(completed) < requiredCompleted {
				fmt.Fprintf(
					os.Stderr,
					"EPOCH_RUN_INCOMPLETE run=%d epoch=%d completed=%d required=%d\n",
					i+1,
					globalEpoch,
					int(completed),
					requiredCompleted,
				)
				runSuccess = false
				break
			}
			epochLatencyMs := setupMs + resultProtocolLatencyMs(res)
			if epochLatencyMs <= setupMs {
				epochLatencyMs = outerAttemptLatencyMs
			}
			totalAttemptLatencyMs += epochLatencyMs
			resultDigest, digestErr := arlResultDigest(cfg, res)
			if digestErr != nil {
				fmt.Fprintf(os.Stderr, "EPOCH_RESULT_DIGEST_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, digestErr)
				runSuccess = false
				break
			}
			barrierCtx, barrierCancel := context.WithTimeout(context.Background(), runTimeoutValue)
			recoverServiceGraceMs := float64(res.RecoverServiceGraceLatency.Microseconds()) / 1000.0
			totalAttemptServiceGraceMs += recoverServiceGraceMs
			barrierErr := waitForBenchmarkEpochQuorum(
				barrierCtx, epochBarrierDir, cfg.SID, i+1, globalEpoch,
				old, localNodeIDs, resultDigest, *n-oldFaults,
			)
			barrierCancel()
			if barrierErr != nil {
				fmt.Fprintf(os.Stderr, "EPOCH_BARRIER_ERROR run=%d epoch=%d err=%v\n", i+1, globalEpoch, barrierErr)
				runSuccess = false
				break
			}
			stats = append(stats, runStat{
				latencyMs:                        epochLatencyMs,
				setupMs:                          setupMs + float64(res.SetupLatency.Microseconds())/1000.0,
				completedNodes:                   completed,
				decidedSetMean:                   float64(len(res.LockedSet)),
				aggRLOReadyMs:                    float64(res.AggRLOReadyLatency.Microseconds()) / 1000.0,
				admitAggAttempts:                 float64(res.AdmitAggAttempts),
				admitAggPasses:                   float64(res.AdmitAggPasses),
				recoverAggSuccess:                boolToFloat(res.RecoverAggSuccess),
				disperseMs:                       float64(res.DisperseLatency.Microseconds()) / 1000.0,
				disperseLocalBuildMs:             float64(res.DisperseLocalBuildLatency.Microseconds()) / 1000.0,
				disperseBroadcastMs:              float64(res.DisperseBroadcastLatency.Microseconds()) / 1000.0,
				disperseReadWaitMs:               float64(res.DisperseReadWaitLatency.Microseconds()) / 1000.0,
				disperseTrustedReadyMs:           float64(res.DisperseTrustedReadyLatency.Microseconds()) / 1000.0,
				disperseAggregatePrewarmMs:       float64(res.DisperseAggregatePrewarmLatency.Microseconds()) / 1000.0,
				lockAggMs:                        float64(res.LockAggLatency.Microseconds()) / 1000.0,
				lockAggReadyCandidatesMs:         float64(res.LockAggReadyCandidatesLatency.Microseconds()) / 1000.0,
				lockAggBuildAggregateMs:          float64(res.LockAggBuildAggregateLatency.Microseconds()) / 1000.0,
				lockAggARCSharePrepareMs:         float64(res.LockAggARCSharePrepareLatency.Microseconds()) / 1000.0,
				lockAggARCShareAttachMs:          float64(res.LockAggARCShareAttachLatency.Microseconds()) / 1000.0,
				lockAggCandidateCount:            float64(res.LockAggCandidateCount),
				lockAggARCShareSignedCnt:         float64(res.LockAggARCShareSignedCount),
				lockAggShareSignMs:               float64(res.LockAggShareSignLatency.Microseconds()) / 1000.0,
				lockAggCertRecoverMs:             float64(res.LockAggCertRecoverLatency.Microseconds()) / 1000.0,
				lockAggLocalAdmitMs:              float64(res.LockAggLocalAdmitLatency.Microseconds()) / 1000.0,
				mvbaOnlyMs:                       float64(res.MVBAOnlyLatency.Microseconds()) / 1000.0,
				mvbaPeerWaitMs:                   float64(res.MVBAPeerWaitLatency.Microseconds()) / 1000.0,
				agreeAggMs:                       float64(res.AgreeAggLatency.Microseconds()) / 1000.0,
				recoverBarrierWaitMs:             float64(res.RecoverBarrierWaitLatency.Microseconds()) / 1000.0,
				recoverServiceGraceMs:            recoverServiceGraceMs,
				recoverMs:                        float64(res.RecoverLatency.Microseconds()) / 1000.0,
				recoverOnlyMs:                    float64(res.RecoverOnlyLatency.Microseconds()) / 1000.0,
				recoverVerifyMs:                  float64(res.RecoverVerifyLatency.Microseconds()) / 1000.0,
				recoverCollectMs:                 float64(res.RecoverCollectLatency.Microseconds()) / 1000.0,
				recoverVerifyOnlyMs:              float64(res.RecoverVerifyOnlyLatency.Microseconds()) / 1000.0,
				recoverMaterializeMs:             float64(res.RecoverMaterializeLatency.Microseconds()) / 1000.0,
				deriveMs:                         float64(res.DeriveLatency.Microseconds()) / 1000.0,
				phaseSentBytes:                   phaseBytesFloat(res.PhaseSentBytes),
				phaseRecvBytes:                   phaseBytesFloat(res.PhaseRecvBytes),
				totalSentBytes:                   float64(res.TotalSentBytes),
				totalRecvBytes:                   float64(res.TotalRecvBytes),
				consensusHash:                    resultDigest,
				cvComponentCount:                 float64(res.CVComponentCount),
				cvARCHolderCount:                 float64(res.CVARCHolderCount),
				cvRecoveredShardCount:            float64(res.CVRecoveredShardCount),
				cvVerifiedReceiptCount:           float64(res.CVVerifiedReceiptCount),
				cvLeafBuildMs:                    float64(res.CVLeafBuildLatency.Microseconds()) / 1000.0,
				cvComponentDisperseMs:            float64(res.CVComponentDisperseLatency.Microseconds()) / 1000.0,
				cvComponentCollectionMs:          float64(res.CVComponentCollectionLatency.Microseconds()) / 1000.0,
				cvEligibilityCoinMs:              float64(res.CVEligibilityCoinLatency.Microseconds()) / 1000.0,
				cvProposerSlotsMs:                float64(res.CVProposerSlotsLatency.Microseconds()) / 1000.0,
				cvCoinFanoutMs:                   float64(res.CVCoinFanoutLatency.Microseconds()) / 1000.0,
				cvCandidateFanoutACKWaitMs:       float64(res.CVCandidateFanoutACKWaitLatency.Microseconds()) / 1000.0,
				cvCandidateFanoutRetryWaitMs:     float64(res.CVCandidateFanoutRetryWaitLatency.Microseconds()) / 1000.0,
				cvCandidateFanoutMaxPeerMs:       float64(res.CVCandidateFanoutMaxPeerLatency.Microseconds()) / 1000.0,
				cvCandidateFanoutAttempts:        float64(res.CVCandidateFanoutAttempts),
				cvCandidateFanoutRetries:         float64(res.CVCandidateFanoutRetries),
				cvAggregateDisperseMs:            float64(res.CVAggregateDisperseLatency.Microseconds()) / 1000.0,
				cvAggregateAgreementMs:           float64(res.CVAggregateAgreementLatency.Microseconds()) / 1000.0,
				cvAPVSSACKCount:                  float64(res.CVAPVSSACKCount),
				cvAPVSSFallbackCount:             float64(res.CVAPVSSFallbackCount),
				cvAPVSSProofBytes:                float64(res.CVAPVSSProofBytes),
				cvAPVSSLeafWireBytes:             float64(res.CVAPVSSLeafWireBytes),
				cvCompletedCandidates:            float64(res.CVCompletedCandidateCount),
				cvPoolWireBytes:                  float64(res.CVPoolWireBytes),
				cvValidationRequestBytes:         float64(res.CVValidationRequestWireBytes),
				cvAgreementObjectBytes:           float64(res.CVAgreementObjectWireBytes),
				cvAggregatePayloadBytes:          float64(res.CVAggregatePayloadBytes),
				cvAggregateAPDBBytes:             float64(res.CVAggregateAPDBShardBytes),
				cvPoolCertificateBytes:           float64(res.CVPoolCertificateBytes),
				cvValidationCertificateBytes:     float64(res.CVValidationCertificateBytes),
				cvARCCertificateBytes:            float64(res.CVARCCertificateBytes),
				cvDecisionCertificateBytes:       float64(res.CVDecisionCertificateBytes),
				cvHandoffWireBytes:               float64(res.CVHandoffWireBytes),
				cvProposerRecoverySentBytes:      float64(res.CVProposerRecoverySentBytes),
				cvProposerRecoveryRecvBytes:      float64(res.CVProposerRecoveryRecvBytes),
				cvProposerRecoveryMs:             float64(res.CVProposerRecoveryLatency.Microseconds()) / 1000.0,
				cvProposerCatalogVerificationMs:  float64(res.CVProposerCatalogVerificationLatency.Microseconds()) / 1000.0,
				cvProposerCatalogScanCount:       float64(res.CVProposerCatalogScanCount),
				cvProposerRejectedCount:          float64(res.CVProposerRejectedComponentCount),
				cvDealerHintBuildMs:              float64(res.CVDealerHintBuildLatency.Microseconds()) / 1000.0,
				cvDealerResponseEncodeMs:         float64(res.CVDealerResponseEncodeLatency.Microseconds()) / 1000.0,
				cvDealerPayloadSentBytes:         float64(res.CVDealerPayloadSentBytes),
				cvDealerHintSentBytes:            float64(res.CVDealerHintSentBytes),
				cvHolderFragmentSentBytes:        float64(res.CVHolderFragmentSentBytes),
				cvComponentRecoveryLateRecvBytes: float64(res.CVComponentRecoveryLateRecvBytes),
				cvComponentDirectPayloadHits:     float64(res.CVComponentDirectPayloadHits),
				cvComponentFragmentRecoveries:    float64(res.CVComponentFragmentRecoveries),
				cvComponentDirectGraceWaitMs:     float64(res.CVComponentDirectGraceWait.Microseconds()) / 1000.0,
				cvReceiverPayloadValidationMs:    float64(res.CVReceiverPayloadValidationLatency.Microseconds()) / 1000.0,
				cvRecoveryQueueWaitMs:            float64(res.CVRecoveryQueueWaitLatency.Microseconds()) / 1000.0,
				cvRecoveryWorkerMs:               float64(res.CVRecoveryWorkerLatency.Microseconds()) / 1000.0,
				cvAggregateRecoveryCacheHits:     float64(res.CVAggregateRecoveryCacheHits),
				cvAggregateRecoveryCacheMisses:   float64(res.CVAggregateRecoveryCacheMisses),
				cvAggregateRecoveryResponseMs: func() float64 {
					if res.CVAggregateRecoveryResponseRequests == 0 {
						return 0
					}
					return float64(res.CVAggregateRecoveryResponseLatency.Microseconds()) /
						(1000.0 * float64(res.CVAggregateRecoveryResponseRequests))
				}(),
				cvAggregateRecoveryResponseRequests:   float64(res.CVAggregateRecoveryResponseRequests),
				cvValidatorComponentRecoverySentBytes: float64(res.CVValidatorComponentRecoverySentBytes),
				cvValidatorComponentRecoveryRecvBytes: float64(res.CVValidatorComponentRecoveryRecvBytes),
				cvValidatorComponentRecoveryMs:        float64(res.CVValidatorComponentRecoveryLatency.Microseconds()) / 1000.0,
				cvValidatorAggregateRecoverySentBytes: float64(res.CVValidatorAggregateRecoverySentBytes),
				cvValidatorAggregateRecoveryRecvBytes: float64(res.CVValidatorAggregateRecoveryRecvBytes),
				cvValidatorAggregateRecoveryMs:        float64(res.CVValidatorAggregateRecoveryLatency.Microseconds()) / 1000.0,
				cvNewAggregateRecoveryMs:              float64(res.CVNewAggregateRecoveryLatency.Microseconds()) / 1000.0,
				cvARCFormationMs:                      float64(res.CVARCFormationLatency.Microseconds()) / 1000.0,
				cvValidationCertificateFormationMs:    float64(res.CVValidationCertificateFormationLatency.Microseconds()) / 1000.0,
				cvValidationCanonicalMs:               float64(res.CVValidationCanonicalLatency.Microseconds()) / 1000.0,
				cvValidationNetworkWaitMs:             float64(res.CVValidationNetworkWaitLatency.Microseconds()) / 1000.0,
				cvValidationSignatureVerifyMs:         float64(res.CVValidationSignatureVerifyLatency.Microseconds()) / 1000.0,
				cvValidationAggregateVerifyMs:         float64(res.CVValidationAggregateVerifyLatency.Microseconds()) / 1000.0,
				cvDecisionCertificateFormationMs:      float64(res.CVDecisionCertificateFormationLatency.Microseconds()) / 1000.0,
				cvScalarBoundedDLogMs:                 float64(res.CVScalarBoundedDLogLatency.Nanoseconds()) / 1e6,
				cvBlindingGroupDecryptionMs:           float64(res.CVBlindingGroupDecryptionLatency.Nanoseconds()) / 1e6,
				cvAggregateGateWaitMs:                 float64(res.CVAggregateGateWaitLatency.Microseconds()) / 1000.0,
				cvAggregateLeafLoadMs:                 float64(res.CVAggregateLeafLoadLatency.Microseconds()) / 1000.0,
				cvAggregateBuildMs:                    float64(res.CVAggregateBuildLatency.Microseconds()) / 1000.0,
				cvAggregateRSMs:                       float64(res.CVAggregateRSLatency.Microseconds()) / 1000.0,
				cvAggregateHeaderTokenMs:              float64(res.CVAggregateHeaderTokenLatency.Microseconds()) / 1000.0,
				cvAggregateOfferSendMs:                float64(res.CVAggregateOfferSendLatency.Microseconds()) / 1000.0,
				cvAggregateARCWaitMs:                  float64(res.CVAggregateARCWaitLatency.Microseconds()) / 1000.0,
				cvAggregateCertificateMs:              float64(res.CVAggregateCertificateLatency.Microseconds()) / 1000.0,
				cvRecoverShardMs:                      float64(res.CVRecoverShardLatency.Microseconds()) / 1000.0,
				cvReceiptMs:                           float64(res.CVReceiptLatency.Microseconds()) / 1000.0,
			})
			traceBenchMain(localNodeIDs, "after_append_stats", fmt.Sprintf("run=%d epoch=%d", i+1, globalEpoch))
		}
		if runSuccess {
			successRuns++
		}
	}

	resultFallbackProfile := apvssFallbackProfileName
	resultFullProofProfile := "none"
	backendStatus := "fallback-backend-profile-gated"
	if apvssModeName == core.APVSSModeFullPublicVE {
		resultFullProofProfile = apvssFullProofProfileName
		resultFallbackProfile = "none"
		if apvssFullProofProfileName == core.APVSSFullProofCompactBatch {
			backendStatus = "experimental-full-compact-independent-review-pending"
		} else if apvssFullProofProfileName == core.APVSSFullProofFieldCongruent {
			backendStatus = "experimental-field-congruent-proof-obligations-pending"
		} else {
			backendStatus = "functional-prototype-backend-gate-pending"
		}
	}
	samplingUnionBound, err := core.CVScalarSamplingUnionBound(sampling, len(stats))
	if err != nil {
		fmt.Fprintf(os.Stderr, "CV_V2_SAMPLING_ERROR err=%v\n", err)
		return
	}
	line := formatBenchResult(benchResultInput{
		setupBundleDigest:          setupBundleDigest,
		n:                          *n,
		fOld:                       oldFaults,
		fNew:                       newFaults,
		kappa:                      effectiveKappa,
		runs:                       *runs,
		timeoutMs:                  runTimeoutValue.Milliseconds(),
		apvssProvider:              "cv-sapvss",
		apvssMode:                  apvssModeName,
		apvssBackendStatus:         backendStatus,
		apvssFullProofProfile:      resultFullProofProfile,
		apvssFallbackProfile:       resultFallbackProfile,
		apvssForcedFallbackCount:   *apvssForcedFallbackCount,
		apvssWaitAllACKs:           *apvssWaitAllACKs,
		experimentalAPVSS:          *allowExperimentalAPVSS,
		apvssOutput:                "scalar-plus-group-blinding",
		securityProfile:            "cv-sapvss-v2-scalar-group-academic-experiment",
		deriveMode:                 "scalar-share-proof-v2",
		arcMode:                    "v2-apdb-aggregate-lock",
		agreementPath:              agreementPath,
		cvAPVSSMode:                cvAPVSSMode,
		successRuns:                successRuns,
		attemptedEpochs:            attemptedEpochs,
		totalAttemptLatencyMs:      totalAttemptLatencyMs,
		totalAttemptServiceGraceMs: totalAttemptServiceGraceMs,
		localNodes:                 append([]int(nil), localNodeIDs...),
		requiredCompleted:          requiredCompleted,
		ablationMode:               strings.ToLower(strings.TrimSpace(*ablationMode)),
		commMetrics:                *commMetrics,
		cvSampling:                 sampling,
		cvSamplingEpochs:           len(stats),
		cvSamplingUnionBound:       samplingUnionBound,
		stats:                      stats,
	})
	traceBenchMain(localNodeIDs, "before_final_print", fmt.Sprintf("success_runs=%d stats=%d", successRuns, len(stats)))
	fmt.Println(line)
	fmt.Fprintln(os.Stderr, line)
	_ = os.Stdout.Sync()
	traceBenchMain(localNodeIDs, "after_final_print", fmt.Sprintf("success_runs=%d stats=%d", successRuns, len(stats)))
	if successRuns != *runs {
		os.Exit(1)
	}
}

func validateCVScalarBenchmarkShape(runs, epochs int) error {
	if runs != 1 || epochs != 1 {
		return fmt.Errorf("CV V2 benchmark supports exactly one fresh run and one epoch; key rotation and incomplete-epoch resume are unsupported")
	}
	return nil
}

func resultProtocolLatencyMs(result *core.EpochResult) float64 {
	if result == nil {
		return 0
	}
	var maximum time.Duration
	for _, node := range result.PerNode {
		if node.Latency > maximum {
			maximum = node.Latency
		}
	}
	return float64(maximum.Microseconds()) / 1000.0
}

func defaultBenchRunTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 10 * time.Minute
	case n >= 128:
		return 5 * time.Minute
	case n >= 96:
		return 3 * time.Minute
	case n >= 64:
		return 2 * time.Minute
	default:
		return 90 * time.Second
	}
}

func defaultBenchWaitSPBCTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 3 * time.Minute
	case n >= 127:
		return 60 * time.Second
	case n >= 96:
		return 35 * time.Second
	case n >= 64:
		return 20 * time.Second
	case n >= 32:
		return 6 * time.Second
	default:
		return 2 * time.Second
	}
}

func defaultBenchRouteSendTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 20 * time.Second
	case n >= 127:
		return 12 * time.Second
	case n >= 96:
		return 8 * time.Second
	case n >= 64:
		return 5 * time.Second
	case n >= 32:
		return 1500 * time.Millisecond
	default:
		return 500 * time.Millisecond
	}
}

func traceBenchMain(localNodeIDs []int, phase string, detail string) {
	if os.Getenv("RLADKR_BENCH_DEBUG_FINALIZE") == "" {
		return
	}
	nodeLabel := intsKey(localNodeIDs)
	fmt.Fprintf(os.Stderr, "BENCH_MAIN node=%s phase=%s detail=%s\n", nodeLabel, phase, detail)
}

func readLocalNodeIDsEnv(n int) []int {
	raw := strings.TrimSpace(os.Getenv("RLADKR_LOCAL_NODE_IDS"))
	if raw == "" {
		ids := make([]int, 0, n)
		for i := 0; i < n; i++ {
			ids = append(ids, i)
		}
		return ids
	}
	valid := make(map[int]struct{}, n)
	for i := 0; i < n; i++ {
		valid[i] = struct{}{}
	}
	ids := make([]int, 0, n)
	seen := make(map[int]struct{}, n)
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		if _, ok := valid[id]; !ok {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	if len(ids) == 0 {
		for i := 0; i < n; i++ {
			ids = append(ids, i)
		}
	}
	return ids
}

func readLocalReceiverIDs(raw string, n int, localOld []int) []int {
	if strings.TrimSpace(raw) == "" && len(localOld) == 1 {
		return []int{n + localOld[0]}
	}
	allowed := make(map[int]struct{}, n)
	for i := 0; i < n; i++ {
		allowed[n+i] = struct{}{}
	}
	seen := make(map[int]struct{})
	var ids []int
	for _, part := range strings.Split(raw, ",") {
		id, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			continue
		}
		if _, ok := allowed[id]; !ok {
			continue
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids
}

func intsKey(v []int) string {
	if len(v) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(v))
	for _, id := range v {
		parts = append(parts, strconv.Itoa(id))
	}
	return strings.Join(parts, ",")
}

func requiredCompletedNodes(n int, f int, localNodeIDs []int) int {
	if len(localNodeIDs) > 0 {
		return len(localNodeIDs)
	}
	required := n - f
	if required <= 0 {
		required = 1
	}
	return required
}

func meanOf(stats []runStat, pick func(runStat) float64) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	for _, s := range stats {
		sum += pick(s)
	}
	return sum / float64(len(stats))
}

func quantileOf(stats []runStat, q float64, pick func(runStat) float64) float64 {
	if len(stats) == 0 {
		return 0
	}
	values := make([]float64, 0, len(stats))
	for _, s := range stats {
		values = append(values, pick(s))
	}
	sort.Float64s(values)
	if q <= 0 {
		return values[0]
	}
	if q >= 1 {
		return values[len(values)-1]
	}
	idx := int(q * float64(len(values)-1))
	return values[idx]
}

func sumOf(stats []runStat, pick func(runStat) float64) float64 {
	sum := 0.0
	for _, s := range stats {
		sum += pick(s)
	}
	return sum
}

func admitAggPassRatio(passes, attempts float64) float64 {
	if attempts <= 0 {
		return 0
	}
	return passes / attempts
}

func boolToFloat(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

func reportedLatencyMs(stat runStat) float64 {
	latency := stat.latencyMs - stat.recoverServiceGraceMs
	if latency < 0 {
		return 0
	}
	return latency
}

func formatBenchResult(in benchResultInput) string {
	agreementPath := strings.TrimSpace(in.agreementPath)
	if agreementPath == "" {
		agreementPath = "single-mvba-v2"
	}
	cvAPVSSMode := strings.TrimSpace(in.cvAPVSSMode)
	if cvAPVSSMode == "" {
		cvAPVSSMode = "cv-sapvss-v2-scalar-group"
	}
	arcMode := strings.ToLower(strings.TrimSpace(in.arcMode))
	if arcMode == "" || arcMode == "header-only" {
		arcMode = "header-only-recovery-obligation"
	}
	successRate := float64(in.successRuns) / float64(in.runs)
	meanRawLatency := meanOf(in.stats, func(s runStat) float64 { return s.latencyMs })
	meanLatency := meanOf(in.stats, reportedLatencyMs)
	meanRawAllLatency := meanRawLatency
	meanAllLatency := meanLatency
	if in.attemptedEpochs > 0 {
		attempts := float64(in.attemptedEpochs)
		meanRawAllLatency = in.totalAttemptLatencyMs / attempts
		meanAllLatency = (in.totalAttemptLatencyMs - in.totalAttemptServiceGraceMs) / attempts
		if meanAllLatency < 0 {
			meanAllLatency = 0
		}
	}
	meanRawP50Latency := quantileOf(in.stats, 0.50, func(s runStat) float64 { return s.latencyMs })
	meanRawP95Latency := quantileOf(in.stats, 0.95, func(s runStat) float64 { return s.latencyMs })
	p50Latency := quantileOf(in.stats, 0.50, reportedLatencyMs)
	p95Latency := quantileOf(in.stats, 0.95, reportedLatencyMs)
	meanSetup := meanOf(in.stats, func(s runStat) float64 { return s.setupMs })
	meanRecoverBarrierWait := meanOf(in.stats, func(s runStat) float64 { return s.recoverBarrierWaitMs })
	meanRecoverServiceGrace := meanOf(in.stats, func(s runStat) float64 { return s.recoverServiceGraceMs })
	meanOnline := meanLatency - meanSetup - meanRecoverBarrierWait
	if meanOnline < 0 {
		meanOnline = 0
	}
	meanOnlinePhaseWall := meanOnline
	meanOnlineActiveKnown := meanOf(in.stats, func(s runStat) float64 {
		active := 0.0
		active += s.disperseLocalBuildMs
		active += s.disperseBroadcastMs
		active += s.lockAggBuildAggregateMs
		active += s.lockAggARCSharePrepareMs
		active += s.lockAggARCShareAttachMs
		active += s.lockAggShareSignMs
		active += s.lockAggCertRecoverMs
		active += s.lockAggLocalAdmitMs
		mvbaActiveKnown := s.mvbaOnlyMs - s.mvbaPeerWaitMs
		if mvbaActiveKnown > 0 {
			active += mvbaActiveKnown
		}
		active += s.recoverVerifyOnlyMs
		active += s.recoverMaterializeMs
		active += s.deriveMs
		return active
	})
	meanCompleted := meanOf(in.stats, func(s runStat) float64 { return s.completedNodes })
	meanDecidedSet := meanOf(in.stats, func(s runStat) float64 { return s.decidedSetMean })
	meanAggRLOReady := meanOf(in.stats, func(s runStat) float64 { return s.aggRLOReadyMs })
	admitAttempts := sumOf(in.stats, func(s runStat) float64 { return s.admitAggAttempts })
	admitPasses := sumOf(in.stats, func(s runStat) float64 { return s.admitAggPasses })
	recoverSuccessRatio := meanOf(in.stats, func(s runStat) float64 { return s.recoverAggSuccess })
	meanSentBytes := meanOf(in.stats, func(s runStat) float64 { return s.totalSentBytes })
	meanRecvBytes := meanOf(in.stats, func(s runStat) float64 { return s.totalRecvBytes })
	hashSummary := summarizeConsensusHash(in.stats)

	line := fmt.Sprintf(
		"E2E_BENCH_RESULT protocol=ARLADKR-GO mode=strict agreement_path=%s cv_apvss_mode=%s arc_mode=%s cv_candidate_mode=%s cv_primary_grace_ms=%d cv_primary_pool_grace_ms=%d start_phase=epoch_setup_start online_start_phase=post_service_setup end_phase=local_decide offline_keygen_included=false setup_model=trusted-offline-owner-provisioned epoch_setup_included=true online_protocol_excludes_setup=true setup_bundle_digest=%s apvss_provider=%s apvss_mode=%s apvss_backend_status=%s apvss_full_proof_profile=%s apvss_fallback_profile=%s apvss_forced_fallback_count=%d apvss_wait_all_acks=%t experimental_apvss=%t apvss_output=%s security_profile=%s derive_mode=%s n=%d f_old=%d f_new=%d kappa=%d runs=%d timeout_ms=%d ablation_mode=%s comm_metrics=%t success_runs=%d success_rate=%.4f mean_latency_ms=%.2f mean_all_latency_ms=%.2f mean_setup_ms=%.2f mean_recover_barrier_wait_ms=%.2f mean_recover_service_grace_ms=%.2f mean_online_protocol_ms=%.2f mean_online_phase_wall_ms=%.2f mean_online_active_known_ms=%.2f p50_latency_ms=%.2f p95_latency_ms=%.2f mean_completed_nodes=%.2f mean_decided_set=%.2f mean_aggrlo_ready_ms=%.2f mean_header_obligation_ready_ms=%.2f admitagg_pass_ratio=%.4f recoveragg_success_ratio=%.4f disperse_ms=%.0f disperse_local_build_ms=%.0f disperse_broadcast_ms=%.0f disperse_read_wait_ms=%.0f disperse_trusted_ready_ms=%.0f disperse_aggregate_prewarm_ms=%.0f lockagg_ms=%.0f lockagg_ready_candidates_ms=%.0f lockagg_build_aggregate_ms=%.0f lockagg_arcshare_prepare_ms=%.0f lockagg_arcshare_attach_ms=%.0f lockagg_candidate_count=%.0f lockagg_arcshare_signed_count=%.0f lockagg_share_sign_ms=%.0f lockagg_cert_recover_ms=%.0f lockagg_local_admit_ms=%.0f mvba_only_ms=%.0f mvba_peer_wait_ms=%.0f mvba_active_known_ms=%.0f agreeagg_ms=%.0f recover_ms=%.0f recover_only_ms=%.0f recover_verify_ms=%.0f recover_collect_ms=%.0f recover_verify_only_ms=%.0f recover_materialize_ms=%.0f derive_ms=%.0f mean_total_sent_bytes=%.0f mean_total_recv_bytes=%.0f mean_agree_sent_bytes=%.0f mean_agree_recv_bytes=%.0f mean_recover_sent_bytes=%.0f mean_recover_recv_bytes=%.0f mean_recover_response_sent_bytes=%.0f mean_recover_response_recv_bytes=%.0f mean_derive_sent_bytes=%.0f mean_derive_recv_bytes=%.0f mean_agclock_prebroadcast_sent_bytes=%.0f mean_agclock_prebroadcast_recv_bytes=%.0f mean_arc_header_prebroadcast_sent_bytes=%.0f mean_arc_header_prebroadcast_recv_bytes=%.0f local_node_count=%d required_completed_nodes=%d consensus_hash=%s",
		agreementPath,
		cvAPVSSMode,
		arcMode,
		core.CVAggregateCandidateMode,
		core.CVAggregatePrimaryGrace().Milliseconds(),
		core.CVAggregatePrimaryPoolGrace().Milliseconds(),
		in.setupBundleDigest,
		in.apvssProvider,
		in.apvssMode,
		in.apvssBackendStatus,
		in.apvssFullProofProfile,
		in.apvssFallbackProfile,
		in.apvssForcedFallbackCount,
		in.apvssWaitAllACKs,
		in.experimentalAPVSS,
		in.apvssOutput,
		in.securityProfile,
		in.deriveMode,
		in.n,
		in.fOld,
		in.fNew,
		in.kappa,
		in.runs,
		in.timeoutMs,
		in.ablationMode,
		in.commMetrics,
		in.successRuns,
		successRate,
		meanLatency,
		meanAllLatency,
		meanSetup,
		meanRecoverBarrierWait,
		meanRecoverServiceGrace,
		meanOnline,
		meanOnlinePhaseWall,
		meanOnlineActiveKnown,
		p50Latency,
		p95Latency,
		meanCompleted,
		meanDecidedSet,
		meanAggRLOReady,
		meanAggRLOReady,
		admitAggPassRatio(admitPasses, admitAttempts),
		recoverSuccessRatio,
		meanOf(in.stats, func(s runStat) float64 { return s.disperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseLocalBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseBroadcastMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseReadWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseTrustedReadyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.disperseAggregatePrewarmMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggReadyCandidatesMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggBuildAggregateMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCSharePrepareMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCShareAttachMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggCandidateCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggARCShareSignedCnt }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggShareSignMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggCertRecoverMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.lockAggLocalAdmitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.mvbaOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.mvbaPeerWaitMs }),
		meanOf(in.stats, func(s runStat) float64 {
			v := s.mvbaOnlyMs - s.mvbaPeerWaitMs
			if v < 0 {
				return 0
			}
			return v
		}),
		meanOf(in.stats, func(s runStat) float64 { return s.agreeAggMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverVerifyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverCollectMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverVerifyOnlyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.recoverMaterializeMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.deriveMs }),
		meanSentBytes,
		meanRecvBytes,
		meanPhaseBytes(in.stats, "agree", true),
		meanPhaseBytes(in.stats, "agree", false),
		meanPhaseBytes(in.stats, "recover", true),
		meanPhaseBytes(in.stats, "recover", false),
		meanPhaseBytes(in.stats, "recover_response", true),
		meanPhaseBytes(in.stats, "recover_response", false),
		meanPhaseBytes(in.stats, "derive", true),
		meanPhaseBytes(in.stats, "derive", false),
		meanPhaseBytes(in.stats, "agclock_prebroadcast", true),
		meanPhaseBytes(in.stats, "agclock_prebroadcast", false),
		meanPhaseBytes(in.stats, "arc_header_prebroadcast", true),
		meanPhaseBytes(in.stats, "arc_header_prebroadcast", false),
		len(in.localNodes),
		in.requiredCompleted,
		hashSummary,
	)
	line += fmt.Sprintf(
		" cv_proposer_slot_grace_ms=%d cv_validation_first_wave_extra=%d cv_validation_first_wave_grace_ms=%d",
		core.CVSampledProposerSlotGrace(in.kappa).Milliseconds(),
		core.CVValidationFirstWaveExtra(),
		core.CVValidationFirstWaveGrace().Milliseconds(),
	)
	line += fmt.Sprintf(
		" latency_reporting=service_grace_adjusted mean_raw_latency_ms=%.2f mean_raw_all_latency_ms=%.2f p50_raw_latency_ms=%.2f p95_raw_latency_ms=%.2f",
		meanRawLatency, meanRawAllLatency, meanRawP50Latency, meanRawP95Latency,
	)
	line += fmt.Sprintf(
		" cv_failure_target=%s cv_sampling_profile=%s cv_sampling_policy=%s cv_fault_fraction=%s cv_total_failure_budget=%s cv_per_event_failure_target=%s cv_proposer_sample=%d cv_validator_sample=%d cv_validator_threshold=%d cv_proposer_failure_bound=%s cv_validator_soundness_failure_bound=%s cv_validator_liveness_failure_bound=%s cv_validator_combined_failure_bound=%s cv_contributor_sampling_failure_bound=%s cv_epoch_sampling_failure_bound=%s cv_sampling_epochs=%d cv_experiment_sampling_union_bound=%s",
		in.cvSampling.Target,
		in.cvSampling.Profile,
		in.cvSampling.Policy,
		in.cvSampling.FaultFraction,
		cvSamplingOutputValue(in.cvSampling.TotalFailureBudget),
		cvSamplingOutputValue(in.cvSampling.PerEventFailureTarget),
		in.cvSampling.ProposerSampleSize,
		in.cvSampling.ValidatorSampleSize,
		in.cvSampling.ValidatorThreshold,
		in.cvSampling.ProposerFailureBound,
		in.cvSampling.ValidatorSoundnessFailureBound,
		in.cvSampling.ValidatorLivenessFailureBound,
		in.cvSampling.ValidatorCombinedFailureBound,
		in.cvSampling.ContributorSamplingFailureBound,
		in.cvSampling.PerEpochCombinedSamplingFailureBound,
		in.cvSamplingEpochs,
		in.cvSamplingUnionBound,
	)
	cvLine := line + fmt.Sprintf(
		" cv_payload_hints=%t cv_component_recovery_schedule=%s cv_component_direct_grace_ms=%d mean_cv_component_count=%.0f mean_cv_arc_holder_count=%.0f mean_cv_recovered_shard_count=%.0f mean_cv_verified_receipt_count=%.0f leaf_build_ms=%.0f component_disperse_ms=%.0f candidate_formation_ms=%.0f eligibility_coin_ms=%.2f proposer_slots_ms=%.2f mean_coin_fanout_ms=%.2f mean_candidate_ack_wait_ms=%.2f mean_candidate_retry_wait_ms=%.2f mean_candidate_fanout_max_peer_ms=%.2f mean_candidate_fanout_attempts=%.0f mean_candidate_fanout_retries=%.0f aggregate_disperse_ms=%.0f aggregate_agreement_ms=%.0f mean_apvss_ack_count=%.2f mean_apvss_fallback_count=%.2f mean_apvss_proof_bytes=%.0f mean_apvss_leaf_wire_bytes=%.0f mean_completed_candidate_count=%.0f mean_pool_wire_bytes=%.0f mean_validation_request_wire_bytes=%.0f mean_agreement_object_wire_bytes=%.0f mean_aggregate_payload_bytes=%.0f mean_aggregate_apdb_encoded_bytes=%.0f mean_pool_certificate_bytes=%.0f mean_validation_certificate_bytes=%.0f mean_arc_certificate_bytes=%.0f mean_decision_certificate_bytes=%.0f mean_handoff_wire_bytes=%.0f mean_proposer_component_recovery_sent_bytes=%.0f mean_proposer_component_recovery_recv_bytes=%.0f mean_proposer_component_recovery_ms=%.2f mean_proposer_catalog_verify_ms=%.2f mean_proposer_catalog_scan_count=%.0f mean_proposer_rejected_component_count=%.0f mean_dealer_hint_build_ms=%.2f mean_dealer_response_encode_ms=%.2f mean_dealer_payload_sent_bytes=%.0f mean_dealer_hint_sent_bytes=%.0f mean_holder_fragment_sent_bytes=%.0f mean_component_recovery_late_recv_bytes=%.0f mean_component_direct_payload_hits=%.0f mean_component_fragment_recoveries=%.0f mean_receiver_payload_validation_ms=%.2f mean_recovery_queue_wait_ms=%.2f mean_recovery_worker_ms=%.2f mean_aggregate_recovery_cache_hits=%.0f mean_aggregate_recovery_cache_misses=%.0f mean_aggregate_recovery_response_ms=%.3f mean_aggregate_recovery_response_requests=%.0f mean_validator_component_recovery_sent_bytes=%.0f mean_validator_component_recovery_recv_bytes=%.0f mean_validator_component_recovery_ms=%.2f mean_validator_aggregate_recovery_sent_bytes=%.0f mean_validator_aggregate_recovery_recv_bytes=%.0f mean_validator_aggregate_recovery_ms=%.2f mean_arc_formation_ms=%.3f mean_vcert_formation_ms=%.3f mean_vcert_canonical_ms=%.3f mean_vcert_network_wait_ms=%.3f mean_vcert_signature_verify_ms=%.3f mean_vcert_aggregate_verify_ms=%.3f mean_deccert_formation_ms=%.3f mean_scalar_bounded_dlog_ms=%.3f mean_blinding_group_decryption_ms=%.3f aggregate_gate_wait_ms=%.2f aggregate_leaf_load_ms=%.2f aggregate_build_ms=%.2f aggregate_rs_ms=%.2f aggregate_header_token_ms=%.2f aggregate_offer_send_ms=%.2f aggregate_arc_wait_ms=%.2f aggregate_certificate_ms=%.2f recover_shard_ms=%.0f receipt_ms=%.0f mean_component_disperse_sent_bytes=%.0f mean_component_disperse_recv_bytes=%.0f mean_candidate_formation_sent_bytes=%.0f mean_candidate_formation_recv_bytes=%.0f mean_candidate_phase_counter_sent_bytes=%.0f mean_candidate_phase_counter_recv_bytes=%.0f mean_aggregate_agreement_sent_bytes=%.0f mean_aggregate_agreement_recv_bytes=%.0f mean_recover_shard_sent_bytes=%.0f mean_recover_shard_recv_bytes=%.0f mean_receipt_sent_bytes=%.0f mean_receipt_recv_bytes=%.0f mean_mvba_pd_data_sent_bytes=%.0f mean_mvba_pd_data_recv_bytes=%.0f mean_mvba_rc_data_sent_bytes=%.0f mean_mvba_rc_data_recv_bytes=%.0f mean_mvba_certificate_sent_bytes=%.0f mean_mvba_certificate_recv_bytes=%.0f",
		core.CVPayloadHintsEnabled(), core.CVComponentRecoverySchedule(), core.CVComponentDirectGraceForCommittee(in.n).Milliseconds(),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvARCHolderCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoveredShardCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvVerifiedReceiptCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvLeafBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentDisperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentCollectionMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvEligibilityCoinMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerSlotsMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCoinFanoutMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCandidateFanoutACKWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCandidateFanoutRetryWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCandidateFanoutMaxPeerMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCandidateFanoutAttempts }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCandidateFanoutRetries }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateDisperseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateAgreementMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSACKCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSFallbackCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSProofBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAPVSSLeafWireBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvCompletedCandidates }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvPoolWireBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationRequestBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAgreementObjectBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregatePayloadBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateAPDBBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvPoolCertificateBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationCertificateBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvARCCertificateBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDecisionCertificateBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvHandoffWireBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerRecoverySentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerRecoveryRecvBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerRecoveryMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerCatalogVerificationMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerCatalogScanCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvProposerRejectedCount }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDealerHintBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDealerResponseEncodeMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDealerPayloadSentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDealerHintSentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvHolderFragmentSentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentRecoveryLateRecvBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentDirectPayloadHits }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentFragmentRecoveries }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvReceiverPayloadValidationMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoveryQueueWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoveryWorkerMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRecoveryCacheHits }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRecoveryCacheMisses }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRecoveryResponseMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRecoveryResponseRequests }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorComponentRecoverySentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorComponentRecoveryRecvBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorComponentRecoveryMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorAggregateRecoverySentBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorAggregateRecoveryRecvBytes }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidatorAggregateRecoveryMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvARCFormationMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationCertificateFormationMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationCanonicalMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationNetworkWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationSignatureVerifyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvValidationAggregateVerifyMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvDecisionCertificateFormationMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvScalarBoundedDLogMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvBlindingGroupDecryptionMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateGateWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateLeafLoadMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateBuildMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateRSMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateHeaderTokenMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateOfferSendMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateARCWaitMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvAggregateCertificateMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvRecoverShardMs }),
		meanOf(in.stats, func(s runStat) float64 { return s.cvReceiptMs }),
		meanPhaseBytes(in.stats, "component_disperse", true), meanPhaseBytes(in.stats, "component_disperse", false),
		meanPhaseBytes(in.stats, "candidate_formation", true), meanPhaseBytes(in.stats, "candidate_formation", false),
		meanPhaseBytes(in.stats, "candidate_phase_counter", true), meanPhaseBytes(in.stats, "candidate_phase_counter", false),
		meanPhaseBytes(in.stats, "aggregate_agreement", true), meanPhaseBytes(in.stats, "aggregate_agreement", false),
		meanPhaseBytes(in.stats, "recover_shard", true), meanPhaseBytes(in.stats, "recover_shard", false),
		meanPhaseBytes(in.stats, "receipt", true), meanPhaseBytes(in.stats, "receipt", false),
		meanPhaseBytes(in.stats, "mvba_pd_data", true), meanPhaseBytes(in.stats, "mvba_pd_data", false),
		meanPhaseBytes(in.stats, "mvba_rc_data", true), meanPhaseBytes(in.stats, "mvba_rc_data", false),
		meanPhaseBytes(in.stats, "mvba_certificate", true), meanPhaseBytes(in.stats, "mvba_certificate", false),
	)
	cvLine += fmt.Sprintf(" cv_component_dealer_response=%s cv_component_payload_compression=%t mean_component_direct_grace_wait_ms=%.2f",
		core.CVComponentDealerResponseMode(), core.CVComponentPayloadCompressionEnabled(),
		meanOf(in.stats, func(s runStat) float64 { return s.cvComponentDirectGraceWaitMs }))
	return cvLine + fmt.Sprintf(
		" mean_component_apdb_dispersal_sent_bytes=%.0f mean_component_apdb_dispersal_recv_bytes=%.0f mean_component_recovery_data_sent_bytes=%.0f mean_component_recovery_data_recv_bytes=%.0f mean_arc_share_sent_bytes=%.0f mean_pool_coin_sent_bytes=%.0f mean_pool_coin_recv_bytes=%.0f mean_validation_request_sent_bytes=%.0f mean_validation_request_recv_bytes=%.0f mean_aggregate_apdb_dispersal_sent_bytes=%.0f mean_aggregate_apdb_dispersal_recv_bytes=%.0f mean_candidate_relay_sent_bytes=%.0f mean_candidate_relay_recv_bytes=%.0f mean_decision_handoff_sent_bytes=%.0f mean_decision_handoff_recv_bytes=%.0f mean_recovery_data_sent_bytes=%.0f mean_recovery_data_recv_bytes=%.0f mean_new_aggregate_recovery_sent_bytes=%.0f mean_new_aggregate_recovery_recv_bytes=%.0f mean_new_aggregate_recovery_ms=%.2f mean_new_share_exchange_sent_bytes=%.0f mean_new_share_exchange_recv_bytes=%.0f mean_apdb_other_sent_bytes=%.0f mean_mvba_other_sent_bytes=%.0f mean_accounted_tag_sent_bytes=%.0f mean_unclassified_sent_bytes=%.0f",
		meanPhaseBytes(in.stats, "component_apdb_dispersal", true), meanPhaseBytes(in.stats, "component_apdb_dispersal", false),
		meanPhaseBytes(in.stats, "component_recovery_data", true), meanPhaseBytes(in.stats, "component_recovery_data", false),
		meanPhaseBytes(in.stats, "arc_share", true),
		meanPhaseBytes(in.stats, "pool_coin", true), meanPhaseBytes(in.stats, "pool_coin", false),
		meanPhaseBytes(in.stats, "validation_request", true), meanPhaseBytes(in.stats, "validation_request", false),
		meanPhaseBytes(in.stats, "aggregate_apdb_dispersal", true), meanPhaseBytes(in.stats, "aggregate_apdb_dispersal", false),
		meanPhaseBytes(in.stats, "candidate_relay", true), meanPhaseBytes(in.stats, "candidate_relay", false),
		meanPhaseBytes(in.stats, "decision_handoff", true), meanPhaseBytes(in.stats, "decision_handoff", false),
		meanPhaseBytes(in.stats, "recovery_data", true), meanPhaseBytes(in.stats, "recovery_data", false),
		meanPhaseBytes(in.stats, "new_aggregate_recovery", true), meanPhaseBytes(in.stats, "new_aggregate_recovery", false),
		meanOf(in.stats, func(s runStat) float64 { return s.cvNewAggregateRecoveryMs }),
		meanPhaseBytes(in.stats, "new_share_exchange", true), meanPhaseBytes(in.stats, "new_share_exchange", false),
		meanPhaseBytes(in.stats, "apdb_other", true), meanPhaseBytes(in.stats, "mvba_other", true),
		meanAccountedSentBytes(in.stats), meanUnclassifiedSentBytes(in.stats),
	)
}

func cvSamplingOutputValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "none"
	}
	return value
}

func summarizeConsensusHash(stats []runStat) string {
	if len(stats) == 0 {
		return "none"
	}
	h := sha256.New()
	_, _ = h.Write([]byte("ARL_ADKR_BENCH_RESULT_SEQUENCE_V1"))
	for _, s := range stats {
		if s.consensusHash == "" || s.consensusHash == "none" {
			return "none"
		}
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(s.consensusHash))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func phaseBytesFloat(src map[string]uint64) map[string]float64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]float64, len(src))
	for k, v := range src {
		out[k] = float64(v)
	}
	return out
}

func meanPhaseBytes(stats []runStat, name string, sent bool) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		var phaseMap map[string]float64
		if sent {
			phaseMap = s.phaseSentBytes
		} else {
			phaseMap = s.phaseRecvBytes
		}
		if phaseMap == nil {
			continue
		}
		sum += phaseMap[name]
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

// These names are populated from disjoint transport tag groups or dedicated
// MVBA phases. Broad commPhase windows such as candidate_phase_counter and
// recover_shard are intentionally excluded because they can overlap.
var mutuallyExclusiveSentByteGroups = []string{
	"component_apdb_dispersal", "aggregate_apdb_dispersal", "arc_share", "pool_coin",
	"validation_request", "candidate_relay", "decision_handoff", "new_share_exchange",
	"component_recovery_data", "recovery_data",
	"mvba_pd_data", "mvba_rc_data", "mvba_certificate", "mvba_other", "apdb_other",
}

func meanAccountedSentBytes(stats []runStat) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, stat := range stats {
		if stat.phaseSentBytes == nil {
			continue
		}
		accounted := 0.0
		for _, name := range mutuallyExclusiveSentByteGroups {
			accounted += stat.phaseSentBytes[name]
		}
		sum += accounted
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func meanUnclassifiedSentBytes(stats []runStat) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, stat := range stats {
		accounted := 0.0
		if stat.phaseSentBytes != nil {
			for _, name := range mutuallyExclusiveSentByteGroups {
				accounted += stat.phaseSentBytes[name]
			}
		}
		residual := stat.totalSentBytes - accounted
		if residual < 0 {
			residual = 0
		}
		sum += residual
		count++
	}
	return sum / float64(count)
}

func envBoolDefault(name string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return def
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
