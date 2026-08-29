package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"practical_adkr/core"
)

type runStat struct {
	latencyMs      float64
	completedNodes float64
	decidedSetMean float64
	selectedMean   float64
	verifiedMean   float64
	phaseMs        map[string]float64
	phaseCounts    map[string]float64
	phaseSentBytes map[string]float64
	phaseRecvBytes map[string]float64
	totalSentBytes float64
	totalRecvBytes float64
	consensusHash  string
}

func main() {
	var (
		n              = flag.Int("n", 10, "paper-style committee size; old and new committees both have n members")
		f              = flag.Int("f", -1, "byzantine threshold; -1 derives floor((n-1)/3) from committee size")
		kappa          = flag.Int("kappa", 0, "explicit selected transcript count; 0 uses kappa-profile")
		kappaProfile   = flag.String("kappa-profile", "matched-lifetime", "automatic kappa profile: practical-original|matched-single-epoch|matched-lifetime|high-assurance|deterministic-inclusion")
		kappaFailProb  = flag.Float64("kappa-failure-prob", 1e-10, "per-epoch failure target for practical-original")
		kappaBits      = flag.Float64("kappa-security-bits", 0, "matched statistical security bits; 0 uses the selected profile default")
		kappaLifeEpoch = flag.Uint64("kappa-lifetime-epochs", 525600, "maximum reconfigurations used by matched-lifetime and union-bound reporting")
		runs           = flag.Int("runs", 3, "number of benchmark runs")
		timeout        = flag.Duration("timeout", 30*time.Second, "timeout per run")
		paillierBits   = flag.Int("paillier-bits", 3072, "Paillier modulus bits (3072 for the matched 128-bit security profile; pass 2048 only for compatibility results)")
		mvbaNetwork    = flag.String("mvba-network", "tcp", "MVBA network mode: tcp")
		mvbaAddrs      = flag.String("mvba-addrs", "", "MVBA node addresses, e.g. 0=10.0.0.1:9000,1=10.0.0.2:9000")
		mvbaLocalIDs   = flag.String("mvba-local-ids", "", "local node IDs for tcp mode, e.g. 0,1,2")
		protoAddrs     = flag.String("proto-addrs", os.Getenv("PRACTICAL_PROTO_NODE_ADDRS"), "DXT/APDB node addresses, e.g. 0=10.0.0.1:9100,100=10.0.0.2:9101")
		protoLocalIDs  = flag.String("proto-local-ids", os.Getenv("PRACTICAL_PROTO_LOCAL_NODE_IDS"), "DXT/APDB local node IDs, e.g. 0,1,100,101")
		coinAddrs      = flag.String("coin-addrs", "", "dedicated threshold Coin.Get addresses for old nodes")
		compAddrs      = flag.String("comp-addrs", os.Getenv("PRACTICAL_COMP_NODE_ADDRS"), "dedicated CompProve addresses for new nodes")
		partialAddrs   = flag.String("partial-verify-addrs", os.Getenv("PRACTICAL_PARTIAL_VERIFY_NODE_ADDRS"), "dedicated partial-verification addresses for new nodes")
		commMetrics    = flag.Bool("comm-metrics", false, "enable protocol-layer communication byte counters")
		setupKeygen    = flag.Bool("setup-keygen-only", false, "generate owner-provisioned trusted setup artifacts and exit")
		setupOutputDir = flag.String("setup-output-dir", os.Getenv("PRACTICAL_SETUP_OUTPUT_DIR"), "output directory for --setup-keygen-only")
	)
	flag.Parse()
	visited := make(map[string]bool)
	flag.Visit(func(current *flag.Flag) {
		visited[current.Name] = true
	})

	if *n <= 0 {
		fmt.Fprintln(os.Stderr, "invalid n")
		os.Exit(1)
	}
	committeeSize := *n
	if !visited["timeout"] {
		*timeout = defaultPracticalBenchTimeout(committeeSize)
	}
	if *f < -1 {
		fmt.Fprintln(os.Stderr, "invalid f (must be -1 or non-negative)")
		os.Exit(1)
	}
	if *f == -1 {
		*f = (committeeSize - 1) / 3
	}
	if committeeSize < 3**f+1 {
		fmt.Fprintln(os.Stderr, "invalid f for given n (must satisfy committee size n >= 3f+1)")
		os.Exit(1)
	}
	if *runs <= 0 {
		fmt.Fprintln(os.Stderr, "runs must be positive")
		os.Exit(1)
	}
	kappaSelection, err := core.ResolvePracticalKappaForCommittee(committeeSize, *f, *kappa, core.KappaPolicy{
		Profile:               core.KappaProfile(*kappaProfile),
		PerEpochFailureTarget: *kappaFailProb,
		MatchedSecurityBits:   *kappaBits,
		LifetimeEpochs:        *kappaLifeEpoch,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid kappa security policy: %v\n", err)
		os.Exit(1)
	}
	effectiveKappa := kappaSelection.Kappa
	oldC := make([]int, committeeSize)
	newC := make([]int, committeeSize)
	for i := 0; i < committeeSize; i++ {
		oldC[i] = i
		newC[i] = committeeSize + i
	}
	sort.Ints(oldC)
	sort.Ints(newC)

	mvbaAddrsVal := *mvbaAddrs
	if strings.TrimSpace(mvbaAddrsVal) == "" {
		if env := os.Getenv("PRACTICAL_MVBA_NODE_ADDRS"); strings.TrimSpace(env) != "" {
			mvbaAddrsVal = strings.TrimSpace(env)
		}
	}
	if strings.TrimSpace(mvbaAddrsVal) == "" {
		parts := make([]string, 0, len(oldC))
		for _, id := range oldC {
			parts = append(parts, fmt.Sprintf("%d=127.0.0.1:%d", id, 23000+id))
		}
		mvbaAddrsVal = strings.Join(parts, ",")
	}
	mvbaLocalIDsVal := *mvbaLocalIDs
	if strings.TrimSpace(mvbaLocalIDsVal) == "" {
		if env := os.Getenv("PRACTICAL_MVBA_LOCAL_NODE_IDS"); strings.TrimSpace(env) != "" {
			mvbaLocalIDsVal = strings.TrimSpace(env)
		}
	}
	if strings.TrimSpace(mvbaLocalIDsVal) == "" {
		items := make([]string, 0, len(oldC))
		for _, id := range oldC {
			items = append(items, fmt.Sprintf("%d", id))
		}
		mvbaLocalIDsVal = strings.Join(items, ",")
	}
	// Keep MVBA listener IDs aligned with the old committee only.
	// This avoids binding extra listeners that may collide with protocol-stage
	// ports (especially when environment exports a larger global node-id set).
	mvbaLocalIDsVal = clampLocalIDsToCommittee(mvbaLocalIDsVal, oldC)
	protoAddrsVal, err := buildProtocolAddrMap(*protoAddrs, mvbaAddrsVal, oldC, newC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid protocol addrs: %v\n", err)
		os.Exit(1)
	}
	protoLocalIDsVal := buildProtocolLocalIDs(*protoLocalIDs, mvbaLocalIDsVal, oldC, newC)
	if err := validateProtocolCompleteness(protoAddrsVal, protoLocalIDsVal, oldC, newC); err != nil {
		fmt.Fprintf(os.Stderr, "invalid protocol transport config: %v\n", err)
		os.Exit(1)
	}
	coinAddrsVal := strings.TrimSpace(*coinAddrs)
	if coinAddrsVal == "" {
		coinAddrsVal = strings.TrimSpace(os.Getenv("PRACTICAL_COIN_NODE_ADDRS"))
	}
	if coinAddrsVal == "" {
		parts := make([]string, 0, len(oldC))
		for i, id := range oldC {
			parts = append(parts, fmt.Sprintf("%d=127.0.0.1:%d", id, 18000+i))
		}
		coinAddrsVal = strings.Join(parts, ",")
	}

	cfg := core.Config{
		SID:                    "practical-adkr-bench",
		OldCommittee:           oldC,
		NewCommittee:           newC,
		F:                      *f,
		Kappa:                  effectiveKappa,
		PaillierBits:           *paillierBits,
		MVBANetwork:            *mvbaNetwork,
		MVBANodeAddrs:          mvbaAddrsVal,
		MVBALocalNodeIDs:       mvbaLocalIDsVal,
		ProtocolNodeAddrs:      protoAddrsVal,
		ProtocolLocalNodeIDs:   protoLocalIDsVal,
		CoinNodeAddrs:          coinAddrsVal,
		CompNodeAddrs:          strings.TrimSpace(*compAddrs),
		PartialVerifyNodeAddrs: strings.TrimSpace(*partialAddrs),
		CommMetrics:            *commMetrics,
		StrictNetwork:          true,
	}
	if *setupKeygen {
		digest, err := core.GeneratePracticalSetupProvision(*setupOutputDir, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PRACTICAL_SETUP_KEYGEN_ERROR err=%v\n", err)
			os.Exit(1)
		}
		fmt.Printf(
			"PRACTICAL_SETUP_KEYGEN_OK output_dir=%s nodes=%d coin_threshold=%d setup_bundle_digest=%s\n",
			*setupOutputDir, len(oldC), len(oldC)-*f, digest,
		)
		return
	}
	setupBundleDigest := "unmanifested"
	setupCacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if setupCacheDir != "" {
		_, manifestErr := os.Stat(setupCacheDir + string(os.PathSeparator) + "setup-manifest.json")
		if manifestErr == nil || envBoolDefault("PRACTICAL_SETUP_READ_ONLY", false) {
			setupBundleDigest, err = core.VerifyPracticalSetupProvision(setupCacheDir, cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "verify provisioned setup failed: %v\n", err)
				os.Exit(1)
			}
		}
	}
	fmt.Printf(
		"KAPPA_SECURITY n=%d f=%d profile=%s population=%d kappa=%d epoch_failure_prob=%.12g epoch_security_bits=%.6g lifetime_epochs=%d lifetime_union_bound=%.12g lifetime_security_bits=%.6g\n",
		committeeSize,
		*f,
		kappaSelection.Profile,
		kappaSelection.Population,
		kappaSelection.Kappa,
		kappaSelection.EpochFailureProbability,
		kappaSelection.EpochSecurityBits,
		kappaSelection.LifetimeEpochs,
		kappaSelection.LifetimeFailureUnionBound,
		kappaSelection.LifetimeSecurityBits,
	)

	// Count local nodes from MVBA local IDs (old committee members on this host).
	// In distributed mode (PRACTICAL_MVBA_NODE_ADDRS set), each host runs a subset.
	localNodeIDs := parseNodeIDSet(mvbaLocalIDsVal)
	localNodeCount := len(localNodeIDs)
	localBarrierNodes := make([]int, 0, localNodeCount)
	for id := range localNodeIDs {
		localBarrierNodes = append(localBarrierNodes, id)
	}
	sort.Ints(localBarrierNodes)
	if localNodeCount == 0 {
		// Local mode or all nodes local: count = n
		localNodeCount = committeeSize
		localBarrierNodes = append([]int(nil), oldC...)
	}
	epochBarrierDir := strings.TrimSpace(os.Getenv("PRACTICAL_EPOCH_BARRIER_DIR"))
	if *runs > 1 && localNodeCount < committeeSize && epochBarrierDir == "" {
		fmt.Fprintln(os.Stderr, "multi-epoch distributed benchmark requires PRACTICAL_EPOCH_BARRIER_DIR")
		os.Exit(1)
	}

	// Optional synchronized start for shared-host multiprocess harnesses:
	// every node waits until the same wall-clock deadline so startup skew does
	// not eat into per-phase readiness windows. Deployment runners keep the
	// Leave the variable unset for immediate start.
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_START_AT_UNIX")); raw != "" {
		if deadline, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil {
			if wait := time.Until(time.Unix(deadline, 0)); wait > 0 {
				time.Sleep(wait)
			}
		}
	}

	stats := make([]runStat, 0, *runs)
	successRuns := 0
	totalLatencyAllRuns := 0.0
	epochBase := uint64(0)
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_EPOCH_BASE")); raw != "" {
		parsed, parseErr := strconv.ParseUint(raw, 10, 64)
		if parseErr != nil {
			fmt.Fprintf(os.Stderr, "invalid PRACTICAL_EPOCH_BASE=%q\n", raw)
			os.Exit(1)
		}
		epochBase = parsed
	}
	requiredCompleted := localNodeCount
	if requiredCompleted > committeeSize-2**f {
		requiredCompleted = committeeSize - 2**f
	}
	if requiredCompleted < *f+1 {
		requiredCompleted = *f + 1
	}
	if requiredCompleted > localNodeCount {
		requiredCompleted = localNodeCount
	}
	for i := 0; i < *runs; i++ {
		runCfg := cfg
		runCfg.Epoch = epochBase + uint64(i)
		attemptStart := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		start := time.Now()
		res, err := core.RunPracticalADKR(ctx, runCfg)
		cancel()
		attemptMs := float64(time.Since(attemptStart).Microseconds()) / 1000.0
		if attemptMs <= 0 {
			attemptMs = float64(timeout.Milliseconds())
		}
		totalLatencyAllRuns += attemptMs
		if err != nil {
			fmt.Printf("PRACTICAL_RUN_ERROR run=%d err=%q\n", i, err)
			fmt.Fprintf(os.Stderr, "run=%d failed: %v\n", i, err)
			if perr, ok := err.(*core.PartialResultError); ok && perr != nil && perr.Result != nil {
				res = perr.Result
			} else {
				continue
			}
		}
		if res == nil {
			fmt.Fprintf(os.Stderr, "run=%d failed: %v\n", i, err)
			continue
		}
		// Count only the nodes that actually completed on this host.
		// If local IDs are not configured, fall back to all old-committee nodes.
		localCompleted := 0
		if len(localNodeIDs) == 0 {
			for _, no := range res.PerNode {
				if no.Completed {
					localCompleted++
				}
			}
		} else {
			for _, no := range res.PerNode {
				if _, ok := localNodeIDs[no.NodeID]; ok && no.Completed {
					localCompleted++
				}
			}
		}
		completed := float64(localCompleted)
		if int(completed) < requiredCompleted {
			continue
		}
		protocolLatencyMs := float64(time.Since(start).Microseconds()) / 1000.0
		resultDigest, digestErr := practicalResultDigest(runCfg, res)
		if digestErr != nil {
			fmt.Fprintf(os.Stderr, "run=%d result digest failed: %v\n", i, digestErr)
			continue
		}
		barrierCtx, barrierCancel := context.WithTimeout(context.Background(), *timeout)
		barrierErr := waitForBenchmarkEpoch(
			barrierCtx, epochBarrierDir, runCfg.SID, i+1, runCfg.Epoch,
			oldC, localBarrierNodes, resultDigest,
		)
		barrierCancel()
		if barrierErr != nil {
			fmt.Fprintf(os.Stderr, "run=%d epoch barrier failed: %v\n", i, barrierErr)
			continue
		}
		successRuns++
		stats = append(stats, runStat{
			latencyMs:      protocolLatencyMs,
			completedNodes: completed,
			decidedSetMean: float64(len(res.DecidedSet)),
			selectedMean:   float64(res.SelectedCount),
			verifiedMean:   float64(res.VerifiedCount),
			phaseMs:        phaseTimingsMs(res.PhaseTimings),
			phaseCounts:    phaseCountsFloat(res.PhaseTimings),
			phaseSentBytes: phaseBytesFloat(res.PhaseSentBytes),
			phaseRecvBytes: phaseBytesFloat(res.PhaseRecvBytes),
			totalSentBytes: float64(res.TotalSentBytes),
			totalRecvBytes: float64(res.TotalRecvBytes),
			consensusHash:  resultDigest,
		})
	}

	successRate := float64(successRuns) / float64(*runs)
	meanLatency := meanOf(stats, func(s runStat) float64 { return s.latencyMs })
	meanAllLatency := totalLatencyAllRuns / float64(*runs)
	p50Latency := quantileOf(stats, 0.50, func(s runStat) float64 { return s.latencyMs })
	p95Latency := quantileOf(stats, 0.95, func(s runStat) float64 { return s.latencyMs })
	meanCompleted := meanOf(stats, func(s runStat) float64 { return s.completedNodes })
	meanDecidedSet := meanOf(stats, func(s runStat) float64 { return s.decidedSetMean })
	meanSelected := meanOf(stats, func(s runStat) float64 { return s.selectedMean })
	meanVerified := meanOf(stats, func(s runStat) float64 { return s.verifiedMean })
	meanSentBytes := meanOf(stats, func(s runStat) float64 { return s.totalSentBytes })
	meanRecvBytes := meanOf(stats, func(s runStat) float64 { return s.totalRecvBytes })
	timeoutRuns := *runs - successRuns
	consensusHash := summarizePracticalResultDigests(stats)

	fmt.Printf(strings.Replace(
		"E2E_BENCH_RESULT protocol=PRACTICAL-ADKR mode=strict start_phase=epoch_setup_start online_start_phase=post_service_setup end_phase=local_decide offline_keygen_included=false setup_bundle_digest=%s n=%d committee_size=%d total_logical_participants=%d f=%d kappa=%d kappa_profile=%s kappa_epoch_failure_prob=%.12g kappa_epoch_security_bits=%.6g kappa_lifetime_epochs=%d kappa_lifetime_union_bound=%.12g kappa_lifetime_security_bits=%.6g runs=%d timeout_ms=%d comm_metrics=%t success_runs=%d success_rate=%.4f mean_latency_ms=%.2f mean_all_latency_ms=%.2f p50_latency_ms=%.2f p95_latency_ms=%.2f mean_completed_nodes=%.2f mean_decided_set=%.2f mean_selected_count=%.2f mean_verified_count=%.2f mean_setup_ms=%.2f mean_online_protocol_ms=%.2f mean_online_active_known_ms=%.2f mean_dxt_dealing_ms=%.2f mean_dxt_network_build_ms=%.2f mean_dxt_network_wait_ms=%.2f mean_dxt_cache_hit_ms=%.2f mean_dxt_cache_build_ms=%.2f mean_dxt_cache_wait_ms=%.2f mean_apdb_dispersal_ms=%.2f mean_mvba_agree_ms=%.2f mean_mvba_peer_wait_ms=%.2f mean_mvba_active_known_ms=%.2f mean_coin_select_ms=%.2f mean_partial_verify_ms=%.2f mean_recover_ms=%.2f mean_recover_ready_ms=%.2f mean_recover_completion_ms=%.2f mean_recover_store_verify_ms=%.2f mean_recover_shard_verify_ms=%.2f mean_recover_verify_ms=%.2f mean_recover_store_seen=%.2f mean_recover_fetch_req_sent=%.2f mean_recover_fetch_resp_recv=%.2f mean_recover_recipient_seen=%.2f mean_derive_ms=%.2f mean_aggregate_derive_ms=%.2f mean_total_phase_ms=%.2f mean_total_sent_bytes=%.2f mean_total_recv_bytes=%.2f mean_dxt_sent_bytes=%.2f mean_dxt_recv_bytes=%.2f mean_apdb_sent_bytes=%.2f mean_apdb_recv_bytes=%.2f mean_mvba_sent_bytes=%.2f mean_mvba_recv_bytes=%.2f mean_coin_sent_bytes=%.2f mean_coin_recv_bytes=%.2f mean_partial_verify_sent_bytes=%.2f mean_partial_verify_recv_bytes=%.2f mean_recover_sent_bytes=%.2f mean_recover_recv_bytes=%.2f mean_derive_sent_bytes=%.2f mean_derive_recv_bytes=%.2f timeout_runs=%d local_node_count=%d consensus_hash=%s\n",
		"offline_keygen_included=false",
		"offline_keygen_included=false setup_model=trusted-offline-owner-provisioned epoch_setup_included=true online_protocol_excludes_setup=true",
		1,
	),
		setupBundleDigest,
		*n,
		committeeSize,
		committeeSize*2,
		*f,
		effectiveKappa,
		kappaSelection.Profile,
		kappaSelection.EpochFailureProbability,
		kappaSelection.EpochSecurityBits,
		kappaSelection.LifetimeEpochs,
		kappaSelection.LifetimeFailureUnionBound,
		kappaSelection.LifetimeSecurityBits,
		*runs,
		timeout.Milliseconds(),
		*commMetrics,
		successRuns,
		successRate,
		meanLatency,
		meanAllLatency,
		p50Latency,
		p95Latency,
		meanCompleted,
		meanDecidedSet,
		meanSelected,
		meanVerified,
		meanPhaseMs(stats, "setup"),
		meanOnlineProtocolMs(stats),
		meanOnlineActiveKnownMs(stats),
		meanPhaseMs(stats, "dxt_dealing"),
		meanPhaseMs(stats, "dxt_network_build"),
		meanPhaseMs(stats, "dxt_network_wait"),
		meanPhaseMs(stats, "dxt_cache_hit"),
		meanPhaseMs(stats, "dxt_cache_build"),
		meanPhaseMs(stats, "dxt_cache_wait"),
		meanPhaseMs(stats, "apdb_dispersal"),
		meanPhaseMs(stats, "mvba_agree"),
		meanPhaseMs(stats, "mvba_peer_wait"),
		meanPhaseMs(stats, "mvba_active_known"),
		meanPhaseMs(stats, "coin_select"),
		meanPhaseMs(stats, "partial_verify"),
		meanPhaseMs(stats, "recover"),
		meanPhaseMs(stats, "recover_ready"),
		meanPhaseMs(stats, "recover_completion"),
		meanPhaseMs(stats, "recover_store_verify"),
		meanPhaseMs(stats, "recover_shard_verify"),
		meanPhaseMs(stats, "recover_verify"),
		meanPhaseCount(stats, "recover_store_seen"),
		meanPhaseCount(stats, "recover_fetch_req_sent"),
		meanPhaseCount(stats, "recover_fetch_resp_recv"),
		meanPhaseCount(stats, "recover_recipient_seen"),
		meanPhaseMs(stats, "derive"),
		meanPhaseMs(stats, "aggregate_derive"),
		meanPhaseMs(stats, "total"),
		meanSentBytes,
		meanRecvBytes,
		meanPhaseBytes(stats, "dxt_dealing", true),
		meanPhaseBytes(stats, "dxt_dealing", false),
		meanPhaseBytes(stats, "apdb_dispersal", true),
		meanPhaseBytes(stats, "apdb_dispersal", false),
		meanPhaseBytes(stats, "mvba_agree", true),
		meanPhaseBytes(stats, "mvba_agree", false),
		meanPhaseBytes(stats, "coin_select", true),
		meanPhaseBytes(stats, "coin_select", false),
		meanPhaseBytes(stats, "partial_verify", true),
		meanPhaseBytes(stats, "partial_verify", false),
		meanPhaseBytes(stats, "recover", true),
		meanPhaseBytes(stats, "recover", false),
		meanPhaseBytes(stats, "derive", true),
		meanPhaseBytes(stats, "derive", false),
		timeoutRuns,
		localNodeCount,
		consensusHash,
	)
	if successRuns != *runs {
		os.Exit(1)
	}
	grace := durationFromEnvMs("PRACTICAL_RECOVER_SERVICE_GRACE_MS")
	if responderGrace := durationFromEnvMs("PRACTICAL_RESPONDER_GRACE_MS"); responderGrace > grace {
		grace = responderGrace
	}
	if grace > 0 {
		time.Sleep(grace)
	}
}

func defaultPracticalBenchTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 30 * time.Minute
	case n >= 128:
		return 20 * time.Minute
	case n >= 96:
		return 15 * time.Minute
	case n >= 64:
		return 10 * time.Minute
	case n >= 32:
		return 5 * time.Minute
	default:
		return 90 * time.Second
	}
}

func durationFromEnvMs(name string) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	v, err := strconv.Atoi(raw)
	if err != nil || v <= 0 {
		return 0
	}
	return time.Duration(v) * time.Millisecond
}

func phaseTimingsMs(timings map[string]time.Duration) map[string]float64 {
	out := make(map[string]float64, len(timings))
	for name, d := range timings {
		if isPhaseCount(name) {
			continue
		}
		out[name] = float64(d.Microseconds()) / 1000.0
	}
	// In local proc-sim, shared DXT cache build/wait is a precompute artifact
	// rather than protocol-online work. Fold it into setup so the reported
	// online latency better matches the intended paper-style boundary.
	out["setup"] += out["dxt_cache_build"] + out["dxt_cache_wait"]
	return out
}

func phaseCountsFloat(timings map[string]time.Duration) map[string]float64 {
	out := make(map[string]float64)
	for name, d := range timings {
		if !isPhaseCount(name) {
			continue
		}
		out[name] = float64(d)
	}
	return out
}

func isPhaseCount(name string) bool {
	switch name {
	case "recover_store_seen", "recover_fetch_req_sent", "recover_fetch_resp_recv", "recover_recipient_seen":
		return true
	default:
		return false
	}
}

func meanPhaseMs(stats []runStat, name string) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		if s.phaseMs == nil {
			continue
		}
		sum += s.phaseMs[name]
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func meanPhaseCount(stats []runStat, name string) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		if s.phaseCounts == nil {
			continue
		}
		sum += s.phaseCounts[name]
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func meanOnlineProtocolMs(stats []runStat) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		if s.phaseMs == nil {
			continue
		}
		online := s.phaseMs["total"] - s.phaseMs["setup"]
		if online < 0 {
			online = 0
		}
		sum += online
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func meanOnlineActiveKnownMs(stats []runStat) float64 {
	if len(stats) == 0 {
		return 0
	}
	sum := 0.0
	count := 0
	for _, s := range stats {
		if s.phaseMs == nil {
			continue
		}
		active := 0.0
		active += s.phaseMs["dxt_dealing"]
		active += s.phaseMs["apdb_dispersal"]
		active += s.phaseMs["mvba_active_known"]
		active += s.phaseMs["coin_select"]
		active += s.phaseMs["partial_verify"]
		active += s.phaseMs["recover_store_verify"]
		active += s.phaseMs["recover_shard_verify"]
		active += s.phaseMs["recover_verify"]
		active += s.phaseMs["derive"]
		sum += active
		count++
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
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

func buildProtocolAddrMap(protoRaw, mvbaRaw string, oldC, newC []int) (string, error) {
	protoMap := parseNodeAddrMap(protoRaw)
	mvbaMap := parseNodeAddrMap(mvbaRaw)
	used := make(map[string]struct{}, len(protoMap))
	for _, addr := range protoMap {
		if strings.TrimSpace(addr) != "" {
			used[addr] = struct{}{}
		}
	}

	for _, id := range oldC {
		if _, ok := protoMap[id]; ok {
			continue
		}
		if addr, ok := mvbaMap[id]; ok && strings.TrimSpace(addr) != "" {
			protoMap[id] = addr
			used[addr] = struct{}{}
			continue
		}
		addr := fmt.Sprintf("127.0.0.1:%d", 26000+id)
		protoMap[id] = addr
		used[addr] = struct{}{}
	}

	for i, id := range newC {
		if _, ok := protoMap[id]; ok {
			continue
		}
		baseAddr := ""
		if i < len(oldC) {
			baseAddr = protoMap[oldC[i]]
		}
		if strings.TrimSpace(baseAddr) == "" {
			baseAddr = fmt.Sprintf("127.0.0.1:%d", 27000+i)
		}
		host, port, err := splitHostPort(baseAddr)
		if err != nil {
			host = "127.0.0.1"
			port = 27000 + i
		} else {
			port += 10000
		}
		candidate := net.JoinHostPort(host, strconv.Itoa(port))
		candidate = dedupeAddr(candidate, used)
		protoMap[id] = candidate
		used[candidate] = struct{}{}
	}

	return formatNodeAddrMap(protoMap), nil
}

func buildProtocolLocalIDs(protoRaw, mvbaRaw string, oldC, newC []int) string {
	protoSet := parseNodeIDSet(protoRaw)
	mvbaSet := parseNodeIDSet(mvbaRaw)
	if len(protoSet) == 0 {
		protoSet = make(map[int]struct{}, len(oldC)+len(newC))
	}
	for _, id := range oldC {
		if len(mvbaSet) == 0 {
			protoSet[id] = struct{}{}
			continue
		}
		if _, ok := mvbaSet[id]; ok {
			protoSet[id] = struct{}{}
		}
	}
	for i, oldID := range oldC {
		if _, ok := protoSet[oldID]; ok && i < len(newC) {
			protoSet[newC[i]] = struct{}{}
		}
	}
	return formatNodeIDSet(protoSet)
}

func validateProtocolCompleteness(addrCSV, localCSV string, oldC, newC []int) error {
	addrMap := parseNodeAddrMap(addrCSV)
	localSet := parseNodeIDSet(localCSV)
	// Every node (old+new) must have a routable address.
	for _, id := range append(append([]int(nil), oldC...), newC...) {
		if _, ok := addrMap[id]; !ok {
			return fmt.Errorf("missing address for node id %d", id)
		}
	}
	// Local set may be a subset of all node IDs – each process only hosts
	// its own subset in multi-node distributed deployments.  As long as
	// every locally-declared ID also has an address, the config is valid.
	for id := range localSet {
		if _, ok := addrMap[id]; !ok {
			return fmt.Errorf("local listener id %d has no address", id)
		}
	}
	return nil
}

func parseNodeAddrMap(raw string) map[int]string {
	out := make(map[int]string)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	for _, item := range strings.Split(raw, ",") {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			continue
		}
		addr := strings.TrimSpace(kv[1])
		if addr == "" {
			continue
		}
		out[id] = addr
	}
	return out
}

func parseNodeIDSet(raw string) map[int]struct{} {
	out := make(map[int]struct{})
	if strings.TrimSpace(raw) == "" {
		return out
	}
	for _, item := range strings.Split(raw, ",") {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		id, err := strconv.Atoi(part)
		if err != nil {
			continue
		}
		out[id] = struct{}{}
	}
	return out
}

func clampLocalIDsToCommittee(raw string, committee []int) string {
	allowed := make(map[int]struct{}, len(committee))
	for _, id := range committee {
		allowed[id] = struct{}{}
	}
	set := parseNodeIDSet(raw)
	keys := make([]int, 0, len(set))
	for id := range set {
		if _, ok := allowed[id]; ok {
			keys = append(keys, id)
		}
	}
	if len(keys) == 0 {
		keys = append(keys, committee...)
	}
	sort.Ints(keys)
	out := make([]string, 0, len(keys))
	for _, id := range keys {
		out = append(out, strconv.Itoa(id))
	}
	return strings.Join(out, ",")
}

func formatNodeAddrMap(m map[int]string) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d=%s", k, m[k]))
	}
	return strings.Join(parts, ",")
}

func formatNodeIDSet(m map[int]struct{}) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, strconv.Itoa(k))
	}
	return strings.Join(parts, ",")
}

func splitHostPort(addr string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, err
	}
	return host, port, nil
}

func dedupeAddr(candidate string, used map[string]struct{}) string {
	host, port, err := splitHostPort(candidate)
	if err != nil {
		return candidate
	}
	for {
		if _, ok := used[candidate]; !ok {
			return candidate
		}
		port++
		candidate = net.JoinHostPort(host, strconv.Itoa(port))
	}
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
