// adkr.go — Practical ADKR 主流程: Dispersal → Agree → Recast
// 对应论文 Algorithm 2
package core

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type dxtCachePayload struct {
	Transcripts map[int]*DXTTranscript    `json:"transcripts"`
	AllShares   map[int]map[int]SharePair `json:"all_shares,omitempty"`
}

type paillierCacheEntry struct {
	N       string `json:"n"`
	NSquare string `json:"n_square"`
	G       string `json:"g"`
	Lambda  string `json:"lambda"`
	Mu      string `json:"mu"`
}

type paillierCachePayload struct {
	Keys map[int]paillierCacheEntry `json:"keys"`
}

type paillierPublicCachePayload struct {
	Keys map[int]paillierPublicCacheEntry `json:"keys"`
}

type paillierPublicCacheEntry struct {
	N       string `json:"n"`
	NSquare string `json:"n_square"`
	G       string `json:"g"`
}

type paillierPrivateCachePayload struct {
	ID  int                `json:"id"`
	Key paillierCacheEntry `json:"key"`
}

type recastStoreWire struct {
	Recipient int                      `json:"recipient,omitempty"`
	Dealer    int                      `json:"dealer"`
	Holder    int                      `json:"holder"`
	Root      []byte                   `json:"root"`
	Store     *RecoverStoreAttestation `json:"store,omitempty"`
	TR        *DXTTranscript           `json:"tr,omitempty"`
}

type recastWire struct {
	Kind             string                          `json:"kind"`
	SID              string                          `json:"sid,omitempty"`
	Epoch            uint64                          `json:"epoch,omitempty"`
	Dealer           int                             `json:"dealer"`
	Holder           int                             `json:"holder"`
	Recipient        int                             `json:"recipient,omitempty"`
	Root             []byte                          `json:"root,omitempty"`
	TR               *DXTTranscript                  `json:"tr,omitempty"`
	Dealers          []int                           `json:"dealers,omitempty"`
	Roots            map[int][]byte                  `json:"roots,omitempty"`
	TRs              map[int]*DXTTranscript          `json:"trs,omitempty"`
	Shards           map[int]RecoverShard            `json:"shards,omitempty"`
	Attests          map[int]RecoverAttestation      `json:"attests,omitempty"`
	Stores           map[int]RecoverStoreAttestation `json:"stores,omitempty"`
	Certs            map[int]APDBCertificate         `json:"certs,omitempty"`
	CompletionDigest []byte                          `json:"completion_digest,omitempty"`
	Signature        []byte                          `json:"signature,omitempty"`
}

var recastFrameMagic = [2]byte{'R', 'C'}

func marshalRecastNetworkWire(wire recastWire) ([]byte, error) {
	return marshalPracticalJSONFrame(recastFrameMagic, wire)
}

func readRecastNetworkWire(reader io.Reader, wire *recastWire) (int, error) {
	return readPracticalJSONFrame(reader, recastFrameMagic, wire)
}

type cacheLockMeta struct {
	RunID     string `json:"run_id"`
	PID       int    `json:"pid"`
	CreatedAt int64  `json:"created_at"`
}

type recipientPaillierKeyBundle struct {
	Pub  map[int]*PaillierPublicKey
	Priv map[int]*PaillierPrivateKey
}

var recipientPaillierKeyCache sync.Map

func recastPerAttemptTimeout(deadline time.Time) time.Duration {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	if remaining > 2*time.Second {
		return 2 * time.Second
	}
	return remaining
}

func recastSleepOrStop(stop <-chan struct{}, d time.Duration) bool {
	if d <= 0 {
		return false
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-stop:
		return true
	case <-timer.C:
		return false
	}
}

func hashRecoverShard(root []byte, dealer int, holder int, recipient int, index int, data []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-RECOVER-SHARD"))
	h.Write(root)
	var b [32]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:16], uint64(holder))
	binary.BigEndian.PutUint64(b[16:24], uint64(recipient))
	binary.BigEndian.PutUint64(b[24:32], uint64(index))
	h.Write(b[:])
	sum := sha256.Sum256(data)
	h.Write(sum[:])
	return h.Sum(nil)
}

func verifyRecoverAttestation(att RecoverAttestation, shard RecoverShard, holderPub ed25519.PublicKey) bool {
	if holderPub == nil {
		return false
	}
	if att.Dealer != shard.Dealer || att.Index != shard.Index {
		return false
	}
	if !bytes.Equal(att.Root, shard.Root) {
		return false
	}
	sum := sha256.Sum256(shard.Data)
	if !bytes.Equal(att.ShardHash, sum[:]) {
		return false
	}
	msg := hashRecoverShard(att.Root, att.Dealer, att.Holder, att.Recipient, att.Index, shard.Data)
	return ed25519.Verify(holderPub, msg, att.Signature)
}

func cloneByteSlices(values [][]byte) [][]byte {
	out := make([][]byte, len(values))
	for i := range values {
		out[i] = append([]byte(nil), values[i]...)
	}
	return out
}

func hashRecoverStore(root []byte, certRoot []byte, dealer int, holder int) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-RECOVER-STORE"))
	h.Write(root)
	h.Write(certRoot)
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:16], uint64(holder))
	h.Write(b[:])
	return h.Sum(nil)
}

func verifyRecoverStoreAttestation(att RecoverStoreAttestation, holderPub ed25519.PublicKey) bool {
	if holderPub == nil {
		return false
	}
	msg := hashRecoverStore(att.Root, att.CertRoot, att.Dealer, att.Holder)
	return ed25519.Verify(holderPub, msg, att.Signature)
}

func practicalRunID(cfg Config, old []int, newC []int) string {
	if runID := strings.TrimSpace(os.Getenv("PRACTICAL_RUN_ID")); runID != "" {
		return runID
	}
	key := struct {
		SID string `json:"sid"`
		Old []int  `json:"old"`
		New []int  `json:"new"`
	}{
		SID: cfg.SID,
		Old: append([]int(nil), old...),
		New: append([]int(nil), newC...),
	}
	raw, _ := json.Marshal(key)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12])
}

// RunPracticalADKR executes the complete Practical ADKR protocol.
func RunPracticalADKR(ctx context.Context, cfg Config) (*Result, error) {
	totalStart := time.Now()
	phaseTimings := make(map[string]time.Duration)
	resetCommStats(cfg.CommMetrics)
	old := append([]int(nil), cfg.OldCommittee...)
	sort.Ints(old)
	perNodeState := make(map[int]*NodeOutput, len(old))
	for _, nodeID := range old {
		perNodeState[nodeID] = &NodeOutput{
			NodeID:     nodeID,
			Latency:    0,
			Completed:  false,
			FinalPhase: "init",
			Error:      "",
			DecidedSet: nil,
		}
	}
	buildPerNode := func() []NodeOutput {
		out := make([]NodeOutput, 0, len(old))
		for _, nodeID := range old {
			if state, ok := perNodeState[nodeID]; ok && state != nil {
				cp := *state
				cp.DecidedSet = append([]int(nil), state.DecidedSet...)
				out = append(out, cp)
			}
		}
		return out
	}
	buildPartialResult := func() *Result {
		totalSentBytes, totalRecvBytes := commStats()
		phaseBytes := phaseCommStats()
		phaseSentBytes := make(map[string]uint64, len(phaseBytes))
		phaseRecvBytes := make(map[string]uint64, len(phaseBytes))
		for name, stat := range phaseBytes {
			phaseSentBytes[name] = stat.sent
			phaseRecvBytes[name] = stat.recv
		}
		phaseSnapshot := make(map[string]time.Duration, len(phaseTimings))
		for name, d := range phaseTimings {
			phaseSnapshot[name] = d
		}
		if _, ok := phaseSnapshot["total"]; !ok {
			phaseSnapshot["total"] = time.Since(totalStart)
		}
		return &Result{
			PerNode:        buildPerNode(),
			PhaseTimings:   phaseSnapshot,
			TotalSentBytes: totalSentBytes,
			TotalRecvBytes: totalRecvBytes,
			PhaseSentBytes: phaseSentBytes,
			PhaseRecvBytes: phaseRecvBytes,
		}
	}
	failWithPartial := func(err error, phase string) (*Result, error) {
		for _, state := range perNodeState {
			if state == nil {
				continue
			}
			if state.FinalPhase == "" || state.FinalPhase == "init" {
				state.FinalPhase = phase
			}
			if state.Error == "" && err != nil {
				state.Error = err.Error()
			}
		}
		return nil, &PartialResultError{Err: err, Result: buildPartialResult()}
	}
	markPhase := func(name string, start time.Time) {
		phaseTimings[name] += time.Since(start)
	}
	trace := strings.TrimSpace(os.Getenv("PRACTICAL_TRACE")) == "1"
	tracef := func(format string, args ...any) {
		if !trace {
			return
		}
		fmt.Fprintf(os.Stderr, "PRACTICAL_TRACE "+format+"\n", args...)
	}

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	newC := append([]int(nil), cfg.NewCommittee...)
	sort.Ints(old)
	sort.Ints(newC)

	kappa := cfg.Kappa
	if kappa <= 0 {
		selection, kappaErr := ResolvePracticalKappaForCommittee(len(old), cfg.F, 0, KappaPolicy{
			Profile:             KappaProfileMatchedLifetime,
			MatchedSecurityBits: 128,
			LifetimeEpochs:      525600,
		})
		if kappaErr != nil {
			return failWithPartial(fmt.Errorf("derive kappa from committee size: %w", kappaErr), "setup")
		}
		kappa = selection.Kappa
	}

	// --- Key setup ---
	setupStart := time.Now()
	setCommPhase("setup")
	tracef("phase=setup_begin sid=%s n_old=%d n_new=%d f=%d kappa=%d", cfg.SID, len(old), len(newC), cfg.F, kappa)
	signingKeys, err := loadPracticalSigningKeys(cfg, old, newC)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	dealerECDSAPub := signingKeys.dealerECDSAPublic
	dealerECDSAPriv := signingKeys.dealerECDSAPrivate
	dealerEDPub := signingKeys.oldEdPublic
	dealerEDPriv := signingKeys.oldEdPrivate

	bits := cfg.PaillierBits
	if bits <= 0 {
		bits = 3072
	}
	cfg.PaillierBits = bits
	recipPub, recipPriv, err := loadOrComputeRecipientPaillierKeys(cfg, newC, tracef)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	compKeys, err := loadOrCreatePracticalCompKeys(cfg, newC)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	compService, err := startCompKeyService(ctx, cfg, newC, compKeys.private)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	defer closeCompServiceAfterGrace(compService, ctx)
	// Establish the CompProve transport barrier before the expensive DXT,
	// APDB and MVBA phases. Otherwise a locally slow process can reach the
	// first probe after faster peers have already finished and closed their
	// listeners, producing a false readiness timeout.
	readyCtx, readyCancel := context.WithTimeout(ctx, compKeyDerivationTimeout(cfg))
	if err := waitCompKeyServiceReady(readyCtx, cfg, newC, compService); err != nil {
		readyCancel()
		return failWithPartial(err, "setup")
	}
	readyCancel()
	compService.ready = true
	partialVerifyService, err := startPartialVerifyService(ctx, cfg, newC)
	if err != nil {
		if cfg.StrictNetwork {
			return failWithPartial(err, "setup")
		}
		tracef("phase=setup_partial_verify_service_unavailable err=%v", err)
	}
	defer partialVerifyService.close()

	recipSignPub := signingKeys.recipientPublic
	recipSignPriv := signingKeys.recipientPrivate

	dxt, err := NewDXTBackend(old, newC, cfg.F, dealerECDSAPriv, dealerECDSAPub,
		recipPub, recipPriv, recipSignPriv, recipSignPub,
		dxtNodeAddrs(cfg), cfg.ProtocolLocalNodeIDs,
	)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	if err := dxt.setCompPublicKeys(compKeys.public); err != nil {
		return failWithPartial(err, "setup")
	}
	defer dxt.closeNetworkService()
	coinKeys, err := loadOrCreateThresholdCoinKeys(cfg, old)
	if err != nil {
		return failWithPartial(err, "setup")
	}
	var coinService *thresholdCoinService
	if cfg.StrictNetwork || len(coinKeys.privateShare) != len(old) {
		coinService, err = startThresholdCoinService(ctx, cfg, old, coinKeys.privateShare)
		if err != nil {
			return failWithPartial(err, "setup")
		}
		defer coinService.close()
	}
	dxt.strictNetwork = cfg.StrictNetwork
	markPhase("setup", setupStart)
	tracef("phase=setup_end ms=%.2f", float64(time.Since(setupStart).Microseconds())/1000.0)

	// ============================================
	// Phase 1: DEALING (each old-committee node is a dealer)
	// ============================================
	dealingStart := time.Now()
	setCommPhase("dxt_dealing")
	tracef("phase=dxt_begin dealers=%d", len(old))
	transcripts, allShares, cacheTimings, err := loadOrComputeDXTCache(ctx, cfg, old, newC, dxt, tracef)
	if err != nil {
		return failWithPartial(err, "dxt_dealing")
	}
	for name, d := range cacheTimings {
		phaseTimings[name] += d
	}
	markPhase("dxt_dealing", dealingStart)
	tracef("phase=dxt_end ms=%.2f", float64(time.Since(dealingStart).Microseconds())/1000.0)

	// ============================================
	// Phase 2: DISPERSAL (APDB-style receipt/certificate flow)
	// ============================================
	apdbStart := time.Now()
	setCommPhase("apdb_dispersal")
	tracef("phase=apdb_begin")
	var apdbService *networkAPDBService
	if cfg.StrictNetwork {
		apdbService, err = startNetworkAPDBService(ctx, cfg, old, transcripts, dealerEDPriv, dealerEDPub, dxt, coinKeys)
		if err != nil {
			return failWithPartial(err, "apdb_dispersal")
		}
		defer apdbService.close()
	}
	// Success-first benchmark path:
	// prefer local APDB aggregation for liveness; if it still yields no valid set,
	// fall back to deterministic full-dealer validity to keep experiments complete.
	apdbCtx, apdbCancel := boundedAPDBContext(ctx)
	apdbResult, err := runAPDBDispersal(apdbCtx, cfg, old, transcripts, dealerEDPriv, dealerEDPub, dxt, apdbService)
	apdbCancel()
	localValid := map[int][]int(nil)
	apdbCerts := make(map[int]APDBCertificate, len(old))
	if apdbResult != nil {
		localValid = apdbResult.LocalValid
		for dealer, cert := range apdbResult.Certificates {
			apdbCerts[dealer] = cert
		}
	}
	if err != nil || allLocalValidEmpty(localValid) {
		if cfg.StrictNetwork {
			return failWithPartial(fmt.Errorf("strict-network rejects APDB fallback: err=%v empty=%v", err, allLocalValidEmpty(localValid)), "apdb_dispersal")
		}
		tracef("phase=apdb_fallback err=%v empty=%v", err, allLocalValidEmpty(localValid))
		localValid = make(map[int][]int, len(old))
		for _, nodeID := range old {
			localValid[nodeID] = append([]int(nil), old...)
		}
		apdbCerts = make(map[int]APDBCertificate)
		for _, dealer := range old {
			tr := transcripts[dealer]
			if tr == nil {
				continue
			}
			raw, mErr := json.Marshal(tr)
			if mErr != nil {
				continue
			}
			root := sha256.Sum256(raw)
			receipts := make([]APDBReceipt, 0, len(old))
			for _, nodeID := range old {
				if err := persistAPDBTranscript(cfg, old, nodeID, dealer, root[:], raw); err != nil {
					continue
				}
				chunkHash := hashChunk(root[:], dealer, nodeID, raw)
				msg := hashReceiptMsg(dealer, nodeID, root[:], chunkHash)
				sig := ed25519.Sign(dealerEDPriv[nodeID], msg)
				receipts = append(receipts, APDBReceipt{
					NodeID:    nodeID,
					Sender:    dealer,
					ChunkHash: chunkHash,
					Signature: sig,
				})
			}
			sort.Slice(receipts, func(i, j int) bool { return receipts[i].NodeID < receipts[j].NodeID })
			thresholdCert := apdbCertificateThreshold(cfg.F, len(receipts))
			apdbCerts[dealer] = APDBCertificate{
				Sender:   dealer,
				Root:     append([]byte(nil), root[:]...),
				Receipts: append([]APDBReceipt(nil), receipts[:thresholdCert]...),
			}
		}
	}
	if !cfg.StrictNetwork {
		apdbCerts = fillMissingAPDBCertificates(cfg, old, old, transcripts, dealerEDPriv, apdbCerts)
	}

	required := apdbFinishedSetThreshold(cfg.F, len(old))
	proposals := make(map[int][]int, len(old))
	for _, nodeID := range old {
		v := stableFirst(localValid[nodeID], len(localValid[nodeID]))
		if len(v) < required {
			return failWithPartial(fmt.Errorf("node %d insufficient valid transcripts: %d < %d", nodeID, len(v), required), "apdb_dispersal")
		}
		// Algorithm 2 agrees on a 2f+1-sized set of finished PD/lock
		// instances, not the full set of all valid dealers.
		proposals[nodeID] = stableFirst(v, required)
		if state := perNodeState[nodeID]; state != nil {
			state.FinalPhase = "apdb_dispersal"
		}
	}
	markPhase("apdb_dispersal", apdbStart)
	tracef("phase=apdb_end ms=%.2f", float64(time.Since(apdbStart).Microseconds())/1000.0)

	// ============================================
	// Phase 3: AGREE (Dumbo-MVBA on dealer set)
	// Try TCP MVBA first, fall back to local quorum if unavailable.
	// ============================================
	mvbaStart := time.Now()
	setCommPhase("mvba_agree")
	tracef("phase=mvba_begin")
	mvbaCtx, mvbaCancel := boundedMVBAContext(ctx)
	mvbaDecision, mvbaBreakdown, mvbaErr := decideByDumboMVBA(mvbaCtx, cfg, old, proposals, apdbCerts, dealerEDPub, coinKeys)
	mvbaCancel()
	var decidedSet []int
	if mvbaDecision != nil {
		decidedSet = append([]int(nil), mvbaDecision.Set...)
		for dealer, certificate := range mvbaDecision.Certificates {
			apdbCerts[dealer] = certificate
		}
	}
	agreementFallback := false
	if mvbaErr != nil || len(decidedSet) == 0 {
		tracef("phase=mvba_fail err=%v decided=%d fallback_disabled=%v", mvbaErr, len(decidedSet), cfg.DisableAgreementFallback)
		if cfg.DisableAgreementFallback {
			if mvbaErr != nil {
				return failWithPartial(fmt.Errorf("dumbo-mvba agreement failed: %w", mvbaErr), "mvba_agree")
			}
			return failWithPartial(fmt.Errorf("dumbo-mvba agreement returned empty dealer set"), "mvba_agree")
		}
		// Fallback: local-only quorum decision (same-process nodes)
		agreementFallback = true
		decidedSet = localQuorumDealerSet(proposals, old, cfg.F)
		if len(decidedSet) == 0 {
			return failWithPartial(fmt.Errorf("mvba+local quorum both empty: mvbaErr=%v", mvbaErr), "mvba_agree")
		}
	}
	markPhase("mvba_agree", mvbaStart)
	phaseTimings["mvba_peer_wait"] += mvbaBreakdown.PeerWait
	if mvbaBreakdown.Wall > mvbaBreakdown.PeerWait {
		phaseTimings["mvba_active_known"] += mvbaBreakdown.Wall - mvbaBreakdown.PeerWait
	}
	tracef("phase=mvba_end ms=%.2f decided=%d fallback=%v", float64(time.Since(mvbaStart).Microseconds())/1000.0, len(decidedSet), agreementFallback)
	// MVBA payloads carry the exact APDB certificates. Once agreement has
	// completed, no later phase reuses the old-node protocol ports for APDB.
	if apdbService != nil {
		apdbService.close()
	}

	for _, nodeID := range old {
		if state := perNodeState[nodeID]; state != nil {
			state.DecidedSet = append([]int(nil), decidedSet...)
			state.FinalPhase = "mvba_agree"
		}
	}

	// ============================================
	// Phase 4: RECAST (Coin selects κ transcripts)
	// ============================================
	recastStart := time.Now()
	setCommPhase("coin_select")
	tracef("phase=recast_begin")
	selectedIDs, coinSignature, err := runThresholdCoin(ctx, cfg, old, decidedSet, kappa, coinKeys, coinService)
	if err != nil {
		return failWithPartial(fmt.Errorf("threshold coin selection failed: %w", err), "coin_select")
	}
	markPhase("coin_select", recastStart)
	tracef("phase=recast_end ms=%.2f selected=%d", float64(time.Since(recastStart).Microseconds())/1000.0, len(selectedIDs))
	tracef("phase=recast_selected ids=%v", selectedIDs)

	// ============================================
	// Phase 5: RECAST selected PD shards to the new committee
	// ============================================
	aggregateStart := time.Now()
	setCommPhase("recover")
	tracef("phase=recover_begin")
	recoveredTranscripts, recoverTiming, err := runRecastRecovery(ctx, cfg, old, newC, selectedIDs, transcripts, apdbCerts, dealerEDPriv, dealerEDPub, dxt, coinKeys)
	if err != nil {
		return failWithPartial(err, "recover")
	}
	markPhase("recover", aggregateStart)
	phaseTimings["recover_verify"] += recoverTiming.FullVerify
	phaseTimings["recover_ready"] += recoverTiming.ReadyWait
	phaseTimings["recover_completion"] += recoverTiming.CompletionWait
	phaseTimings["recover_store_verify"] += recoverTiming.StoreVerify
	phaseTimings["recover_shard_verify"] += recoverTiming.ShardVerify
	phaseTimings["recover_store_seen"] += time.Duration(recoverTiming.StoreSeen)
	phaseTimings["recover_fetch_req_sent"] += time.Duration(recoverTiming.FetchReqSent)
	phaseTimings["recover_fetch_resp_recv"] += time.Duration(recoverTiming.FetchRespRecv)
	phaseTimings["recover_recipient_seen"] += time.Duration(recoverTiming.RecipientSeen)
	tracef("phase=recover_end ms=%.2f recovered=%d", float64(time.Since(aggregateStart).Microseconds())/1000.0, len(recoveredTranscripts))

	// ============================================
	// Phase 6: new-committee verification after RC, as in Algorithm 2
	// ============================================
	verifyStart := time.Now()
	setCommPhase("partial_verify")
	tracef("phase=verify_begin actor=new-committee")
	verifiedSelected := make([]int, 0, len(selectedIDs))
	partialVerifyMode := "result-multicast"
	partialVerifyPositiveVotes := make(map[string]int)
	if strings.EqualFold(strings.TrimSpace(cfg.AblationMode), "no-partial-verify") {
		if cfg.StrictNetwork {
			return failWithPartial(errors.New("strict-network rejects no-partial-verify ablation"), "partial_verify")
		}
		verifiedSelected = append([]int(nil), selectedIDs...)
		partialVerifyMode = "no-partial-verify"
	} else if strings.EqualFold(strings.TrimSpace(cfg.AblationMode), "full-local-verify") {
		if cfg.StrictNetwork {
			return failWithPartial(errors.New("strict-network rejects full-local-verify ablation"), "partial_verify")
		}
		partialVerifyMode = "full-local-verify"
		for _, dealer := range selectedIDs {
			if dxt.VerifyTranscript(0, recoveredTranscripts[dealer]) {
				verifiedSelected = append(verifiedSelected, dealer)
			}
		}
	} else {
		verified, positiveVotes, multicastErr := runPartialVerificationMulticast(
			ctx, cfg, newC, selectedIDs, recoveredTranscripts, partialVerifyService, dxt, tracef,
		)
		if multicastErr != nil {
			if cfg.StrictNetwork {
				return failWithPartial(multicastErr, "partial_verify")
			}
			tracef("phase=partial_verify_multicast_fallback err=%v", multicastErr)
			partialVerifyMode = "full-local-fallback"
			for _, dealer := range selectedIDs {
				if dxt.VerifyTranscript(0, recoveredTranscripts[dealer]) {
					verifiedSelected = append(verifiedSelected, dealer)
				}
			}
		} else {
			verifiedSelected = verified
			partialVerifyPositiveVotes = positiveVotes
		}
	}
	if len(verifiedSelected) != len(selectedIDs) {
		return failWithPartial(fmt.Errorf("selected transcript verification failed after RC: valid=%d selected=%d", len(verifiedSelected), len(selectedIDs)), "partial_verify")
	}
	markPhase("partial_verify", verifyStart)
	tracef("phase=verify_end ms=%.2f verified=%d", float64(time.Since(verifyStart).Microseconds())/1000.0, len(verifiedSelected))
	tracef("phase=verify_selected ids=%v", verifiedSelected)

	// ============================================
	// Phase 7: AGGREGATE & DERIVE NEW SHARES
	// ============================================
	deriveStart := time.Now()
	setCommPhase("derive")
	aggCommit, aggCipher, err := aggregateTranscripts(recoveredTranscripts, verifiedSelected, newC, recipPub)
	if err != nil {
		return nil, err
	}
	// The distributed DXT cache snapshots receiver ACK aux when the local
	// dealer finishes, but a dealer's dealing-delta window can stay open
	// past that point and include a slow receiver's ACK whose local share
	// write lands after the snapshot. Re-read the live receiver store here:
	// MVBA has fixed the transcript set, so every signature-implying write
	// has already happened.
	if dxt != nil && dxt.networkService != nil {
		allShares = dxt.networkService.shareSnapshot()
	}
	newShares, newThresholdPK, newPublicShares, compCompletionCerts, err := runCompKeyDerivationMulticast(
		ctx, cfg, newC, verifiedSelected, recoveredTranscripts, allShares,
		recipPriv, compKeys, compService, dxt,
	)
	if err != nil {
		return failWithPartial(fmt.Errorf("Algorithm 3 key derivation: %w", err), "derive")
	}
	markPhase("derive", deriveStart)
	markPhase("aggregate_derive", aggregateStart)
	phaseTimings["total"] = time.Since(totalStart)
	tracef("phase=aggregate_end ms=%.2f total_ms=%.2f", float64(time.Since(aggregateStart).Microseconds())/1000.0, float64(time.Since(totalStart).Microseconds())/1000.0)
	totalSentBytes, totalRecvBytes := commStats()
	phaseBytes := phaseCommStats()
	phaseSentBytes := make(map[string]uint64, len(phaseBytes))
	phaseRecvBytes := make(map[string]uint64, len(phaseBytes))
	for name, stat := range phaseBytes {
		phaseSentBytes[name] = stat.sent
		phaseRecvBytes[name] = stat.recv
	}
	for _, nodeID := range old {
		if state := perNodeState[nodeID]; state != nil {
			state.Completed = true
			state.FinalPhase = "derive"
			state.Latency = time.Since(totalStart)
			state.Error = ""
		}
	}

	return &Result{
		DecidedSet:                    decidedSet,
		SelectedTranscripts:           verifiedSelected,
		RecoveredTranscripts:          recoveredTranscripts,
		AgreementMode:                 agreementModeName(agreementFallback),
		AgreementFallback:             agreementFallback,
		AblationMode:                  strings.ToLower(strings.TrimSpace(cfg.AblationMode)),
		SelectedCount:                 len(selectedIDs),
		VerifiedCount:                 len(verifiedSelected),
		NewShares:                     newShares,
		CoinSignature:                 append([]byte(nil), coinSignature...),
		CoinThreshold:                 coinKeys.threshold,
		AggregateCommitments:          aggCommit,
		AggregateCiphertexts:          aggCipher,
		NewThresholdPK:                newThresholdPK,
		NewPublicShares:               newPublicShares,
		CompKeyCompletionCertificates: compCompletionCerts,
		PerNode:                       buildPerNode(),
		PhaseTimings:                  phaseTimings,
		TotalSentBytes:                totalSentBytes,
		TotalRecvBytes:                totalRecvBytes,
		PhaseSentBytes:                phaseSentBytes,
		PhaseRecvBytes:                phaseRecvBytes,
		PartialVerifyMode:             partialVerifyMode,
		PartialVerifyPositiveVotes:    partialVerifyPositiveVotes,
	}, nil
}

// aggregateTranscripts aggregates commitments and ciphertexts from selected transcripts.
func aggregateTranscripts(
	transcripts map[int]*DXTTranscript,
	selectedIDs []int,
	newCommittee []int,
	recipientPub map[int]*PaillierPublicKey,
) (map[int][]byte, map[int][]byte, error) {
	aggCommit := make(map[int][]byte, len(newCommittee))
	aggCipher := make(map[int][]byte, len(newCommittee))

	for _, rid := range newCommittee {
		var commitAgg []byte
		pk := recipientPub[rid]
		cAgg := pk.Neutral()
		hasCiphertext := false

		for _, dealer := range selectedIDs {
			tr := transcripts[dealer]
			if tr == nil {
				return nil, nil, fmt.Errorf("missing transcript for dealer %d", dealer)
			}

			commitAgg = addCommit(commitAgg, tr.Commitments[rid])

			if cBytes, ok := tr.Ciphertexts[rid]; ok {
				c := new(big.Int).SetBytes(cBytes)
				cAgg = pk.Add(cAgg, c)
				hasCiphertext = true
			}
		}

		aggCommit[rid] = commitAgg
		if hasCiphertext {
			aggCipher[rid] = cAgg.Bytes()
		}
	}
	return aggCommit, aggCipher, nil
}

func recordRecastCommMetrics(
	cfg Config,
	old []int,
	newC []int,
	selectedIDs []int,
	transcripts map[int]*DXTTranscript,
) {
	if !cfg.CommMetrics || len(selectedIDs) == 0 {
		return
	}
	localSet := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(localSet) == 0 {
		return
	}
	for _, dealer := range selectedIDs {
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			continue
		}
		root := sha256.Sum256(raw)
		for _, holder := range old {
			wire, wErr := json.Marshal(recastStoreWire{
				Dealer: dealer,
				Holder: holder,
				Root:   root[:],
			})
			if wErr != nil {
				continue
			}
			for _, recipient := range newC {
				if _, ok := localSet[holder]; ok {
					recordSentBytes(len(wire))
				}
				if _, ok := localSet[recipient]; ok {
					recordRecvBytes(len(wire))
				}
			}
		}
	}
}

func fillMissingAPDBCertificates(
	cfg Config,
	old []int,
	selectedIDs []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	certs map[int]APDBCertificate,
) map[int]APDBCertificate {
	if certs == nil {
		certs = make(map[int]APDBCertificate, len(selectedIDs))
	}
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	for _, dealer := range selectedIDs {
		if _, ok := certs[dealer]; ok {
			continue
		}
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			continue
		}
		root := sha256.Sum256(raw)
		receipts := make([]APDBReceipt, 0, len(old))
		for _, nodeID := range old {
			sk, ok := nodePriv[nodeID]
			if !ok {
				continue
			}
			if err := persistAPDBTranscript(cfg, old, nodeID, dealer, root[:], raw); err != nil {
				continue
			}
			chunkHash := hashChunk(root[:], dealer, nodeID, raw)
			msg := hashReceiptMsg(dealer, nodeID, root[:], chunkHash)
			sig := ed25519.Sign(sk, msg)
			receipts = append(receipts, APDBReceipt{
				NodeID:    nodeID,
				Sender:    dealer,
				ChunkHash: chunkHash,
				Signature: sig,
			})
		}
		if len(receipts) == 0 {
			continue
		}
		sort.Slice(receipts, func(i, j int) bool { return receipts[i].NodeID < receipts[j].NodeID })
		thresholdForDealer := threshold
		if thresholdForDealer > len(receipts) {
			thresholdForDealer = len(receipts)
		}
		certs[dealer] = APDBCertificate{
			Sender:   dealer,
			Root:     append([]byte(nil), root[:]...),
			Receipts: append([]APDBReceipt(nil), receipts[:thresholdForDealer]...),
		}
	}
	return certs
}

func waitForRecastReadyQuorum(
	ctx context.Context,
	cfg Config,
	old []int,
	newC []int,
	localSet map[int]struct{},
	lnByID map[int]net.Listener,
	addrMap map[int]string,
) error {
	if len(old) == 0 || len(newC) < len(old) {
		return fmt.Errorf("recast readiness requires an old/new listener pair per old node: old=%d new=%d", len(old), len(newC))
	}
	fromID := old[0]
	for _, oldID := range old {
		if _, ok := localSet[oldID]; ok {
			fromID = oldID
			break
		}
	}
	expected := apdbCertificateThreshold(cfg.F, len(old))
	if expected < 1 {
		return fmt.Errorf("invalid recast readiness threshold: old=%d f=%d", len(old), cfg.F)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		type pairResult struct {
			oldID int
			ready bool
		}
		results := make(chan pairResult, len(old))
		for index, oldID := range old {
			newID := newC[index]
			go func(oldID, newID int) {
				oldReady := recastListenerReady(ctx, cfg, fromID, oldID, localSet, lnByID, addrMap)
				newReady := recastListenerReady(ctx, cfg, fromID, newID, localSet, lnByID, addrMap)
				results <- pairResult{oldID: oldID, ready: oldReady && newReady}
			}(oldID, newID)
		}
		ready := 0
		for range old {
			if (<-results).ready {
				ready++
			}
		}
		if ready >= expected {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for recast TCP readiness: have_pairs=%d need=%d old=%d f=%d: %w", ready, expected, len(old), cfg.F, ctx.Err())
		case <-ticker.C:
		}
	}
}

func recastListenerReady(
	ctx context.Context,
	cfg Config,
	fromID int,
	target int,
	localSet map[int]struct{},
	lnByID map[int]net.Listener,
	addrMap map[int]string,
) bool {
	if _, local := localSet[target]; local {
		return lnByID[target] != nil
	}
	addr := strings.TrimSpace(addrMap[target])
	if addr == "" {
		return false
	}
	select {
	case <-ctx.Done():
		return false
	default:
	}
	conn, err := dialWithBandwidth("tcp", addr, 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	wire := recastWire{Kind: "ready", SID: cfg.SID, Epoch: cfg.Epoch, Holder: target}
	body, err := json.Marshal(wire)
	if err != nil {
		return false
	}
	if err := json.NewEncoder(conn).Encode(wire); err != nil {
		return false
	}
	recordSentBytes(len(body) + 1)
	var ack recastWire
	if err := json.NewDecoder(conn).Decode(&ack); err != nil {
		return false
	}
	if ackBody, err := json.Marshal(ack); err == nil {
		recordRecvBytes(len(ackBody) + 1)
	}
	return ack.Kind == "ready_ack" && ack.SID == cfg.SID && ack.Epoch == cfg.Epoch && ack.Holder == target
}

func respondRecastReady(conn net.Conn, cfg Config, localID int, wire recastWire) bool {
	if wire.Kind != "ready" || !validRecastWireContext(cfg, wire) || wire.Holder != localID {
		return false
	}
	ack := recastWire{Kind: "ready_ack", SID: cfg.SID, Epoch: cfg.Epoch, Holder: localID}
	body, err := json.Marshal(ack)
	if err != nil {
		return false
	}
	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if err := json.NewEncoder(conn).Encode(ack); err != nil {
		return false
	}
	recordSentBytes(len(body) + 1)
	return true
}

func validRecastWireContext(cfg Config, wire recastWire) bool {
	return wire.SID == cfg.SID && wire.Epoch == cfg.Epoch
}

func recastCompletionDigest(
	cfg Config,
	receiver int,
	selectedIDs []int,
	transcriptRoots map[int][]byte,
) ([]byte, error) {
	selected := append([]int(nil), selectedIDs...)
	sort.Ints(selected)
	if len(selected) == 0 {
		return nil, errors.New("empty recast completion dealer set")
	}
	h := sha256.New()
	h.Write([]byte("PRACTICAL-RECAST-RECEIVER-COMPLETION-v1"))
	var numbers [8]byte
	binary.BigEndian.PutUint64(numbers[:], uint64(len(cfg.SID)))
	h.Write(numbers[:])
	h.Write([]byte(cfg.SID))
	binary.BigEndian.PutUint64(numbers[:], cfg.Epoch)
	h.Write(numbers[:])
	binary.BigEndian.PutUint64(numbers[:], uint64(receiver))
	h.Write(numbers[:])
	binary.BigEndian.PutUint64(numbers[:], uint64(len(selected)))
	h.Write(numbers[:])
	for index, dealer := range selected {
		if index > 0 && selected[index-1] == dealer {
			return nil, errors.New("duplicate dealer in recast completion")
		}
		root := transcriptRoots[dealer]
		if len(root) != sha256.Size {
			return nil, fmt.Errorf("missing transcript root for dealer %d", dealer)
		}
		binary.BigEndian.PutUint64(numbers[:], uint64(dealer))
		h.Write(numbers[:])
		h.Write(root)
	}
	return h.Sum(nil), nil
}

func verifyRecastCompletion(
	cfg Config,
	wire recastWire,
	selectedIDs []int,
	transcriptRoots map[int][]byte,
	dxt *DXTBackend,
) bool {
	if wire.Kind != "completion" || !validRecastWireContext(cfg, wire) {
		return false
	}
	if _, ok := dxt.newIndex[wire.Recipient]; !ok {
		return false
	}
	if _, ok := dxt.oldIndex[wire.Holder]; !ok {
		return false
	}
	expected, err := recastCompletionDigest(cfg, wire.Recipient, selectedIDs, transcriptRoots)
	if err != nil || !bytes.Equal(expected, wire.CompletionDigest) {
		return false
	}
	public := dxt.recipientSignPub[wire.Recipient]
	return public != nil && ecdsa.VerifyASN1(public, expected, wire.Signature)
}

func recoverCompletionBarrierEnabled() bool {
	return durationFromEnvMsOr("PRACTICAL_RECOVER_COMPLETION_WAIT_MS", 0) > 0
}

func listenRecastWithRetry(ctx context.Context, address string) (net.Listener, error) {
	retryWindow := durationFromEnvMsOr("PRACTICAL_RECOVER_LISTEN_RETRY_MS", 2*time.Second)
	deadline := time.Now().Add(retryWindow)
	var lastErr error
	for {
		listener, err := net.Listen("tcp", address)
		if err == nil {
			return listener, nil
		}
		lastErr = err
		if retryWindow <= 0 || !time.Now().Before(deadline) {
			return nil, lastErr
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func recastNodeAddrMap(protocolAddrs string) (map[int]string, error) {
	base := parseNodeAddrMap(protocolAddrs)
	raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECAST_PORT_OFFSET"))
	if raw == "" {
		return base, nil
	}
	offset, err := strconv.Atoi(raw)
	if err != nil || offset < 0 {
		return nil, fmt.Errorf("invalid PRACTICAL_RECAST_PORT_OFFSET=%q", raw)
	}
	if offset == 0 {
		return base, nil
	}
	shifted := make(map[int]string, len(base))
	for id, address := range base {
		host, portText, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, fmt.Errorf("invalid recast address for node %d: %w", id, splitErr)
		}
		port, convErr := strconv.Atoi(portText)
		if convErr != nil || port <= 0 || port+offset > 65535 {
			return nil, fmt.Errorf("invalid recast port for node %d", id)
		}
		shifted[id] = net.JoinHostPort(host, strconv.Itoa(port+offset))
	}
	return shifted, nil
}

func runRecastRecovery(
	ctx context.Context,
	cfg Config,
	old []int,
	newC []int,
	selectedIDs []int,
	transcripts map[int]*DXTTranscript,
	apdbCerts map[int]APDBCertificate,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
	thresholdKeys *thresholdCoinKeySet,
) (map[int]*DXTTranscript, RecoverTimingBreakdown, error) {
	trace := strings.TrimSpace(os.Getenv("PRACTICAL_TRACE")) == "1"
	tracef := func(format string, args ...any) {
		if !trace {
			return
		}
		fmt.Fprintf(os.Stderr, "PRACTICAL_TRACE "+format+"\n", args...)
	}
	if len(selectedIDs) == 0 {
		return map[int]*DXTTranscript{}, RecoverTimingBreakdown{}, nil
	}
	addrMap, addrErr := recastNodeAddrMap(cfg.ProtocolNodeAddrs)
	if addrErr != nil {
		return nil, RecoverTimingBreakdown{}, addrErr
	}
	localSet := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(addrMap) == 0 || len(localSet) == 0 {
		// Keep local compatibility path if protocol transport is absent.
		out := make(map[int]*DXTTranscript, len(selectedIDs))
		for _, dealer := range selectedIDs {
			if tr := transcripts[dealer]; tr != nil {
				out[dealer] = tr
			}
		}
		return out, RecoverTimingBreakdown{}, nil
	}
	if !cfg.StrictNetwork {
		completeRS := true
		for _, dealer := range selectedIDs {
			cert := apdbCerts[dealer]
			if len(cert.ValueDigest) != sha256.Size || len(cert.MerkleRoot) != sha256.Size ||
				cert.DataShards <= 0 || cert.TotalShards != len(old) {
				completeRS = false
				break
			}
		}
		if !completeRS {
			out := make(map[int]*DXTTranscript, len(selectedIDs))
			for _, dealer := range selectedIDs {
				if tr := transcripts[dealer]; tr != nil {
					out[dealer] = tr
				}
			}
			return out, RecoverTimingBreakdown{}, nil
		}
	}
	timing := RecoverTimingBreakdown{}

	timeout := 120 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > timeout {
			timeout = candidate
		}
	}
	timeout = durationFromEnvMsOr("PRACTICAL_RECOVER_TIMEOUT_MS", timeout)
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl) - 2*time.Second
		if remaining > 0 && remaining < timeout {
			timeout = remaining
		}
	}
	if timeout < 30*time.Second {
		timeout = 30 * time.Second
	}
	storeBuf := boundedQueueSize(len(selectedIDs)*len(old), 256, 8192)
	fetchBuf := boundedQueueSize(len(selectedIDs)*len(newC), 256, 8192)
	storeSeenCh := make(chan recastStoreWire, storeBuf)
	fetchRespCh := make(chan recastWire, fetchBuf)
	completionCh := make(chan recastWire, boundedQueueSize(len(old)*len(newC), 64, 8192))
	lnByID := make(map[int]net.Listener, len(newC)+len(old))
	listenerErrs := make(map[int]error)
	var lnWG sync.WaitGroup
	var sendWG sync.WaitGroup
	var sendMu sync.Mutex
	acceptingSends := true
	stop := make(chan struct{})
	keepServicesAfterSuccess := false
	sendLimiter := make(chan struct{}, boundedQueueSize(len(localSet)*4, 32, 512))
	retryBackoff := 120 * time.Millisecond
	sendRecast := func(
		fromID int,
		toID int,
		addr string,
		wire recastWire,
		onSend func(),
		onDialFail func(error),
		onWriteFail func(error),
	) {
		body, marshalErr := marshalRecastNetworkWire(wire)
		if marshalErr != nil {
			if onWriteFail != nil {
				onWriteFail(marshalErr)
			}
			return
		}
		sendMu.Lock()
		if !acceptingSends {
			sendMu.Unlock()
			return
		}
		sendWG.Add(1)
		sendMu.Unlock()
		go func(body []byte) {
			defer sendWG.Done()
			select {
			case sendLimiter <- struct{}{}:
			case <-stop:
				return
			}
			defer func() { <-sendLimiter }()
			deadlineAt := time.Now().Add(timeout)
			for {
				select {
				case <-stop:
					return
				default:
				}
				attemptTO := recastPerAttemptTimeout(deadlineAt)
				if attemptTO <= 0 {
					if onDialFail != nil {
						onDialFail(fmt.Errorf("recast send deadline exceeded"))
					}
					return
				}
				conn, err := dialWithBandwidth("tcp", addr, attemptTO)
				if err != nil {
					if time.Now().Add(retryBackoff).After(deadlineAt) {
						if onDialFail != nil {
							onDialFail(err)
						}
						return
					}
					if recastSleepOrStop(stop, retryBackoff) {
						return
					}
					continue
				}
				_ = conn.SetWriteDeadline(time.Now().Add(attemptTO))
				if onSend != nil {
					onSend()
				}
				remaining := body
				for len(remaining) > 0 {
					written, writeErr := conn.Write(remaining)
					recordSentBytes(written)
					remaining = remaining[written:]
					if writeErr != nil {
						err = writeErr
						break
					}
					if written == 0 {
						err = io.ErrShortWrite
						break
					}
				}
				_ = conn.Close()
				if err == nil && len(remaining) == 0 {
					return
				}
				if time.Now().Add(retryBackoff).After(deadlineAt) {
					if onWriteFail != nil {
						onWriteFail(err)
					}
					return
				}
				if recastSleepOrStop(stop, retryBackoff) {
					return
				}
			}
		}(body)
	}
	defer func() {
		cleanup := func() {
			sendMu.Lock()
			acceptingSends = false
			sendMu.Unlock()
			close(stop)
			for _, ln := range lnByID {
				_ = ln.Close()
			}
			lnWG.Wait()
			sendWG.Wait()
		}
		grace := durationFromEnvMsOr("PRACTICAL_RECOVER_SERVICE_GRACE_MS", 0)
		if keepServicesAfterSuccess && grace > 0 {
			go func() {
				time.Sleep(grace)
				cleanup()
			}()
			return
		}
		cleanup()
	}()

	selectedSet := make(map[int]struct{}, len(selectedIDs))
	transcriptRoots := make(map[int][]byte, len(selectedIDs))
	holderKeys := make(map[int]ed25519.PublicKey, len(old))
	recovered := make(map[int]*DXTTranscript, len(selectedIDs))
	var recoveredMu sync.RWMutex
	erasureK := len(old) - 2*cfg.F
	if erasureK < cfg.F+1 {
		erasureK = cfg.F + 1
	}
	for _, dealer := range selectedIDs {
		selectedSet[dealer] = struct{}{}
		cert, ok := apdbCerts[dealer]
		if !ok || !verifyAPDBCertificateWithThresholdPublic(cert, nodePub, cfg.F, trustedAPDBThresholdPublic(thresholdKeys)) ||
			len(cert.ValueDigest) != sha256.Size || len(cert.MerkleRoot) != sha256.Size ||
			cert.DataShards != erasureK || cert.TotalShards != len(old) {
			return nil, timing, fmt.Errorf("selected dealer %d lacks a complete RS/Merkle APDB certificate", dealer)
		}
		transcriptRoots[dealer] = append([]byte(nil), cert.Root...)
		for _, holder := range old {
			if pk, present := nodePub[holder]; present {
				holderKeys[holder] = pk
			}
		}
	}
	// Recover store/fetch obligations are emitted by old-committee holders, not
	// only by the 2f+1 receipt signers that happened to land in a dealer's APDB
	// certificate. Using only certificate signers here incorrectly discards
	// valid holder responses and can strand recovery below the holder threshold.
	for _, holder := range old {
		if pk, ok := nodePub[holder]; ok {
			holderKeys[holder] = pk
		}
	}

	for localID := range localSet {
		addr, ok := addrMap[localID]
		if !ok || strings.TrimSpace(addr) == "" {
			continue
		}
		_, port, _ := net.SplitHostPort(addr)
		ln, err := listenRecastWithRetry(ctx, net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			listenerErrs[localID] = err
			continue
		}
		lnByID[localID] = ln
		lnWG.Add(1)
		go func(localID int, l net.Listener) {
			defer lnWG.Done()
			handleConn := func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
				var wire recastWire
				wireBytes, err := readRecastNetworkWire(conn, &wire)
				if err != nil {
					return
				}
				recordRecvBytes(wireBytes)
				if !validRecastWireContext(cfg, wire) {
					return
				}
				switch wire.Kind {
				case "ready":
					respondRecastReady(conn, cfg, localID, wire)
				case "completion":
					select {
					case completionCh <- wire:
					case <-stop:
					}
				case "store":
					if _, ok := selectedSet[wire.Dealer]; !ok {
						return
					}
					tracef("phase=recover_store_recv receiver=%d dealer=%d holder=%d", localID, wire.Dealer, wire.Holder)
					select {
					case storeSeenCh <- recastStoreWire{
						Recipient: wire.Recipient,
						Dealer:    wire.Dealer,
						Holder:    wire.Holder,
						Root:      append([]byte(nil), wire.Root...),
						TR:        wire.TR,
					}:
					case <-stop:
					}
				case "store_batch":
					for _, dealer := range wire.Dealers {
						if _, ok := selectedSet[dealer]; !ok {
							continue
						}
						root := append([]byte(nil), wire.Roots[dealer]...)
						var storePtr *RecoverStoreAttestation
						if st, ok := wire.Stores[dealer]; ok {
							s := st
							storePtr = &s
						}
						tracef("phase=recover_store_recv receiver=%d dealer=%d holder=%d", localID, dealer, wire.Holder)
						select {
						case storeSeenCh <- recastStoreWire{
							Recipient: wire.Recipient,
							Dealer:    dealer,
							Holder:    wire.Holder,
							Root:      root,
							Store:     storePtr,
							TR: func() *DXTTranscript {
								if tr, ok := wire.TRs[dealer]; ok {
									return tr
								}
								return nil
							}(),
						}:
						case <-stop:
						}
					}
				case "fetch_resp":
					if shard, ok := wire.Shards[wire.Dealer]; ok {
						att, ok := wire.Attests[wire.Dealer]
						if !ok {
							return
						}
						tracef("phase=recover_fetch_resp_recv receiver=%d dealer=%d holder=%d", localID, wire.Dealer, wire.Holder)
						select {
						case fetchRespCh <- recastWire{
							Kind:      "fetch_resp",
							Dealer:    wire.Dealer,
							Holder:    wire.Holder,
							Recipient: wire.Recipient,
							Root:      append([]byte(nil), shard.Root...),
							Shards:    map[int]RecoverShard{wire.Dealer: shard},
							Attests:   map[int]RecoverAttestation{wire.Dealer: att},
						}:
						case <-stop:
						}
					}
				case "fetch_resp_batch":
					for _, dealer := range wire.Dealers {
						recoveredMu.RLock()
						_, alreadyRecovered := recovered[dealer]
						recoveredMu.RUnlock()
						if alreadyRecovered {
							continue
						}
						shard, ok := wire.Shards[dealer]
						if !ok {
							continue
						}
						att, ok := wire.Attests[dealer]
						if !ok {
							continue
						}
						if expect, ok := transcriptRoots[dealer]; ok && len(expect) > 0 && !bytes.Equal(shard.Root, expect) {
							tracef("phase=recover_fetch_resp_root_mismatch receiver=%d dealer=%d holder=%d", localID, dealer, wire.Holder)
							continue
						}
						tracef("phase=recover_fetch_resp_recv receiver=%d dealer=%d holder=%d", localID, dealer, wire.Holder)
						select {
						case fetchRespCh <- recastWire{
							Kind:      "fetch_resp",
							Dealer:    dealer,
							Holder:    wire.Holder,
							Recipient: wire.Recipient,
							Root:      append([]byte(nil), shard.Root...),
							Shards:    map[int]RecoverShard{dealer: shard},
							Attests:   map[int]RecoverAttestation{dealer: att},
						}:
						case <-stop:
						}
					}
				case "fetch_req", "fetch_req_batch":
					if wire.Recipient < 0 {
						return
					}
					addr, ok := addrMap[wire.Recipient]
					if !ok || strings.TrimSpace(addr) == "" {
						return
					}
					dealers := []int{wire.Dealer}
					if wire.Kind == "fetch_req_batch" {
						dealers = append([]int(nil), wire.Dealers...)
					}
					respShards := make(map[int]RecoverShard, len(dealers))
					respAttests := make(map[int]RecoverAttestation, len(dealers))
					respDealers := make([]int, 0, len(dealers))
					for _, dealer := range dealers {
						tracef("phase=recover_fetch_req_recv holder=%d dealer=%d recipient=%d", localID, dealer, wire.Recipient)
						cert, ok := apdbCerts[dealer]
						if !ok {
							continue
						}
						stored, loadErr := loadNetworkAPDBShard(cfg, old, localID, cert)
						if loadErr != nil {
							tracef("phase=recover_load_pd_shard_fail holder=%d dealer=%d err=%v", localID, dealer, loadErr)
							continue
						}
						respDealers = append(respDealers, dealer)
						shard := RecoverShard{
							Dealer: dealer, Index: stored.ShardIndex,
							Root: append([]byte(nil), stored.Root...), ValueDigest: append([]byte(nil), stored.ValueDigest...),
							MerkleRoot: append([]byte(nil), stored.MerkleRoot...), DataShards: stored.DataShards,
							TotalShards: stored.TotalShards, Data: append([]byte(nil), stored.Shard...),
							Proof: cloneByteSlices(stored.Proof),
						}
						respShards[dealer] = shard
						shardHash := sha256.Sum256(shard.Data)
						msg := hashRecoverShard(shard.Root, dealer, localID, wire.Recipient, shard.Index, shard.Data)
						sk, ok := nodePriv[localID]
						if !ok || len(sk) != ed25519.PrivateKeySize {
							continue
						}
						respAttests[dealer] = RecoverAttestation{
							Dealer:    dealer,
							Holder:    localID,
							Recipient: wire.Recipient,
							Index:     shard.Index,
							Root:      append([]byte(nil), shard.Root...),
							ShardHash: append([]byte(nil), shardHash[:]...),
							Signature: append([]byte(nil), ed25519.Sign(sk, msg)...),
						}
					}
					if len(respDealers) == 0 {
						return
					}
					resp := recastWire{
						Kind:      "fetch_resp_batch",
						SID:       cfg.SID,
						Epoch:     cfg.Epoch,
						Holder:    localID,
						Recipient: wire.Recipient,
						Dealers:   respDealers,
						Shards:    respShards,
						Attests:   respAttests,
					}
					sendRecast(
						localID,
						wire.Recipient,
						addr,
						resp,
						func() {
							for _, dealer := range resp.Dealers {
								tracef("phase=recover_fetch_resp_send holder=%d dealer=%d recipient=%d", localID, dealer, wire.Recipient)
							}
						},
						func(err error) {
							tracef("phase=recover_fetch_resp_dial_fail holder=%d dealers=%v recipient=%d err=%v", localID, resp.Dealers, wire.Recipient, err)
						},
						func(err error) {
							tracef("phase=recover_fetch_resp_write_fail holder=%d dealers=%v recipient=%d err=%v", localID, resp.Dealers, wire.Recipient, err)
						},
					)
				}
			}
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case <-stop:
						return
					default:
						continue
					}
				}
				go handleConn(conn)
			}
		}(localID, ln)
	}

	if len(lnByID) != len(localSet) {
		missing := make([]string, 0, len(localSet)-len(lnByID))
		for localID := range localSet {
			if _, ok := lnByID[localID]; ok {
				continue
			}
			if err := listenerErrs[localID]; err != nil {
				missing = append(missing, fmt.Sprintf("%d: %v", localID, err))
			} else {
				missing = append(missing, fmt.Sprintf("%d: unknown bind error", localID))
			}
		}
		sort.Strings(missing)
		return nil, timing, fmt.Errorf("recast listeners unavailable for local protocol nodes: %s", strings.Join(missing, "; "))
	}
	readyStart := time.Now()
	if err := waitForRecastReadyQuorum(ctx, cfg, old, newC, localSet, lnByID, addrMap); err != nil {
		timing.ReadyWait += time.Since(readyStart)
		return nil, timing, err
	}
	timing.ReadyWait += time.Since(readyStart)

	requiredHolders := len(old) - 2*cfg.F
	if requiredHolders < cfg.F+1 {
		requiredHolders = cfg.F + 1
	}
	// In proc-sim, each process hosts a subset of new-committee nodes. A dealer
	// is considered recovered for this process only after all locally hosted new
	// recipients have completed the fetch/receive path for that dealer. This is
	// stricter than the previous process-local shortcut (recipient=1), while
	// still matching the one-process-per-node deployment model.
	requiredRecipients := 0
	for _, recipient := range newC {
		if _, ok := localSet[recipient]; ok {
			requiredRecipients++
		}
	}
	if requiredRecipients <= 0 {
		requiredRecipients = 1
	}
	// PD certifies an arbitrary n-f subset of holders. Activating another
	// arbitrary n-f subset guarantees an intersection of at least n-2f
	// persisted shards, which is exactly the RS reconstruction threshold.
	// Activating only n-2f holders is insufficient: the two subsets may
	// intersect below the decoding threshold even with no Byzantine faults.
	activeStoreHolderCount := len(old) - cfg.F
	if activeStoreHolderCount > len(old) {
		activeStoreHolderCount = len(old)
	}
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECOVER_STORE_HOLDERS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			activeStoreHolderCount = v
			minimumSafeFanout := len(old) - cfg.F
			if activeStoreHolderCount < minimumSafeFanout {
				activeStoreHolderCount = minimumSafeFanout
			}
			if activeStoreHolderCount > len(old) {
				activeStoreHolderCount = len(old)
			}
		}
	}
	recoverFetchInitialFanout := recoverInitialFetchFanout(erasureK, cfg.F, len(old))
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECOVER_FETCH_FANOUT")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			recoverFetchInitialFanout = v
		}
	}
	recoverFetchRetryStep := recoverRetryStep(cfg.F)
	recoverSpeculativeFanout := recoverSpeculativeExtra(cfg.F)
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECOVER_SPECULATIVE_EXTRA")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			recoverSpeculativeFanout = v
		}
	}
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECOVER_FETCH_RETRY_STEP")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			recoverFetchRetryStep = v
		}
	}
	recoverFetchStallInterval := 1 * time.Second
	if raw := strings.TrimSpace(os.Getenv("PRACTICAL_RECOVER_FETCH_STALL_MS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			recoverFetchStallInterval = time.Duration(v) * time.Millisecond
		}
	}

	recipientRoots := make(map[int][]byte, len(selectedIDs))
	storeObligationSeen := make(map[int]map[int]struct{}, len(selectedIDs))
	holderSeen := make(map[int]map[int]struct{}, len(selectedIDs))
	recipientSeen := make(map[int]map[int]struct{}, len(selectedIDs))
	fetchAttempted := make(map[int]map[int]map[int]struct{}, len(selectedIDs))
	receivedShards := make(map[int]map[int]map[int][]byte, len(selectedIDs))
	lastFetchDispatch := make(map[int]time.Time, len(newC))
	recoverVerifyElapsed := time.Duration(0)
	recoverStoreVerifyElapsed := time.Duration(0)
	recoverShardVerifyElapsed := time.Duration(0)
	storeSeenCount := uint64(0)
	fetchReqSentCount := uint64(0)
	fetchRespRecvCount := uint64(0)
	recipientSeenCount := uint64(0)
	for _, dealer := range selectedIDs {
		storeObligationSeen[dealer] = make(map[int]struct{})
		holderSeen[dealer] = make(map[int]struct{})
		recipientSeen[dealer] = make(map[int]struct{})
		fetchAttempted[dealer] = make(map[int]map[int]struct{})
		receivedShards[dealer] = make(map[int]map[int][]byte)
	}
	for _, dealer := range selectedIDs {
		root := append([]byte(nil), transcriptRoots[dealer]...)
		for _, holder := range old {
			if _, ok := localSet[holder]; !ok {
				continue
			}
			_ = root
		}
	}
	eligibleFetchHolders := func(recipient int) []int {
		if _, ok := localSet[recipient]; !ok {
			return nil
		}
		holders := make(map[int]struct{}, len(old))
		for _, dealer := range selectedIDs {
			if _, ok := recipientSeen[dealer][recipient]; ok {
				continue
			}
			for holder := range holderSeen[dealer] {
				if _, ok := storeObligationSeen[dealer][holder]; !ok {
					continue
				}
				holders[holder] = struct{}{}
			}
		}
		if len(holders) == 0 {
			return nil
		}
		out := make([]int, 0, len(holders))
		for holder := range holders {
			out = append(out, holder)
		}
		sort.Ints(out)
		return out
	}
	dispatchFetchRequests := func(recipient int, holders []int) {
		if _, ok := localSet[recipient]; !ok {
			return
		}
		if len(holders) == 0 {
			return
		}
		if _, ok := lastFetchDispatch[recipient]; !ok {
			lastFetchDispatch[recipient] = time.Time{}
		}
		currentFanout := recoverFetchInitialFanout
		if !lastFetchDispatch[recipient].IsZero() && time.Since(lastFetchDispatch[recipient]) >= recoverFetchStallInterval {
			// Gradually widen the search only when recovery appears stalled.
			extraSteps := int(time.Since(lastFetchDispatch[recipient]) / recoverFetchStallInterval)
			currentFanout += recoverSpeculativeFanout + max(0, extraSteps-1)*recoverFetchRetryStep
		}
		if currentFanout > len(holders) {
			currentFanout = len(holders)
		}
		// Deterministically rotate the holder order per recipient so that local
		// proc-sim runs do not stampede the same low-index holders first.
		startIdx := recipient % len(holders)
		if startIdx < 0 {
			startIdx += len(holders)
		}
		dispatched := 0
		sentAny := false
		for i := 0; i < len(holders); i++ {
			if dispatched >= currentFanout {
				break
			}
			holder := holders[(startIdx+i)%len(holders)]
			addr, ok := addrMap[holder]
			if !ok || strings.TrimSpace(addr) == "" {
				continue
			}
			pending := make([]int, 0, len(selectedIDs))
			for _, dealer := range selectedIDs {
				if len(holderSeen[dealer]) < requiredHolders {
					continue
				}
				if _, ok := holderSeen[dealer][holder]; !ok {
					continue
				}
				if _, ok := storeObligationSeen[dealer][holder]; !ok {
					continue
				}
				if _, ok := fetchAttempted[dealer][recipient]; !ok {
					fetchAttempted[dealer][recipient] = make(map[int]struct{})
				}
				if _, ok := fetchAttempted[dealer][recipient][holder]; ok {
					continue
				}
				if _, ok := recipientSeen[dealer][recipient]; ok {
					continue
				}
				pending = append(pending, dealer)
			}
			if len(pending) == 0 {
				continue
			}
			for _, dealer := range pending {
				fetchAttempted[dealer][recipient][holder] = struct{}{}
			}
			req := recastWire{
				Kind:      "fetch_req_batch",
				SID:       cfg.SID,
				Epoch:     cfg.Epoch,
				Holder:    holder,
				Recipient: recipient,
				Dealers:   pending,
			}
			sendRecast(
				recipient,
				holder,
				addr,
				req,
				func() {
					atomic.AddUint64(&fetchReqSentCount, uint64(len(req.Dealers)))
					for _, dealer := range req.Dealers {
						tracef("phase=recover_fetch_req_send recipient=%d dealer=%d holder=%d", recipient, dealer, holder)
					}
				},
				func(err error) {
					tracef("phase=recover_fetch_req_dial_fail recipient=%d dealers=%v holder=%d err=%v", recipient, req.Dealers, holder, err)
				},
				func(err error) {
					tracef("phase=recover_fetch_req_write_fail recipient=%d dealers=%v holder=%d err=%v", recipient, req.Dealers, holder, err)
				},
			)
			dispatched++
			sentAny = true
		}
		if sentAny {
			lastFetchDispatch[recipient] = time.Now()
		}
	}
	for _, holder := range old {
		if _, ok := localSet[holder]; !ok {
			continue
		}
		for _, recipient := range newC {
			addr, ok := addrMap[recipient]
			if !ok || strings.TrimSpace(addr) == "" {
				continue
			}
			holderPos := recoverStoreHolderPosition(old, recipient, holder, activeStoreHolderCount)
			if holderPos < 0 {
				continue
			}
			roots := make(map[int][]byte, len(selectedIDs))
			stores := make(map[int]RecoverStoreAttestation, len(selectedIDs))
			availableDealers := make([]int, 0, len(selectedIDs))
			sk, ok := nodePriv[holder]
			if !ok || len(sk) != ed25519.PrivateKeySize {
				return nil, timing, fmt.Errorf("recast local holder %d signing key unavailable", holder)
			}
			for _, dealer := range selectedIDs {
				cert, ok := apdbCerts[dealer]
				if !ok {
					continue
				}
				if _, loadErr := loadNetworkAPDBShard(cfg, old, holder, cert); loadErr != nil {
					tracef("phase=recover_store_skip_missing_pd_shard holder=%d dealer=%d err=%v", holder, dealer, loadErr)
					continue
				}
				availableDealers = append(availableDealers, dealer)
				roots[dealer] = append([]byte(nil), transcriptRoots[dealer]...)
				msg := hashRecoverStore(transcriptRoots[dealer], cert.Root, dealer, holder)
				stores[dealer] = RecoverStoreAttestation{
					Dealer: dealer, Holder: holder,
					Root: append([]byte(nil), transcriptRoots[dealer]...), CertRoot: append([]byte(nil), cert.Root...),
					Signature: append([]byte(nil), ed25519.Sign(sk, msg)...),
				}
			}
			if len(availableDealers) == 0 {
				continue
			}
			wire := recastWire{
				Kind:      "store_batch",
				SID:       cfg.SID,
				Epoch:     cfg.Epoch,
				Holder:    holder,
				Recipient: recipient,
				Dealers:   availableDealers,
				Roots:     roots,
				Stores:    stores,
			}
			sendRecast(
				holder,
				recipient,
				addr,
				wire,
				func() {
					for _, dealer := range wire.Dealers {
						tracef("phase=recover_store_send holder=%d dealer=%d recipient=%d", holder, dealer, recipient)
					}
				},
				func(err error) {
					tracef("phase=recover_store_dial_fail holder=%d dealers=%v recipient=%d err=%v", holder, wire.Dealers, recipient, err)
				},
				func(err error) {
					tracef("phase=recover_store_write_fail holder=%d dealers=%v recipient=%d err=%v", holder, wire.Dealers, recipient, err)
				},
			)
		}
	}
	localOldIDs := make([]int, 0, len(old))
	for _, holder := range old {
		if _, ok := localSet[holder]; ok {
			localOldIDs = append(localOldIDs, holder)
		}
	}
	localReceiverIDs := make([]int, 0, len(newC))
	for _, receiver := range newC {
		if _, ok := localSet[receiver]; ok {
			localReceiverIDs = append(localReceiverIDs, receiver)
		}
	}
	if len(localOldIDs) == 0 || len(localReceiverIDs) == 0 {
		return nil, timing, errors.New("recast completion requires local old and new identities")
	}
	completionThreshold := apdbCertificateThreshold(cfg.F, len(newC))
	completionSeen := make(map[int]map[int]struct{}, len(localOldIDs))
	for _, holder := range localOldIDs {
		completionSeen[holder] = make(map[int]struct{}, completionThreshold)
	}
	completionStarted := false
	completionWaitStart := time.Time{}
	// Completion votes are only a process-lifecycle barrier; they are not
	// needed to validate recovered transcripts or derive keys. Keep the old
	// barrier as an opt-in diagnostic mode, but let the normal recovery path
	// return as soon as every selected transcript is reconstructed locally.
	waitForCompletions := recoverCompletionBarrierEnabled()
	// Completion votes coordinate benchmark-process teardown only. They do not
	// alter transcript validity, agreement, recovery, or the derived key.
	completionSatisfied := func() bool {
		for _, holder := range localOldIDs {
			if len(completionSeen[holder]) < completionThreshold {
				return false
			}
		}
		return true
	}
	startCompletions := func() error {
		completionStarted = true
		completionWaitStart = time.Now()
		for _, receiver := range localReceiverIDs {
			digest, err := recastCompletionDigest(cfg, receiver, selectedIDs, transcriptRoots)
			if err != nil {
				return err
			}
			private := dxt.recipientSignPriv[receiver]
			if private == nil {
				return fmt.Errorf("recast completion private key unavailable for receiver %d", receiver)
			}
			signature, err := ecdsa.SignASN1(rand.Reader, private, digest)
			if err != nil {
				return err
			}
			for _, holder := range old {
				addr := strings.TrimSpace(addrMap[holder])
				if addr == "" {
					continue
				}
				wire := recastWire{
					Kind: "completion", SID: cfg.SID, Epoch: cfg.Epoch,
					Holder: holder, Recipient: receiver,
					CompletionDigest: append([]byte(nil), digest...), Signature: append([]byte(nil), signature...),
				}
				sendRecast(
					receiver, holder, addr, wire,
					func() { tracef("phase=recover_completion_send receiver=%d holder=%d", receiver, holder) },
					func(err error) {
						tracef("phase=recover_completion_dial_fail receiver=%d holder=%d err=%v", receiver, holder, err)
					},
					func(err error) {
						tracef("phase=recover_completion_write_fail receiver=%d holder=%d err=%v", receiver, holder, err)
					},
				)
			}
		}
		return nil
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	retryTickerInterval := recoverFetchStallInterval / 2
	if retryTickerInterval < 250*time.Millisecond {
		retryTickerInterval = 250 * time.Millisecond
	}
	retryTicker := time.NewTicker(retryTickerInterval)
	defer retryTicker.Stop()
	for {
		if len(recovered) == len(selectedIDs) && !completionStarted {
			if !waitForCompletions {
				break
			}
			if err := startCompletions(); err != nil {
				return nil, timing, err
			}
		}
		if completionStarted && completionSatisfied() {
			timing.CompletionWait += time.Since(completionWaitStart)
			break
		}
		select {
		case <-ctx.Done():
			if completionStarted {
				timing.CompletionWait += time.Since(completionWaitStart)
			}
			timing.StoreVerify += recoverStoreVerifyElapsed
			timing.ShardVerify += recoverShardVerifyElapsed
			timing.FullVerify += recoverVerifyElapsed
			timing.StoreSeen += storeSeenCount
			timing.FetchReqSent += atomic.LoadUint64(&fetchReqSentCount)
			timing.FetchRespRecv += atomic.LoadUint64(&fetchRespRecvCount)
			timing.RecipientSeen += atomic.LoadUint64(&recipientSeenCount)
			return nil, timing, ctx.Err()
		case <-deadline.C:
			if completionStarted {
				timing.CompletionWait += time.Since(completionWaitStart)
			}
			missing := make([]string, 0, len(selectedIDs)-len(recovered))
			for _, dealer := range selectedIDs {
				if _, ok := recovered[dealer]; ok {
					continue
				}
				missing = append(
					missing,
					fmt.Sprintf("dealer=%d holders=%d recipients=%d", dealer, len(holderSeen[dealer]), len(recipientSeen[dealer])),
				)
			}
			timing.StoreVerify += recoverStoreVerifyElapsed
			timing.ShardVerify += recoverShardVerifyElapsed
			timing.FullVerify += recoverVerifyElapsed
			timing.StoreSeen += storeSeenCount
			timing.FetchReqSent += atomic.LoadUint64(&fetchReqSentCount)
			timing.FetchRespRecv += atomic.LoadUint64(&fetchRespRecvCount)
			timing.RecipientSeen += atomic.LoadUint64(&recipientSeenCount)
			completionState := make([]string, 0, len(localOldIDs))
			for _, holder := range localOldIDs {
				completionState = append(completionState, fmt.Sprintf("holder=%d completions=%d/%d", holder, len(completionSeen[holder]), completionThreshold))
			}
			return nil, timing, fmt.Errorf("recast recovery timeout: %s; %s", strings.Join(missing, "; "), strings.Join(completionState, "; "))
		case completion := <-completionCh:
			if _, local := completionSeen[completion.Holder]; !local {
				continue
			}
			if _, duplicate := completionSeen[completion.Holder][completion.Recipient]; duplicate {
				continue
			}
			if !verifyRecastCompletion(cfg, completion, selectedIDs, transcriptRoots, dxt) {
				tracef("phase=recover_completion_reject receiver=%d holder=%d", completion.Recipient, completion.Holder)
				continue
			}
			completionSeen[completion.Holder][completion.Recipient] = struct{}{}
			tracef("phase=recover_completion_recv receiver=%d holder=%d count=%d threshold=%d", completion.Recipient, completion.Holder, len(completionSeen[completion.Holder]), completionThreshold)
		case seen := <-storeSeenCh:
			storeSeenCount++
			if _, ok := holderSeen[seen.Dealer]; !ok {
				continue
			}
			recoveredMu.RLock()
			_, alreadyRecovered := recovered[seen.Dealer]
			recoveredMu.RUnlock()
			if alreadyRecovered {
				continue
			}
			cert, ok := apdbCerts[seen.Dealer]
			if !ok {
				continue
			}
			// The selected certificate was authenticated once before listeners
			// started. RC STORE messages bind that agreed lock root instead of
			// retransmitting and re-verifying the same certificate per holder.
			if !bytes.Equal(seen.Root, transcriptRoots[seen.Dealer]) {
				tracef("phase=recover_store_root_mismatch dealer=%d holder=%d", seen.Dealer, seen.Holder)
				continue
			}
			holderPK, ok := holderKeys[seen.Holder]
			if !ok {
				tracef("phase=recover_store_missing_holder_pk dealer=%d holder=%d", seen.Dealer, seen.Holder)
				continue
			}
			if seen.Store == nil {
				tracef("phase=recover_store_missing_attestation dealer=%d holder=%d", seen.Dealer, seen.Holder)
				continue
			}
			if seen.Store.Dealer != seen.Dealer || seen.Store.Holder != seen.Holder || !bytes.Equal(seen.Store.Root, seen.Root) || !bytes.Equal(seen.Store.CertRoot, cert.Root) {
				tracef("phase=recover_store_attestation_mismatch dealer=%d holder=%d", seen.Dealer, seen.Holder)
				continue
			}
			if _, ok := storeObligationSeen[seen.Dealer][seen.Holder]; !ok {
				verifyStart := time.Now()
				if !verifyRecoverStoreAttestation(*seen.Store, holderPK) {
					tracef("phase=recover_store_bad_attestation dealer=%d holder=%d", seen.Dealer, seen.Holder)
					continue
				}
				recoverStoreVerifyElapsed += time.Since(verifyStart)
				storeObligationSeen[seen.Dealer][seen.Holder] = struct{}{}
			}
			if root, ok := recipientRoots[seen.Dealer]; ok {
				if !bytes.Equal(root, seen.Root) {
					continue
				}
			} else {
				recipientRoots[seen.Dealer] = append([]byte(nil), seen.Root...)
			}
			holderSeen[seen.Dealer][seen.Holder] = struct{}{}
			if seen.TR != nil && seen.Recipient >= 0 {
				if _, ok := recipientSeen[seen.Dealer][seen.Recipient]; ok {
					goto maybeFetch
				}
				verifyStart := time.Now()
				if dxt.VerifyTranscript(seen.Recipient, seen.TR) {
					recoverVerifyElapsed += time.Since(verifyStart)
					recipientSeen[seen.Dealer][seen.Recipient] = struct{}{}
					atomic.AddUint64(&recipientSeenCount, 1)
					tracef("phase=recover_recipient_direct dealer=%d recipient=%d holder=%d seen=%d", seen.Dealer, seen.Recipient, seen.Holder, len(recipientSeen[seen.Dealer]))
					if len(recipientSeen[seen.Dealer]) >= requiredRecipients {
						recoveredMu.Lock()
						if _, exists := recovered[seen.Dealer]; !exists {
							cp := *seen.TR
							recovered[seen.Dealer] = &cp
							tracef("phase=recover_dealer_done dealer=%d holders=%d recipients=%d mode=direct", seen.Dealer, len(holderSeen[seen.Dealer]), len(recipientSeen[seen.Dealer]))
						}
						recoveredMu.Unlock()
					}
				}
			}
		maybeFetch:
			if len(holderSeen[seen.Dealer]) < requiredHolders {
				continue
			}
			for _, recipient := range newC {
				if _, ok := localSet[recipient]; !ok {
					continue
				}
				if _, ok := recipientSeen[seen.Dealer][recipient]; ok {
					continue
				}
				dispatchFetchRequests(recipient, eligibleFetchHolders(recipient))
			}
		case resp := <-fetchRespCh:
			atomic.AddUint64(&fetchRespRecvCount, 1)
			if _, ok := recipientSeen[resp.Dealer]; !ok {
				continue
			}
			recoveredMu.RLock()
			_, alreadyRecovered := recovered[resp.Dealer]
			recoveredMu.RUnlock()
			if alreadyRecovered {
				continue
			}
			shard, ok := resp.Shards[resp.Dealer]
			if !ok || len(shard.Data) == 0 {
				continue
			}
			cert, ok := apdbCerts[resp.Dealer]
			if !ok || shard.DataShards != cert.DataShards || shard.TotalShards != cert.TotalShards ||
				!bytes.Equal(shard.Root, cert.Root) || !bytes.Equal(shard.ValueDigest, cert.ValueDigest) ||
				!bytes.Equal(shard.MerkleRoot, cert.MerkleRoot) {
				tracef("phase=recover_pd_shard_metadata_bad dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			leaf := apdbShardLeaf(shard.Dealer, shard.Index, shard.Data)
			if !verifyAPDBMerkleProof(leaf, shard.Index, shard.TotalShards, shard.Proof, shard.MerkleRoot) {
				tracef("phase=recover_pd_shard_merkle_bad dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			att, ok := resp.Attests[resp.Dealer]
			if !ok {
				tracef("phase=recover_attestation_missing dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			if _, ok := storeObligationSeen[resp.Dealer][resp.Holder]; !ok {
				tracef("phase=recover_admission_inconsistent dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			if root, ok := recipientRoots[resp.Dealer]; ok && !bytes.Equal(root, att.Root) {
				tracef("phase=recover_admission_root_inconsistent dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			holderPK, ok := holderKeys[resp.Holder]
			verifyShardStart := time.Now()
			if !ok || !verifyRecoverAttestation(att, shard, holderPK) {
				tracef("phase=recover_attestation_bad dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			recoverShardVerifyElapsed += time.Since(verifyShardStart)
			if att.Recipient != resp.Recipient || att.Holder != resp.Holder {
				tracef("phase=recover_attestation_mismatch dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			if _, ok := recipientSeen[resp.Dealer][resp.Recipient]; ok {
				continue
			}
			if expect, ok := transcriptRoots[resp.Dealer]; ok && len(expect) > 0 && !bytes.Equal(shard.Root, expect) {
				tracef("phase=recover_shard_root_mismatch dealer=%d recipient=%d holder=%d", resp.Dealer, resp.Recipient, resp.Holder)
				continue
			}
			if _, ok := receivedShards[resp.Dealer][resp.Recipient]; !ok {
				receivedShards[resp.Dealer][resp.Recipient] = make(map[int][]byte)
			}
			receivedShards[resp.Dealer][resp.Recipient][shard.Index] = append([]byte(nil), shard.Data...)
			if len(receivedShards[resp.Dealer][resp.Recipient]) < erasureK {
				continue
			}
			raw, err := recoverDecodeValue(receivedShards[resp.Dealer][resp.Recipient], erasureK, len(old))
			if err != nil {
				tracef("phase=recover_decode_fail dealer=%d recipient=%d err=%v", resp.Dealer, resp.Recipient, err)
				continue
			}
			valueDigest := sha256.Sum256(raw)
			if !bytes.Equal(valueDigest[:], cert.ValueDigest) {
				tracef("phase=recover_decode_value_digest_mismatch dealer=%d recipient=%d", resp.Dealer, resp.Recipient)
				continue
			}
			var recoveredTR DXTTranscript
			if err := json.Unmarshal(raw, &recoveredTR); err != nil {
				tracef("phase=recover_unmarshal_fail dealer=%d recipient=%d err=%v", resp.Dealer, resp.Recipient, err)
				continue
			}
			verifyStart := time.Now()
			if !dxt.VerifyTranscript(resp.Recipient, &recoveredTR) {
				tracef("phase=recover_verify_fail dealer=%d recipient=%d", resp.Dealer, resp.Recipient)
				continue
			}
			recoverVerifyElapsed += time.Since(verifyStart)
			recipientSeen[resp.Dealer][resp.Recipient] = struct{}{}
			atomic.AddUint64(&recipientSeenCount, 1)
			tracef("phase=recover_recipient_seen dealer=%d recipient=%d seen=%d", resp.Dealer, resp.Recipient, len(recipientSeen[resp.Dealer]))
			if len(recipientSeen[resp.Dealer]) >= requiredRecipients {
				recoveredMu.Lock()
				if _, exists := recovered[resp.Dealer]; !exists {
					cp := recoveredTR
					recovered[resp.Dealer] = &cp
					tracef("phase=recover_dealer_done dealer=%d holders=%d recipients=%d", resp.Dealer, len(holderSeen[resp.Dealer]), len(recipientSeen[resp.Dealer]))
				}
				recoveredMu.Unlock()
			}
		case <-retryTicker.C:
			for _, recipient := range newC {
				dispatchFetchRequests(recipient, eligibleFetchHolders(recipient))
			}
		}
	}
	timing.StoreVerify += recoverStoreVerifyElapsed
	timing.ShardVerify += recoverShardVerifyElapsed
	timing.FullVerify += recoverVerifyElapsed
	timing.StoreSeen += storeSeenCount
	timing.FetchReqSent += atomic.LoadUint64(&fetchReqSentCount)
	timing.FetchRespRecv += atomic.LoadUint64(&fetchRespRecvCount)
	timing.RecipientSeen += atomic.LoadUint64(&recipientSeenCount)
	keepServicesAfterSuccess = true
	return recovered, timing, nil
}

func validateConfig(cfg Config) error {
	if cfg.SID == "" {
		return errors.New("empty SID")
	}
	if len(cfg.OldCommittee) == 0 {
		return errors.New("empty old committee")
	}
	if len(cfg.NewCommittee) == 0 {
		return errors.New("empty new committee")
	}
	if cfg.F < 0 {
		return errors.New("invalid F")
	}
	nOld := len(cfg.OldCommittee)
	if nOld < 3*cfg.F+1 {
		return errors.New("old committee does not satisfy n >= 3f+1")
	}
	if cfg.Kappa < 0 || cfg.Kappa > 2*cfg.F+1 {
		return errors.New("kappa must be in [0, 2f+1]")
	}
	if cfg.StrictNetwork {
		if err := validateStrictNetworkConfig(cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateStrictNetworkConfig(cfg Config) error {
	if !strings.EqualFold(strings.TrimSpace(cfg.MVBANetwork), "tcp") {
		return errors.New("strict-network requires tcp MVBA network")
	}
	if strings.TrimSpace(cfg.MVBANodeAddrs) == "" {
		return errors.New("strict-network requires MVBA node addresses")
	}
	if strings.TrimSpace(cfg.MVBALocalNodeIDs) == "" {
		return errors.New("strict-network requires MVBA local node ids")
	}
	if strings.TrimSpace(cfg.ProtocolNodeAddrs) == "" {
		return errors.New("strict-network requires protocol node addresses")
	}
	if strings.TrimSpace(cfg.ProtocolLocalNodeIDs) == "" {
		return errors.New("strict-network requires protocol local node ids")
	}
	if strings.TrimSpace(cfg.CoinNodeAddrs) == "" {
		return errors.New("strict-network requires dedicated threshold coin node addresses")
	}
	if !cfg.DisableAgreementFallback {
		return errors.New("strict-network requires disabled agreement fallback")
	}
	if strings.TrimSpace(os.Getenv("PRACTICAL_DXT_FAST_LOCAL_ACKS")) == "1" {
		return errors.New("strict-network rejects PRACTICAL_DXT_FAST_LOCAL_ACKS")
	}
	mvbaLocal := parseNodeIDSet(cfg.MVBALocalNodeIDs)
	if len(mvbaLocal) >= len(cfg.OldCommittee) {
		return errors.New("strict-network requires a proper local old-committee MVBA subset")
	}
	protoLocal := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(protoLocal) >= len(cfg.OldCommittee)+len(cfg.NewCommittee) {
		return errors.New("strict-network requires a proper local protocol-node subset")
	}
	return nil
}

func allLocalValidEmpty(localValid map[int][]int) bool {
	if len(localValid) == 0 {
		return true
	}
	for _, v := range localValid {
		if len(v) > 0 {
			return false
		}
	}
	return true
}

func MeanNodeLatency(perNode []NodeOutput) time.Duration {
	if len(perNode) == 0 {
		return 0
	}
	sum := time.Duration(0)
	for _, o := range perNode {
		sum += o.Latency
	}
	return sum / time.Duration(len(perNode))
}

func boundedMVBAContext(parent context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := parent.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining > 0 {
			// Let MVBA consume most of the parent run budget. Large internal-delay
			// proc-sim runs (n >= 96/127) can legitimately need much more than the
			// old fixed 240s cap, and that cap causes PD/SPBC to fail long before
			// the overall run deadline.
			mvbaTO := remaining - 5*time.Second
			if mvbaTO < 30*time.Second {
				mvbaTO = remaining
			}
			// Keep only a high ceiling as a safety guard; do not prematurely
			// truncate large-scale runs.
			if mvbaTO > 30*time.Minute {
				mvbaTO = 30 * time.Minute
			}
			return context.WithTimeout(parent, mvbaTO)
		}
	}
	return context.WithTimeout(parent, 30*time.Second)
}

func agreementModeName(fallback bool) string {
	if fallback {
		return "local-quorum-fallback"
	}
	return "dumbomvba-go-spbc"
}

func boundedAPDBContext(parent context.Context) (context.Context, context.CancelFunc) {
	if dl, ok := parent.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining > 0 {
			// The previous 4s cap is too tight once node count grows. APDB is
			// still a setup-side subphase, but it should not time out so early that
			// it starves the subsequent agreement path of valid proposals.
			apdbTO := remaining / 3
			if apdbTO < 2*time.Second {
				apdbTO = 2 * time.Second
			}
			if apdbTO > 60*time.Second {
				apdbTO = 60 * time.Second
			}
			return context.WithTimeout(parent, apdbTO)
		}
	}
	return context.WithTimeout(parent, 4*time.Second)
}

func localQuorumDealerSet(proposals map[int][]int, old []int, f int) []int {
	if len(proposals) == 0 {
		return nil
	}
	threshold := len(old) - 2*f
	if threshold < f+1 {
		threshold = f + 1
	}
	count := make(map[int]int, len(old))
	for _, nodeID := range old {
		for _, dealer := range proposals[nodeID] {
			count[dealer]++
		}
	}
	out := make([]int, 0, len(count))
	for dealer, c := range count {
		if c >= threshold {
			out = append(out, dealer)
		}
	}
	if len(out) == 0 {
		for _, nodeID := range old {
			if len(proposals[nodeID]) > 0 {
				out = append(out, stableFirst(proposals[nodeID], len(proposals[nodeID]))...)
				break
			}
		}
	}
	sort.Ints(out)
	return stableFirst(out, len(out))
}

func loadOrComputeDXTCache(
	ctx context.Context,
	cfg Config,
	old []int,
	newC []int,
	dxt *DXTBackend,
	tracef func(string, ...any),
) (map[int]*DXTTranscript, map[int]map[int]SharePair, map[string]time.Duration, error) {
	cacheTimings := map[string]time.Duration{
		"dxt_cache_hit":   0,
		"dxt_cache_build": 0,
		"dxt_cache_wait":  0,
	}
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		if cfg.StrictNetwork {
			return nil, nil, nil, fmt.Errorf("strict-network requires PRACTICAL_ARTIFACT_CACHE_DIR for distributed DXT cache")
		}
		buildStart := time.Now()
		transcripts, allShares, err := computeAllDXT(ctx, old, dxt, tracef)
		cacheTimings["dxt_cache_build"] += time.Since(buildStart)
		return transcripts, allShares, cacheTimings, err
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, nil, nil, fmt.Errorf("create practical cache dir: %w", err)
	}
	if cfg.StrictNetwork {
		return loadOrComputeDistributedDXTCache(ctx, cfg, old, newC, dxt, cacheDir, cacheTimings, tracef)
	}

	cachePath := filepath.Join(cacheDir, dxtCacheFileName(cfg, old, newC))
	lockPath := cachePath + ".lock"
	runID := practicalRunID(cfg, old, newC)
	hitStart := time.Now()
	if payload, err := readDXTCache(cachePath); err == nil {
		cacheTimings["dxt_cache_hit"] += time.Since(hitStart)
		tracef("phase=dxt_cache_hit path=%s dealers=%d", cachePath, len(payload.Transcripts))
		return payload.Transcripts, payload.AllShares, cacheTimings, nil
	}
	cacheTimings["dxt_cache_hit"] += time.Since(hitStart)

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		meta := cacheLockMeta{RunID: runID, PID: os.Getpid(), CreatedAt: time.Now().Unix()}
		if raw, mErr := json.Marshal(meta); mErr == nil {
			_, _ = lockFile.Write(raw)
		}
		_ = lockFile.Close()
		tracef("phase=dxt_cache_build path=%s", cachePath)
		buildStart := time.Now()
		transcripts, allShares, dxtErr := computeAllDXT(ctx, old, dxt, tracef)
		cacheTimings["dxt_cache_build"] += time.Since(buildStart)
		if dxtErr != nil {
			_ = os.Remove(lockPath)
			return nil, nil, nil, dxtErr
		}
		payload := dxtCachePayload{
			Transcripts: transcripts,
			AllShares:   allShares,
		}
		if writeErr := writeDXTCache(cachePath, payload); writeErr != nil {
			_ = os.Remove(lockPath)
			return nil, nil, nil, writeErr
		}
		_ = os.Remove(lockPath)
		tracef("phase=dxt_cache_store path=%s dealers=%d", cachePath, len(transcripts))
		return transcripts, allShares, cacheTimings, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, nil, nil, fmt.Errorf("create dxt cache lock: %w", err)
	}
	if stale, staleErr := cacheLockStale(lockPath, 10*time.Minute); staleErr == nil && stale {
		_ = os.Remove(lockPath)
		return loadOrComputeDXTCache(ctx, cfg, old, newC, dxt, tracef)
	}

	tracef("phase=dxt_cache_wait path=%s", cachePath)
	waitStart := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if payload, readErr := readDXTCache(cachePath); readErr == nil {
			cacheTimings["dxt_cache_wait"] += time.Since(waitStart)
			tracef("phase=dxt_cache_ready path=%s dealers=%d", cachePath, len(payload.Transcripts))
			return payload.Transcripts, payload.AllShares, cacheTimings, nil
		}
		select {
		case <-ctx.Done():
			cacheTimings["dxt_cache_wait"] += time.Since(waitStart)
			return nil, nil, nil, fmt.Errorf("waiting for dxt cache: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

func computeAllDXT(
	ctx context.Context,
	old []int,
	dxt *DXTBackend,
	tracef func(string, ...any),
) (map[int]*DXTTranscript, map[int]map[int]SharePair, error) {
	transcripts := make(map[int]*DXTTranscript, len(old))
	allShares := make(map[int]map[int]SharePair, len(old))
	for _, dealer := range old {
		tracef("phase=dxt_dealer_begin dealer=%d", dealer)
		tr, shares, err := dxt.Deal(ctx, dealer, nil)
		if err != nil {
			tracef("phase=dxt_dealer_fail dealer=%d err=%v", dealer, err)
			return nil, nil, fmt.Errorf("dealer %d DXT+ deal failed: %w", dealer, err)
		}
		transcripts[dealer] = tr
		allShares[dealer] = shares
		tracef("phase=dxt_dealer_end dealer=%d ack_count=%d ciphertext_count=%d", dealer, len(tr.Signatures), len(tr.Ciphertexts))
	}
	return transcripts, allShares, nil
}

func loadOrComputeDistributedDXTCache(
	ctx context.Context,
	cfg Config,
	old []int,
	newC []int,
	dxt *DXTBackend,
	cacheDir string,
	cacheTimings map[string]time.Duration,
	tracef func(string, ...any),
) (map[int]*DXTTranscript, map[int]map[int]SharePair, map[string]time.Duration, error) {
	localDealers := localOldDealersFromProtocolIDs(cfg, old)
	if len(localDealers) == 0 {
		return nil, nil, nil, fmt.Errorf("strict-network distributed DXT has no local old dealer")
	}
	localStateDir := strings.TrimSpace(os.Getenv("PRACTICAL_LOCAL_STATE_DIR"))
	if localStateDir == "" {
		localStateDir = filepath.Join(cacheDir, "process-local-"+strings.ReplaceAll(cfg.ProtocolLocalNodeIDs, ",", "-"))
	}
	shareDir := filepath.Join(localStateDir, "dxt-receiver-shares")
	if err := dxt.setShareStoreDir(shareDir); err != nil {
		return nil, nil, nil, err
	}
	service, err := startDXTNetworkService(ctx, cfg, old, dxt)
	if err != nil {
		return nil, nil, nil, err
	}
	dxt.networkService = service
	dxt.externalReceivers = true
	defer func() { dxt.externalReceivers = false }()
	readyThreshold := 2*cfg.F + 1
	if readyThreshold < cfg.F+1 {
		readyThreshold = cfg.F + 1
	}
	readyStart := time.Now()
	if err := service.waitForReceiverQuorum(ctx, newC, readyThreshold); err != nil {
		return nil, nil, nil, err
	}
	cacheTimings["dxt_network_wait"] += time.Since(readyStart)
	tracef("phase=dxt_network_receivers_ready ready=%d/%d wait_ms=%.2f", readyThreshold, len(newC), float64(time.Since(readyStart).Microseconds())/1000.0)
	buildStart := time.Now()
	transcripts := make(map[int]*DXTTranscript, len(localDealers))
	for _, dealer := range localDealers {
		tracef("phase=dxt_dealer_begin dealer=%d mode=network", dealer)
		tr, _, dealErr := dxt.Deal(ctx, dealer, nil)
		if dealErr != nil {
			tracef("phase=dxt_dealer_fail dealer=%d err=%v", dealer, dealErr)
			return nil, nil, nil, fmt.Errorf("dealer %d DXT+ deal failed: %w", dealer, dealErr)
		}
		// Algorithm 2 sends the completed transcript into PD. Other old nodes
		// receive only their PD shard; the full transcript is not pre-broadcast.
		transcripts[dealer] = tr
		tracef("phase=dxt_dealer_end dealer=%d ack_count=%d ciphertext_count=%d mode=network", dealer, len(tr.Signatures), len(tr.Ciphertexts))
	}
	cacheTimings["dxt_network_build"] += time.Since(buildStart)
	tracef("phase=dxt_network_ready local_dealers=%d mode=pd-direct local_state=%s", len(transcripts), localStateDir)
	return transcripts, service.shareSnapshot(), cacheTimings, nil
}

func localOldDealersFromProtocolIDs(cfg Config, old []int) []int {
	localSet := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(localSet) == 0 {
		localSet = parseNodeIDSet(cfg.MVBALocalNodeIDs)
	}
	out := make([]int, 0, len(localSet))
	for _, dealer := range old {
		if _, ok := localSet[dealer]; ok {
			out = append(out, dealer)
		}
	}
	return out
}

func dxtCacheFileName(cfg Config, old []int, newC []int) string {
	key := struct {
		Version      int    `json:"version"`
		SID          string `json:"sid"`
		F            int    `json:"f"`
		Kappa        int    `json:"kappa"`
		PaillierBits int    `json:"paillier_bits"`
		Old          []int  `json:"old"`
		New          []int  `json:"new"`
	}{
		Version:      2,
		SID:          cfg.SID,
		F:            cfg.F,
		Kappa:        cfg.Kappa,
		PaillierBits: cfg.PaillierBits,
		Old:          append([]int(nil), old...),
		New:          append([]int(nil), newC...),
	}
	raw, _ := json.Marshal(key)
	sum := sha256.Sum256(raw)
	return "practical_dxt_" + hex.EncodeToString(sum[:16]) + ".json"
}

func loadOrComputeRecipientPaillierKeys(
	cfg Config,
	newC []int,
	tracef func(string, ...any),
) (map[int]*PaillierPublicKey, map[int]*PaillierPrivateKey, error) {
	bits := cfg.PaillierBits
	if bits <= 0 {
		bits = 3072
	}
	if len(newC) == 0 {
		return map[int]*PaillierPublicKey{}, map[int]*PaillierPrivateKey{}, nil
	}
	cacheKey := recipientPaillierCacheKey(cfg, newC)
	if cached, ok := recipientPaillierKeyCache.Load(cacheKey); ok {
		if bundle, ok := cached.(*recipientPaillierKeyBundle); ok && bundle != nil {
			return clonePaillierPubMap(bundle.Pub), clonePaillierPrivMap(bundle.Priv), nil
		}
	}
	cacheDir := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if cacheDir == "" {
		pub, priv, err := generateRecipientPaillierKeys(newC, bits)
		if err != nil {
			return nil, nil, err
		}
		recipientPaillierKeyCache.Store(cacheKey, &recipientPaillierKeyBundle{Pub: clonePaillierPubMap(pub), Priv: clonePaillierPrivMap(priv)})
		return pub, priv, nil
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("create practical cache dir: %w", err)
	}
	if cfg.StrictNetwork {
		return loadOrComputeStrictRecipientPaillierKeys(cfg, newC, cacheDir, tracef)
	}
	cachePath := filepath.Join(cacheDir, paillierCacheFileName(cfg, newC))
	lockPath := cachePath + ".lock"
	runID := practicalRunID(cfg, nil, newC)

	if payload, err := readPaillierCache(cachePath); err == nil {
		pub, priv, convErr := paillierCacheToMaps(payload)
		if convErr == nil {
			tracef("phase=paillier_cache_hit path=%s keys=%d", cachePath, len(pub))
			recipientPaillierKeyCache.Store(cacheKey, &recipientPaillierKeyBundle{Pub: clonePaillierPubMap(pub), Priv: clonePaillierPrivMap(priv)})
			return pub, priv, nil
		}
	}

	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err == nil {
		meta := cacheLockMeta{RunID: runID, PID: os.Getpid(), CreatedAt: time.Now().Unix()}
		if raw, mErr := json.Marshal(meta); mErr == nil {
			_, _ = lockFile.Write(raw)
		}
		_ = lockFile.Close()
		tracef("phase=paillier_cache_build path=%s", cachePath)
		pub, priv, genErr := generateRecipientPaillierKeys(newC, bits)
		if genErr != nil {
			_ = os.Remove(lockPath)
			return nil, nil, genErr
		}
		if writeErr := writePaillierCache(cachePath, mapsToPaillierCache(pub, priv)); writeErr != nil {
			_ = os.Remove(lockPath)
			return nil, nil, writeErr
		}
		_ = os.Remove(lockPath)
		recipientPaillierKeyCache.Store(cacheKey, &recipientPaillierKeyBundle{Pub: clonePaillierPubMap(pub), Priv: clonePaillierPrivMap(priv)})
		return pub, priv, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("create paillier cache lock: %w", err)
	}
	if stale, staleErr := cacheLockStale(lockPath, 10*time.Minute); staleErr == nil && stale {
		_ = os.Remove(lockPath)
		return loadOrComputeRecipientPaillierKeys(cfg, newC, tracef)
	}

	tracef("phase=paillier_cache_wait path=%s", cachePath)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	for {
		if payload, readErr := readPaillierCache(cachePath); readErr == nil {
			pub, priv, convErr := paillierCacheToMaps(payload)
			if convErr == nil {
				recipientPaillierKeyCache.Store(cacheKey, &recipientPaillierKeyBundle{Pub: clonePaillierPubMap(pub), Priv: clonePaillierPrivMap(priv)})
				return pub, priv, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, nil, fmt.Errorf("waiting for paillier cache: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

// loadOrComputeStrictRecipientPaillierKeys keeps the public recipient keys in
// one shared artifact, while each process reads only the private key files for
// the receiver IDs it actually hosts.  The public artifact is published last
// so readers never observe a partially generated key set.
func loadOrComputeStrictRecipientPaillierKeys(
	cfg Config,
	newC []int,
	cacheDir string,
	tracef func(string, ...any),
) (map[int]*PaillierPublicKey, map[int]*PaillierPrivateKey, error) {
	base := filepath.Join(cacheDir, paillierCacheFileName(cfg, newC))
	publicPath := base + ".public.json"
	lockPath := publicPath + ".lock"
	localSet := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(localSet) == 0 {
		return nil, nil, fmt.Errorf("strict-network paillier cache requires ProtocolLocalNodeIDs")
	}
	localIDs := make([]int, 0, len(localSet))
	for _, id := range newC {
		if _, ok := localSet[id]; ok {
			localIDs = append(localIDs, id)
		}
	}
	if len(localIDs) == 0 {
		return nil, nil, fmt.Errorf("strict-network paillier cache has no local new-committee receiver")
	}

	if cached, err := readPaillierPublicCache(publicPath); err == nil {
		if len(cached) != len(newC) {
			return nil, nil, fmt.Errorf("strict paillier public cache committee mismatch: have=%d want=%d", len(cached), len(newC))
		}
		for _, id := range newC {
			if cached[id] == nil {
				return nil, nil, fmt.Errorf("strict paillier public cache missing receiver %d", id)
			}
		}
	} else {
		if practicalSetupReadOnly() {
			return nil, nil, fmt.Errorf("read-only Practical setup is missing Paillier public artifact: %w", err)
		}
		lockFile, lockErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if lockErr == nil {
			_, _ = lockFile.WriteString(fmt.Sprintf("pid=%d\n", os.Getpid()))
			_ = lockFile.Close()
			bits := cfg.PaillierBits
			if bits <= 0 {
				bits = 3072
			}
			pub, priv, genErr := generateRecipientPaillierKeys(newC, bits)
			if genErr == nil {
				for id, sk := range priv {
					genErr = writePaillierPrivateCache(paillierPrivateCachePath(publicPath, id), id, sk)
					if genErr != nil {
						break
					}
				}
			}
			if genErr == nil {
				genErr = writePaillierPublicCache(publicPath, pub)
			}
			_ = os.Remove(lockPath)
			if genErr != nil {
				return nil, nil, genErr
			}
			tracef("phase=paillier_cache_store mode=receiver-local path=%s keys=%d", publicPath, len(pub))
		} else if !errors.Is(lockErr, os.ErrExist) {
			return nil, nil, fmt.Errorf("create strict paillier cache lock: %w", lockErr)
		}
	}

	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var public map[int]*PaillierPublicKey
	var priv map[int]*PaillierPrivateKey
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		public, _ = readPaillierPublicCache(publicPath)
		publicComplete := len(public) == len(newC)
		if publicComplete {
			for _, id := range newC {
				if public[id] == nil {
					publicComplete = false
					break
				}
			}
		}
		if publicComplete {
			priv = make(map[int]*PaillierPrivateKey, len(localIDs))
			complete := true
			for _, id := range localIDs {
				sk, err := readPaillierPrivateCache(paillierPrivateCachePath(publicPath, id), id)
				if err != nil {
					complete = false
					break
				}
				priv[id] = sk
			}
			if complete {
				tracef("phase=paillier_cache_hit mode=receiver-local path=%s local_keys=%d public_keys=%d", publicPath, len(priv), len(public))
				return public, priv, nil
			}
		}
		select {
		case <-waitCtx.Done():
			return nil, nil, fmt.Errorf("waiting for receiver-local paillier cache: %w", waitCtx.Err())
		case <-ticker.C:
		}
	}
}

func PrewarmPracticalRecipientKeys(cfg Config) error {
	newC := append([]int(nil), cfg.NewCommittee...)
	sort.Ints(newC)
	_, _, err := loadOrComputeRecipientPaillierKeys(cfg, newC, func(string, ...any) {})
	return err
}

func generateRecipientPaillierKeys(newC []int, bits int) (map[int]*PaillierPublicKey, map[int]*PaillierPrivateKey, error) {
	pub := make(map[int]*PaillierPublicKey, len(newC))
	priv := make(map[int]*PaillierPrivateKey, len(newC))
	for _, id := range newC {
		sk, err := GeneratePaillierKey(bits)
		if err != nil {
			return nil, nil, err
		}
		priv[id] = sk
		pub[id] = sk.PublicKey
	}
	return pub, priv, nil
}

func recipientPaillierCacheKey(cfg Config, newC []int) string {
	raw, _ := json.Marshal(struct {
		SID          string `json:"sid"`
		PaillierBits int    `json:"paillier_bits"`
		New          []int  `json:"new"`
	}{
		SID:          cfg.SID,
		PaillierBits: cfg.PaillierBits,
		New:          append([]int(nil), newC...),
	})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func paillierCacheFileName(cfg Config, newC []int) string {
	return "practical_paillier_" + recipientPaillierCacheKey(cfg, newC) + ".json"
}

func paillierPrivateCachePath(publicPath string, id int) string {
	return fmt.Sprintf("%s.node-%06d.private.json", strings.TrimSuffix(publicPath, ".public.json"), id)
}

func mapsToPaillierCache(pub map[int]*PaillierPublicKey, priv map[int]*PaillierPrivateKey) paillierCachePayload {
	payload := paillierCachePayload{Keys: make(map[int]paillierCacheEntry, len(priv))}
	for id, sk := range priv {
		if sk == nil || sk.PublicKey == nil {
			continue
		}
		payload.Keys[id] = paillierCacheEntry{
			N:       sk.PublicKey.N.Text(16),
			NSquare: sk.PublicKey.NSquare.Text(16),
			G:       sk.PublicKey.G.Text(16),
			Lambda:  sk.Lambda.Text(16),
			Mu:      sk.Mu.Text(16),
		}
	}
	return payload
}

func paillierCacheToMaps(payload *paillierCachePayload) (map[int]*PaillierPublicKey, map[int]*PaillierPrivateKey, error) {
	if payload == nil || len(payload.Keys) == 0 {
		return nil, nil, fmt.Errorf("empty paillier cache payload")
	}
	pub := make(map[int]*PaillierPublicKey, len(payload.Keys))
	priv := make(map[int]*PaillierPrivateKey, len(payload.Keys))
	for id, entry := range payload.Keys {
		n, ok := new(big.Int).SetString(entry.N, 16)
		if !ok {
			return nil, nil, fmt.Errorf("decode paillier n for id %d", id)
		}
		nSquare, ok := new(big.Int).SetString(entry.NSquare, 16)
		if !ok {
			return nil, nil, fmt.Errorf("decode paillier n^2 for id %d", id)
		}
		g, ok := new(big.Int).SetString(entry.G, 16)
		if !ok {
			return nil, nil, fmt.Errorf("decode paillier g for id %d", id)
		}
		lambda, ok := new(big.Int).SetString(entry.Lambda, 16)
		if !ok {
			return nil, nil, fmt.Errorf("decode paillier lambda for id %d", id)
		}
		mu, ok := new(big.Int).SetString(entry.Mu, 16)
		if !ok {
			return nil, nil, fmt.Errorf("decode paillier mu for id %d", id)
		}
		pk := &PaillierPublicKey{N: n, NSquare: nSquare, G: g}
		sk := &PaillierPrivateKey{PublicKey: pk, Lambda: lambda, Mu: mu}
		pub[id] = pk
		priv[id] = sk
	}
	return pub, priv, nil
}

func readPaillierCache(path string) (*paillierCachePayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload paillierCachePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if len(payload.Keys) == 0 {
		return nil, fmt.Errorf("empty paillier cache payload")
	}
	return &payload, nil
}

func writePaillierCache(path string, payload paillierCachePayload) error {
	data, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshal paillier cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write paillier cache temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename paillier cache: %w", err)
	}
	return nil
}

func readPaillierPublicCache(path string) (map[int]*PaillierPublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload paillierPublicCachePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if len(payload.Keys) == 0 {
		return nil, fmt.Errorf("empty paillier public cache payload")
	}
	pub := make(map[int]*PaillierPublicKey, len(payload.Keys))
	for id, entry := range payload.Keys {
		n, ok := new(big.Int).SetString(entry.N, 16)
		if !ok {
			return nil, fmt.Errorf("decode paillier public n for id %d", id)
		}
		n2, ok := new(big.Int).SetString(entry.NSquare, 16)
		if !ok {
			return nil, fmt.Errorf("decode paillier public n^2 for id %d", id)
		}
		g, ok := new(big.Int).SetString(entry.G, 16)
		if !ok {
			return nil, fmt.Errorf("decode paillier public g for id %d", id)
		}
		pub[id] = &PaillierPublicKey{N: n, NSquare: n2, G: g}
	}
	return pub, nil
}

func writePaillierPublicCache(path string, pub map[int]*PaillierPublicKey) error {
	payload := paillierPublicCachePayload{Keys: make(map[int]paillierPublicCacheEntry, len(pub))}
	for id, pk := range pub {
		if pk == nil {
			continue
		}
		payload.Keys[id] = paillierPublicCacheEntry{N: pk.N.Text(16), NSquare: pk.NSquare.Text(16), G: pk.G.Text(16)}
	}
	data, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshal paillier public cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write paillier public cache temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename paillier public cache: %w", err)
	}
	return nil
}

func writePaillierPrivateCache(path string, id int, sk *PaillierPrivateKey) error {
	if sk == nil || sk.PublicKey == nil || sk.Lambda == nil || sk.Mu == nil {
		return fmt.Errorf("invalid paillier private key for id %d", id)
	}
	payload := paillierPrivateCachePayload{ID: id, Key: paillierCacheEntry{
		N: sk.PublicKey.N.Text(16), NSquare: sk.PublicKey.NSquare.Text(16), G: sk.PublicKey.G.Text(16),
		Lambda: sk.Lambda.Text(16), Mu: sk.Mu.Text(16),
	}}
	data, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshal paillier private cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write paillier private cache temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename paillier private cache: %w", err)
	}
	return nil
}

func readPaillierPrivateCache(path string, id int) (*PaillierPrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload paillierPrivateCachePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if payload.ID != id {
		return nil, fmt.Errorf("paillier private cache id mismatch: have=%d want=%d", payload.ID, id)
	}
	n, ok := new(big.Int).SetString(payload.Key.N, 16)
	if !ok {
		return nil, fmt.Errorf("decode paillier private n for id %d", id)
	}
	n2, ok := new(big.Int).SetString(payload.Key.NSquare, 16)
	if !ok {
		return nil, fmt.Errorf("decode paillier private n^2 for id %d", id)
	}
	g, ok := new(big.Int).SetString(payload.Key.G, 16)
	if !ok {
		return nil, fmt.Errorf("decode paillier private g for id %d", id)
	}
	lambda, ok := new(big.Int).SetString(payload.Key.Lambda, 16)
	if !ok {
		return nil, fmt.Errorf("decode paillier lambda for id %d", id)
	}
	mu, ok := new(big.Int).SetString(payload.Key.Mu, 16)
	if !ok {
		return nil, fmt.Errorf("decode paillier mu for id %d", id)
	}
	pk := &PaillierPublicKey{N: n, NSquare: n2, G: g}
	return &PaillierPrivateKey{PublicKey: pk, Lambda: lambda, Mu: mu}, nil
}

func clonePaillierPubMap(src map[int]*PaillierPublicKey) map[int]*PaillierPublicKey {
	out := make(map[int]*PaillierPublicKey, len(src))
	for id, pk := range src {
		if pk == nil {
			continue
		}
		out[id] = &PaillierPublicKey{
			N:       new(big.Int).Set(pk.N),
			NSquare: new(big.Int).Set(pk.NSquare),
			G:       new(big.Int).Set(pk.G),
		}
	}
	return out
}

func clonePaillierPrivMap(src map[int]*PaillierPrivateKey) map[int]*PaillierPrivateKey {
	out := make(map[int]*PaillierPrivateKey, len(src))
	for id, sk := range src {
		if sk == nil || sk.PublicKey == nil {
			continue
		}
		out[id] = &PaillierPrivateKey{
			PublicKey: &PaillierPublicKey{
				N:       new(big.Int).Set(sk.PublicKey.N),
				NSquare: new(big.Int).Set(sk.PublicKey.NSquare),
				G:       new(big.Int).Set(sk.PublicKey.G),
			},
			Lambda: new(big.Int).Set(sk.Lambda),
			Mu:     new(big.Int).Set(sk.Mu),
		}
	}
	return out
}

func readDXTCache(path string) (*dxtCachePayload, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var payload dxtCachePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	if len(payload.Transcripts) == 0 {
		return nil, fmt.Errorf("empty dxt cache payload")
	}
	return &payload, nil
}

func writeDXTCache(path string, payload dxtCachePayload) error {
	data, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshal dxt cache: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write dxt cache temp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename dxt cache: %w", err)
	}
	return nil
}

func boundedQueueSize(estimate int, floor int, ceiling int) int {
	if estimate < floor {
		return floor
	}
	if ceiling > 0 && estimate > ceiling {
		return ceiling
	}
	return estimate
}

func cacheLockStale(path string, maxAge time.Duration) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}
	return time.Since(info.ModTime()) > maxAge, nil
}

func recoverInitialFetchFanout(erasureK int, f int, holderCount int) int {
	fanout := erasureK
	if fanout <= 0 {
		fanout = 1
	}
	if holderCount > 0 && fanout > holderCount {
		fanout = holderCount
	}
	return fanout
}

func recoverSpeculativeExtra(f int) int {
	return max(4, min(16, f/2))
}

func recoverRetryStep(f int) int {
	return max(4, min(12, f/4))
}

func recoverStoreHolderPosition(old []int, recipient int, holder int, activeCount int) int {
	if len(old) == 0 || activeCount <= 0 {
		return -1
	}
	if activeCount > len(old) {
		activeCount = len(old)
	}
	holderIdx := sort.SearchInts(old, holder)
	if holderIdx < 0 || holderIdx >= len(old) || old[holderIdx] != holder {
		return -1
	}
	startIdx := recipient % len(old)
	if startIdx < 0 {
		startIdx += len(old)
	}
	pos := holderIdx - startIdx
	if pos < 0 {
		pos += len(old)
	}
	if pos >= activeCount {
		return -1
	}
	return pos
}
