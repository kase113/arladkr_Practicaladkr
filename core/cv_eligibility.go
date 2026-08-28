package core

import (
	"bytes"
	"context"
	"fmt"
	"math/big"
	"sort"
)

const cvEligibilityCoinDomain = "ARL-CV-sAPVSS/eligibility-coin/v1"

// cvEligibilitySampleSize returns the smallest proposer sample c whose
// hypergeometric probability of containing only faulty old members is at most
// the requested bound. The bound is represented as a rational p/q.
func cvEligibilitySampleSize(n, f int, maxNumerator, maxDenominator uint64) (int, error) {
	if n <= 0 || f < 0 || f >= n || maxNumerator == 0 || maxNumerator >= maxDenominator {
		return 0, fmt.Errorf("invalid eligibility parameters")
	}
	bound := new(big.Rat).SetFrac(new(big.Int).SetUint64(maxNumerator), new(big.Int).SetUint64(maxDenominator))
	for c := 1; c <= n; c++ {
		if c > f {
			return c, nil
		}
		bad := binomial(f, c)
		all := binomial(n, c)
		if new(big.Rat).SetFrac(bad, all).Cmp(bound) <= 0 {
			return c, nil
		}
	}
	return 0, fmt.Errorf("no eligibility sample size")
}

func binomial(n, k int) *big.Int {
	if k < 0 || k > n {
		return new(big.Int)
	}
	if k > n-k {
		k = n - k
	}
	r := big.NewInt(1)
	for i := 1; i <= k; i++ {
		r.Mul(r, big.NewInt(int64(n-k+i)))
		r.Div(r, big.NewInt(int64(i)))
	}
	return r
}

// cvEligibilityProposerSet deterministically samples c distinct roster
// members from a recovered coin output. The roster is sorted before hashing,
// so all nodes obtain the same set independent of input order.
func cvEligibilityProposerSet(roster []int, c, f int, coin []byte) ([]int, error) {
	if len(coin) == 0 || c <= 0 || c > len(roster) || f < 0 || f >= len(roster) {
		return nil, fmt.Errorf("invalid eligibility proposer set parameters")
	}
	ordered := sortedUnique(roster)
	if len(ordered) != len(roster) || c > len(ordered) {
		return nil, fmt.Errorf("invalid eligibility roster")
	}
	keys := make([]struct {
		id     int
		digest []byte
	}, len(ordered))
	for i, id := range ordered {
		keys[i] = struct {
			id     int
			digest []byte
		}{id: id, digest: hashBytes([]byte(cvEligibilityCoinDomain), coin, encodeInts([]int{id}))}
	}
	sort.Slice(keys, func(i, j int) bool { return string(keys[i].digest) < string(keys[j].digest) })
	out := make([]int, c)
	for i := range out {
		out[i] = keys[i].id
	}
	return out, nil
}

func cvEligibilityCoinInput(sid string, epoch int) []byte {
	return hashBytes([]byte(cvEligibilityCoinDomain), []byte(sid), encodeInts([]int{epoch}))
}

func cvEligibilityShareCanonicalBytes(digest, signature []byte) ([]byte, error) {
	if len(digest) != 32 || len(signature) == 0 || len(signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid eligibility coin share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvEligibilityCoinDomain))
	_ = cvWriteBytes(&wire, digest)
	_ = cvWriteBytes(&wire, signature)
	return wire.Bytes(), nil
}

func cvDecodeEligibilityShare(wire []byte) ([]byte, []byte, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvEligibilityCoinDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvEligibilityCoinDomain)) {
		return nil, nil, fmt.Errorf("invalid eligibility coin share domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, nil, fmt.Errorf("invalid eligibility coin share digest")
	}
	signature, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(signature) == 0 || r.reader.Len() != 0 {
		return nil, nil, fmt.Errorf("invalid eligibility coin share signature")
	}
	canonical, err := cvEligibilityShareCanonicalBytes(digest, signature)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, nil, fmt.Errorf("non-canonical eligibility coin share")
	}
	return digest, signature, nil
}

func (s *cvComponentService) CollectEligibilityCoin(ctx context.Context) ([]byte, error) {
	if ctx == nil || s == nil || s.cfg.runtime == nil || s.cfg.runtime.coinSigner == nil {
		return nil, fmt.Errorf("eligibility coin runtime is unavailable")
	}
	digest := cvEligibilityCoinInput(s.cfg.SID, s.cfg.Epoch)
	share, err := s.cfg.runtime.coinSigner.SignShare(s.localNode, cvEligibilityCoinDomain, digest)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%x", digest)
	s.mu.Lock()
	if s.eligibilityShares[key] == nil {
		s.eligibilityShares[key] = make(map[int][]byte)
	}
	s.eligibilityShares[key][s.localNode] = append([]byte(nil), share...)
	s.mu.Unlock()
	wire, err := cvEligibilityShareCanonicalBytes(digest, share)
	if err != nil {
		return nil, err
	}
	targets := s.oldCommitteeOrder()
	peers := make([]int, 0, len(targets)-1)
	for _, target := range targets {
		if target != s.localNode {
			peers = append(peers, target)
		}
	}
	if s.sendMany(peers, cvTagEligibilityShare, wire) < len(peers) {
		return nil, fmt.Errorf("eligibility coin share broadcast incomplete")
	}
	threshold := s.cfg.runtime.coinSigner.Threshold()
	for {
		s.mu.Lock()
		stored := s.eligibilityShares[key]
		shares := make(map[int][]byte, len(stored))
		for member, value := range stored {
			shares[member] = append([]byte(nil), value...)
		}
		s.mu.Unlock()
		if len(shares) >= threshold {
			coin, recoverErr := s.cfg.runtime.coinSigner.Recover(cvEligibilityCoinDomain, digest, shares)
			if recoverErr != nil {
				return nil, fmt.Errorf("recover eligibility coin: %w", recoverErr)
			}
			if !s.cfg.runtime.coinSigner.VerifyRecovered(cvEligibilityCoinDomain, digest, coin) {
				return nil, fmt.Errorf("recovered eligibility coin failed verification")
			}
			return coin, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.ctx.Done():
			return nil, s.ctx.Err()
		case <-s.eligibilityUpdates:
		}
	}
}

func (s *cvComponentService) handleEligibilityShare(msg Message) {
	digest, signature, err := cvDecodeEligibilityShare(msg.Body)
	if err != nil || !bytes.Equal(digest, cvEligibilityCoinInput(s.cfg.SID, s.cfg.Epoch)) {
		return
	}
	if _, ok := s.oldMembers[msg.From]; !ok {
		return
	}
	key := fmt.Sprintf("%x", digest)
	s.mu.Lock()
	if shares := s.eligibilityShares[key]; shares != nil {
		if _, duplicate := shares[msg.From]; duplicate {
			s.mu.Unlock()
			return
		}
	}
	s.mu.Unlock()
	if !s.cfg.runtime.coinSigner.VerifyShare(msg.From, cvEligibilityCoinDomain, digest, signature) {
		return
	}
	s.mu.Lock()
	if s.eligibilityShares[key] == nil {
		s.eligibilityShares[key] = make(map[int][]byte)
	}
	if _, exists := s.eligibilityShares[key][msg.From]; !exists {
		s.eligibilityShares[key][msg.From] = append([]byte(nil), signature...)
	}
	s.mu.Unlock()
	select {
	case s.eligibilityUpdates <- struct{}{}:
	default:
	}
}
