package core

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

type runtimeCrypto struct {
	oldOrder    []int
	oldIndex    map[int]int
	lockSigner  *tblsThresholdSigner
	coinSigner  *tblsThresholdSigner
	commMetrics bool

	commMu         sync.Mutex
	totalSentBytes uint64
	totalRecvBytes uint64
	commPhase      string
	phaseSentBytes map[string]uint64
	phaseRecvBytes map[string]uint64
}

func newRuntimeCommMetrics(enabled bool) *runtimeCrypto {
	return &runtimeCrypto{
		commMetrics: enabled, phaseSentBytes: make(map[string]uint64), phaseRecvBytes: make(map[string]uint64),
	}
}

func ensureRuntime(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("nil config")
	}
	*cfg = NormalizeConfig(*cfg)
	if cfg.runtime != nil {
		return nil
	}
	if len(cfg.OldCommittee) == 0 || len(cfg.NewCommittee) == 0 {
		return nil
	}
	oldOrder := sortedCopy(cfg.OldCommittee)
	oldIndex := make(map[int]int, len(oldOrder))
	for i, id := range oldOrder {
		oldIndex[id] = i
	}
	lockThreshold := len(oldOrder) - cfg.FOld
	if lockThreshold <= 0 {
		lockThreshold = 1
	}
	coinThreshold := cfg.FOld + 1
	var lockSigner, coinSigner *tblsThresholdSigner
	hasCVKeyDir := strings.TrimSpace(cfg.CVPublicKeyDir) != "" || strings.TrimSpace(cfg.CVLocalSecretDir) != ""
	if hasCVKeyDir {
		if strings.TrimSpace(cfg.CVPublicKeyDir) == "" || strings.TrimSpace(cfg.CVLocalSecretDir) == "" {
			return fmt.Errorf("CV runtime requires both public and local secret key directories")
		}
		material, err := cvLoadOldLockKeyMaterial(
			cfg.CVPublicKeyDir, cfg.CVLocalSecretDir, cfg.SID,
			oldOrder, lockThreshold, localOldNodes(*cfg),
		)
		if err != nil {
			return fmt.Errorf("load CV old-lock key material: %w", err)
		}
		lockSigner, err = newTBLSThresholdSignerFromMaterial(material)
		if err != nil {
			return err
		}
		coinMaterial, err := cvLoadMVBACoinKeyMaterial(
			cfg.CVPublicKeyDir, cfg.CVLocalSecretDir, cfg.SID,
			oldOrder, coinThreshold, localOldNodes(*cfg),
		)
		if err != nil {
			return fmt.Errorf("load CV MVBA coin key material: %w", err)
		}
		coinSigner, err = newTBLSThresholdSignerFromCoinMaterial(coinMaterial)
		if err != nil {
			return err
		}
	} else {
		if cfg.StrictNetwork {
			return fmt.Errorf("strict CV runtime requires materialized receiver, old-lock, and MVBA coin key directories")
		}
		var err error
		lockSigner, err = newTBLSThresholdSigner(
			oldOrder,
			lockThreshold,
			deterministicStream(
				"rladkr-lock-signer",
				[]byte(cfg.SID),
				[]byte(fmt.Sprintf("|epoch=%d", cfg.Epoch)),
				encodeInts(oldOrder),
			),
		)
		if err != nil {
			return err
		}
		coinSigner, err = newTBLSThresholdSigner(
			oldOrder,
			coinThreshold,
			deterministicStream(
				"rladkr-test-only-mvba-coin-signer",
				[]byte(cfg.SID),
				encodeInts(oldOrder),
			),
		)
		if err != nil {
			return err
		}
	}

	cfg.runtime = &runtimeCrypto{
		oldOrder: oldOrder, oldIndex: oldIndex, lockSigner: lockSigner, coinSigner: coinSigner,
		commMetrics:    cfg.CommMetrics,
		phaseSentBytes: make(map[string]uint64), phaseRecvBytes: make(map[string]uint64),
	}
	return nil
}

func deterministicStream(label string, parts ...[]byte) cipher.Stream {
	keySeedParts := make([][]byte, 0, len(parts)+1)
	keySeedParts = append(keySeedParts, []byte(label))
	keySeedParts = append(keySeedParts, parts...)
	keySeed := hashBytes(keySeedParts...)
	ivSeed := hashBytes(append(keySeedParts, []byte("|iv"))...)

	block, _ := aes.NewCipher(keySeed[:32])
	return cipher.NewCTR(block, ivSeed[:aes.BlockSize])
}

func (r *runtimeCrypto) recordSentBytes(n int) {
	if r == nil || !r.commMetrics || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.totalSentBytes += uint64(n)
	if r.commPhase != "" {
		r.phaseSentBytes[r.commPhase] += uint64(n)
	}
	r.commMu.Unlock()
}

func (r *runtimeCrypto) recordRecvBytes(n int) {
	if r == nil || !r.commMetrics || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.totalRecvBytes += uint64(n)
	if r.commPhase != "" {
		r.phaseRecvBytes[r.commPhase] += uint64(n)
	}
	r.commMu.Unlock()
}

func (r *runtimeCrypto) recordNamedSentBytes(name string, n int) {
	if r == nil || !r.commMetrics || name == "" || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.phaseSentBytes[name] += uint64(n)
	r.commMu.Unlock()
}

func (r *runtimeCrypto) recordNamedRecvBytes(name string, n int) {
	if r == nil || !r.commMetrics || name == "" || n <= 0 {
		return
	}
	r.commMu.Lock()
	r.phaseRecvBytes[name] += uint64(n)
	r.commMu.Unlock()
}

func (r *runtimeCrypto) commStats() (uint64, uint64) {
	if r == nil {
		return 0, 0
	}
	r.commMu.Lock()
	defer r.commMu.Unlock()
	return r.totalSentBytes, r.totalRecvBytes
}

func (r *runtimeCrypto) setCommPhase(name string) {
	if r == nil {
		return
	}
	r.commMu.Lock()
	r.commPhase = name
	r.commMu.Unlock()
}

func (r *runtimeCrypto) phaseCommStats() (map[string]uint64, map[string]uint64) {
	if r == nil {
		return nil, nil
	}
	r.commMu.Lock()
	defer r.commMu.Unlock()
	sent := make(map[string]uint64, len(r.phaseSentBytes))
	recv := make(map[string]uint64, len(r.phaseRecvBytes))
	for k, v := range r.phaseSentBytes {
		sent[k] = v
	}
	for k, v := range r.phaseRecvBytes {
		recv[k] = v
	}
	return sent, recv
}

type tblsThresholdSigner struct {
	t int
	n int
	// v2Role is non-empty only for signers loaded from the V2 role bundle.
	// Protocol entry points use it to reject APDB/control/coin key swapping.
	v2Role string

	pubKey                bls12381.G2Affine   // group public key = secret * G2
	pubKeyShares          []bls12381.G2Affine // individual pk_i = share_i * G2
	transportPubKeyShares []bls12381.G1Affine
	shares                []fr.Element // secret key shares

	memberOrder    []int
	memberIndex    map[int]int
	signingMembers map[int]struct{}
}

var _, _, genG1, genG2 = bls12381.Generators()

func newTBLSThresholdSigner(members []int, threshold int, stream cipher.Stream) (*tblsThresholdSigner, error) {
	if len(members) == 0 {
		return nil, fmt.Errorf("empty members")
	}
	if threshold <= 0 || threshold > len(members) {
		return nil, fmt.Errorf("invalid threshold: %d", threshold)
	}

	n := len(members)
	// Generate BLS12-381 t-out-of-n threshold keys via Shamir secret sharing
	coeffs := make([]fr.Element, threshold)
	for j := 0; j < threshold; j++ {
		buf := make([]byte, fr.Bytes)
		stream.XORKeyStream(buf, buf)
		coeffs[j].SetBytes(buf[:fr.Bytes])
	}

	shares := make([]fr.Element, n)
	for i := 0; i < n; i++ {
		var x fr.Element
		x.SetInt64(int64(i + 1))
		shares[i].SetZero()
		xPow := new(fr.Element)
		xPow.SetOne()
		for j := 0; j < threshold; j++ {
			var term fr.Element
			term.Mul(&coeffs[j], xPow)
			shares[i].Add(&shares[i], &term)
			xPow.Mul(xPow, &x)
		}
	}

	// Compute public key shares: pk_i = share_i * G2
	pubKeyShares := make([]bls12381.G2Affine, n)
	transportPubKeyShares := make([]bls12381.G1Affine, n)
	for i := 0; i < n; i++ {
		pubKeyShares[i].ScalarMultiplication(&genG2, shares[i].BigInt(new(big.Int)))
		transportPubKeyShares[i].ScalarMultiplication(&genG1, shares[i].BigInt(new(big.Int)))
	}

	// Group public key = coeffs[0] * G2
	var pubKey bls12381.G2Affine
	pubKey.ScalarMultiplication(&genG2, coeffs[0].BigInt(new(big.Int)))

	memberOrder := sortedCopy(members)
	memberIndex := make(map[int]int, len(memberOrder))
	for i, id := range memberOrder {
		memberIndex[id] = i
	}

	return &tblsThresholdSigner{
		t:                     threshold,
		n:                     n,
		pubKey:                pubKey,
		pubKeyShares:          pubKeyShares,
		transportPubKeyShares: transportPubKeyShares,
		shares:                shares,
		memberOrder:           memberOrder,
		memberIndex:           memberIndex,
	}, nil
}

func newTBLSThresholdSignerFromMaterial(material *cvOldLockKeyMaterial) (*tblsThresholdSigner, error) {
	if material == nil || material.threshold <= 0 || material.threshold > len(material.members) ||
		len(material.publicShares) != len(material.members) || len(material.localShares) == 0 {
		return nil, fmt.Errorf("invalid CV old-lock signer material")
	}
	memberIndex := make(map[int]int, len(material.members))
	shares := make([]fr.Element, len(material.members))
	for i, member := range material.members {
		memberIndex[member] = i
		if share, ok := material.localShares[member]; ok {
			shares[i] = share
		}
	}
	return &tblsThresholdSigner{
		t: material.threshold, n: len(material.members), pubKey: material.groupPublic,
		pubKeyShares: append([]bls12381.G2Affine(nil), material.publicShares...), shares: shares,
		transportPubKeyShares: append([]bls12381.G1Affine(nil), material.transportPublicShares...),
		memberOrder:           append([]int(nil), material.members...), memberIndex: memberIndex,
		signingMembers: nodeSet(materialMemberIDs(material.localShares)),
	}, nil
}

func cvV2SignerHasRole(signer *tblsThresholdSigner, role string) bool {
	return signer != nil && cvV2KnownThresholdRole(role) && signer.v2Role == role
}

func newTBLSThresholdSignerFromCoinMaterial(material *cvMVBACoinKeyMaterial) (*tblsThresholdSigner, error) {
	if material == nil || material.threshold <= 0 || material.threshold > len(material.members) ||
		len(material.publicShares) != len(material.members) || len(material.localShares) == 0 {
		return nil, fmt.Errorf("invalid CV MVBA coin signer material")
	}
	memberIndex := make(map[int]int, len(material.members))
	shares := make([]fr.Element, len(material.members))
	for i, member := range material.members {
		memberIndex[member] = i
		if share, ok := material.localShares[member]; ok {
			shares[i] = share
		}
	}
	return &tblsThresholdSigner{
		t: material.threshold, n: len(material.members), pubKey: material.groupPublic,
		pubKeyShares: append([]bls12381.G2Affine(nil), material.publicShares...), shares: shares,
		memberOrder: append([]int(nil), material.members...), memberIndex: memberIndex,
		signingMembers: nodeSet(materialMemberIDs(material.localShares)),
	}, nil
}

func newTBLSThresholdSignerFromV2Material(material *cvV2ThresholdKeyMaterial) (*tblsThresholdSigner, error) {
	if material == nil || !cvV2KnownThresholdRole(material.role) || material.threshold <= 0 ||
		material.threshold > len(material.members) || len(material.publicShares) != len(material.members) ||
		len(material.transportPublicShares) != len(material.members) || len(material.localShares) == 0 {
		return nil, fmt.Errorf("invalid CV V2 threshold signer material")
	}
	memberIndex := make(map[int]int, len(material.members))
	shares := make([]fr.Element, len(material.members))
	for i, member := range material.members {
		memberIndex[member] = i
		if share, ok := material.localShares[member]; ok {
			shares[i] = share
		}
	}
	return &tblsThresholdSigner{
		t: material.threshold, n: len(material.members), v2Role: material.role, pubKey: material.groupPublic,
		pubKeyShares: append([]bls12381.G2Affine(nil), material.publicShares...), shares: shares,
		transportPubKeyShares: append([]bls12381.G1Affine(nil), material.transportPublicShares...),
		memberOrder:           append([]int(nil), material.members...), memberIndex: memberIndex,
		signingMembers: nodeSet(materialMemberIDs(material.localShares)),
	}, nil
}

type mvbaDomainSigner struct {
	member int
	high   *tblsThresholdSigner
	low    *tblsThresholdSigner
}

func (s *mvbaDomainSigner) ID() int { return s.member }

func (s *mvbaDomainSigner) signerForDomain(domain string) (*tblsThresholdSigner, bool) {
	switch strings.ToUpper(domain) {
	case "PD_STORED", "PD_LOCKED", "ACS_DIFFUSE":
		return s.high, s.high != nil
	case "PD_QUIT_READY", "EQ_COIN_SHARE":
		return s.low, s.low != nil
	default:
		return nil, false
	}
}

func (s *mvbaDomainSigner) Sign(domain string, digest []byte) ([]byte, error) {
	signer, ok := s.signerForDomain(domain)
	if !ok {
		return nil, fmt.Errorf("missing MVBA signer for domain %s", domain)
	}
	return signer.SignShare(s.member, domain, digest)
}

func (s *mvbaDomainSigner) Verify(from int, domain string, digest, signature []byte) bool {
	signer, ok := s.signerForDomain(domain)
	return ok && signer.VerifyShare(from, domain, digest, signature)
}

func (s *mvbaDomainSigner) Threshold(domain string) int {
	signer, ok := s.signerForDomain(domain)
	if !ok {
		return 0
	}
	return signer.Threshold()
}

func (s *mvbaDomainSigner) Recover(domain string, digest []byte, shares map[int][]byte) ([]byte, error) {
	signer, ok := s.signerForDomain(domain)
	if !ok {
		return nil, fmt.Errorf("missing MVBA signer for domain %s", domain)
	}
	return signer.Recover(domain, digest, shares)
}

func (s *mvbaDomainSigner) VerifyRecovered(domain string, digest, signature []byte) bool {
	signer, ok := s.signerForDomain(domain)
	return ok && signer.VerifyRecovered(domain, digest, signature)
}

func materialMemberIDs(shares map[int]fr.Element) []int {
	ids := make([]int, 0, len(shares))
	for id := range shares {
		ids = append(ids, id)
	}
	return ids
}

func (s *tblsThresholdSigner) Threshold() int {
	return s.t
}

func (s *tblsThresholdSigner) restrictSigningTo(members []int) {
	s.signingMembers = nodeSet(members)
}

// SignShare produces a BLS signature share on G1: H(m)^share_i
func (s *tblsThresholdSigner) SignShare(member int, domain string, digest []byte) ([]byte, error) {
	idx, ok := s.memberIndex[member]
	if !ok {
		return nil, fmt.Errorf("unknown member: %d", member)
	}
	if s.signingMembers != nil {
		if _, ok := s.signingMembers[member]; !ok {
			return nil, fmt.Errorf("member %d has no local signing share", member)
		}
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return nil, fmt.Errorf("hash to G1: %w", err)
	}
	var sig bls12381.G1Affine
	sig.ScalarMultiplication(&h, s.shares[idx].BigInt(new(big.Int)))
	return sig.Marshal(), nil
}

// VerifyShare checks e(sig_i, G2) == e(H(m), pk_i)
func (s *tblsThresholdSigner) VerifyShare(member int, domain string, digest []byte, sigBytes []byte) bool {
	idx, ok := s.memberIndex[member]
	if !ok || idx >= len(s.pubKeyShares) {
		return false
	}
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil {
		return false
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return false
	}
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKeyShares[idx])
	ok, _ = bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{genG2, negPK},
	)
	return ok
}

// Recover reconstructs the full BLS signature via Lagrange interpolation over G1.
func (s *tblsThresholdSigner) Recover(domain string, digest []byte, sharesMap map[int][]byte) ([]byte, error) {
	if len(sharesMap) < s.t {
		return nil, fmt.Errorf("insufficient shares: have=%d need=%d", len(sharesMap), s.t)
	}
	memberIDs := make([]int, 0, len(sharesMap))
	for id := range sharesMap {
		memberIDs = append(memberIDs, id)
	}
	sort.Slice(memberIDs, func(i, j int) bool {
		return s.memberIndex[memberIDs[i]] < s.memberIndex[memberIDs[j]]
	})

	// Lagrange coefficients
	ids := make([]int, len(memberIDs))
	for i, mid := range memberIDs {
		ids[i] = s.memberIndex[mid] + 1 // use 1-based index
	}
	coeffs := make([]fr.Element, len(ids))
	for i, id1 := range ids {
		coeffs[i].SetOne()
		for _, id2 := range ids {
			if id1 == id2 {
				continue
			}
			num := new(big.Int).SetInt64(int64(id2))
			den := new(big.Int).SetInt64(int64(id2 - id1))
			var nf, df fr.Element
			nf.SetBigInt(num)
			df.SetBigInt(den)
			df.Inverse(&df)
			nf.Mul(&nf, &df)
			coeffs[i].Mul(&coeffs[i], &nf)
		}
	}

	var recovered bls12381.G1Affine
	zero := big.NewInt(0)
	recovered.ScalarMultiplication(&genG1, zero)
	for i, mid := range memberIDs {
		var sig bls12381.G1Affine
		if err := sig.Unmarshal(sharesMap[mid]); err != nil {
			return nil, fmt.Errorf("unmarshal share %d: %w", mid, err)
		}
		var term bls12381.G1Affine
		term.ScalarMultiplication(&sig, coeffs[i].BigInt(new(big.Int)))
		recovered.Add(&recovered, &term)
	}
	return recovered.Marshal(), nil
}

// VerifyRecovered checks e(sig, G2) == e(H(m), PK)
func (s *tblsThresholdSigner) VerifyRecovered(domain string, digest, sigBytes []byte) bool {
	var sig bls12381.G1Affine
	if err := sig.Unmarshal(sigBytes); err != nil {
		return false
	}
	msg := domainDigest(domain, digest)
	h, err := bls12381.HashToG1(msg, []byte(domain))
	if err != nil {
		return false
	}
	negPK := bls12381.G2Affine{}
	negPK.Neg(&s.pubKey)
	ok, _ := bls12381.PairingCheck(
		[]bls12381.G1Affine{sig, h},
		[]bls12381.G2Affine{genG2, negPK},
	)
	return ok
}

func domainDigest(domain string, digest []byte) []byte {
	return hashBytes(
		[]byte("rladkr-domain"),
		[]byte(strings.ToUpper(domain)),
		digest,
	)
}
