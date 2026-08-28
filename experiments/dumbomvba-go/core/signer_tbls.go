package core

import (
	"crypto/cipher"
	"fmt"
	"sort"
	"strings"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
)

type tblsKeyset struct {
	t       int
	n       int
	pubPoly *share.PubPoly
	shares  []*share.PriShare
}

type TBLSKeyBundle struct {
	suite pairing.Suite
	low   tblsKeyset
	high  tblsKeyset
}

type TBLSSigner struct {
	id    int
	suite pairing.Suite
	low   tblsKeyset
	high  tblsKeyset
}

func GenerateTBLSKeyBundle(n int, f int) (*TBLSKeyBundle, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid n")
	}
	if f < 0 || n < 3*f+1 {
		return nil, fmt.Errorf("invalid f")
	}
	suite := bn256.NewSuite()
	lowT := f + 1
	highT := n - f
	low, err := genTBLSKeyset(suite, n, lowT)
	if err != nil {
		return nil, err
	}
	high, err := genTBLSKeyset(suite, n, highT)
	if err != nil {
		return nil, err
	}
	return &TBLSKeyBundle{
		suite: suite,
		low:   low,
		high:  high,
	}, nil
}

func genTBLSKeyset(suite pairing.Suite, n int, threshold int) (tblsKeyset, error) {
	return genTBLSKeysetWithStream(suite, n, threshold, suite.RandomStream())
}

func genTBLSKeysetWithStream(suite pairing.Suite, n int, threshold int, stream cipher.Stream) (tblsKeyset, error) {
	if threshold <= 0 || threshold > n {
		return tblsKeyset{}, fmt.Errorf("invalid threshold")
	}
	secret := suite.G2().Scalar().Pick(stream)
	priPoly := share.NewPriPoly(suite.G2(), threshold, secret, stream)
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	return tblsKeyset{
		t:       threshold,
		n:       n,
		pubPoly: pubPoly,
		shares:  priPoly.Shares(n),
	}, nil
}

// GenerateDeterministicTBLSKeyBundle creates a TBLS key bundle from a
// deterministic cipher.Stream so all machines with the same seed produce
// identical keys.
func GenerateDeterministicTBLSKeyBundle(n int, f int, stream cipher.Stream) (*TBLSKeyBundle, error) {
	if n <= 0 { return nil, fmt.Errorf("invalid n") }
	if f < 0 || n < 3*f+1 { return nil, fmt.Errorf("invalid f") }
	suite := bn256.NewSuite()
	lowT := f + 1
	highT := n - f
	low, err := genTBLSKeysetWithStream(suite, n, lowT, stream)
	if err != nil { return nil, err }
	high, err := genTBLSKeysetWithStream(suite, n, highT, stream)
	if err != nil { return nil, err }
	return &TBLSKeyBundle{suite: suite, low: low, high: high}, nil
}

func NewTBLSSigner(id int, bundle *TBLSKeyBundle) (*TBLSSigner, error) {
	if bundle == nil {
		return nil, fmt.Errorf("%w: nil tbls bundle", ErrInvalidConfig)
	}
	if id < 0 || id >= bundle.low.n {
		return nil, fmt.Errorf("%w: signer id %d out of range", ErrInvalidConfig, id)
	}
	return &TBLSSigner{
		id:    id,
		suite: bundle.suite,
		low:   bundle.low,
		high:  bundle.high,
	}, nil
}

func (s *TBLSSigner) ID() int {
	return s.id
}

func (s *TBLSSigner) Threshold(domain string) int {
	return s.selectKey(domain).t
}

func (s *TBLSSigner) Sign(domain string, digest []byte) ([]byte, error) {
	key := s.selectKey(domain)
	msg := domainDigest(domain, digest)
	return tbls.Sign(s.suite, key.shares[s.id], msg)
}

func (s *TBLSSigner) Verify(from int, domain string, digest, sig []byte) bool {
	key := s.selectKey(domain)
	if from < 0 || from >= key.n {
		return false
	}
	shareSig := tbls.SigShare(sig)
	idx, err := shareSig.Index()
	if err != nil || idx != from {
		return false
	}
	msg := domainDigest(domain, digest)
	return tbls.Verify(s.suite, key.pubPoly, msg, sig) == nil
}

func (s *TBLSSigner) Recover(domain string, digest []byte, shares map[int][]byte) ([]byte, error) {
	key := s.selectKey(domain)
	if len(shares) < key.t {
		return nil, fmt.Errorf("insufficient shares: have=%d need=%d", len(shares), key.t)
	}
	keys := make([]int, 0, len(shares))
	for id := range shares {
		keys = append(keys, id)
	}
	sort.Ints(keys)
	ordered := make([][]byte, 0, len(keys))
	for _, id := range keys {
		ordered = append(ordered, shares[id])
	}
	msg := domainDigest(domain, digest)
	return tbls.Recover(s.suite, key.pubPoly, msg, ordered, key.t, key.n)
}

func (s *TBLSSigner) VerifyRecovered(domain string, digest, sig []byte) bool {
	key := s.selectKey(domain)
	msg := domainDigest(domain, digest)
	return bls.Verify(s.suite, key.pubPoly.Commit(), msg, sig) == nil
}

func (s *TBLSSigner) selectKey(domain string) tblsKeyset {
	d := strings.ToUpper(domain)
	switch d {
	case "PD_STORED", "PD_LOCKED", "SPBC_ECHO", "ACS_DIFFUSE":
		return s.high
	default:
		return s.low
	}
}
