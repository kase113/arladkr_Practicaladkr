package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	cvV2SamplerDomain      = "ARL-CV-sAPVSS/v2-scalar-group/sample"
	cvV2CoinDomain         = "ARL-CV-sAPVSS/v2-scalar-group/coin"
	cvV2CoinOutputDomain   = "ARL-CV-sAPVSS/v2-scalar-group/coin-output"
	cvV2EligibilityCoinTag = "ELIG"
	cvV2ContributorCoinTag = "CONTRIB"
	cvV2ProposerSampleTag  = "PROP"
	cvV2ValidatorSampleTag = "VAL"
	cvV2SelectionSampleTag = "SELECT"
	cvV2CoinShareDomain    = "ARL-CV-sAPVSS/v2-scalar-group/coin-share"
)

type cvCoinShareV2 struct {
	InvocationDigest []byte
	Signature        []byte
}

func cvCoinShareV2CanonicalBytes(share *cvCoinShareV2) ([]byte, error) {
	if share == nil || len(share.InvocationDigest) != 32 || len(share.Signature) == 0 ||
		len(share.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 coin share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvV2CoinShareDomain))
	_ = cvWriteBytes(&wire, share.InvocationDigest)
	_ = cvWriteBytes(&wire, share.Signature)
	return wire.Bytes(), nil
}

func cvDecodeCoinShareV2(wire []byte) (*cvCoinShareV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvV2CoinShareDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvV2CoinShareDomain)) {
		return nil, fmt.Errorf("invalid CV V2 coin share domain")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 coin share invocation")
	}
	signature, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(signature) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 coin share signature")
	}
	share := &cvCoinShareV2{InvocationDigest: digest, Signature: signature}
	canonical, err := cvCoinShareV2CanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 coin share")
	}
	return share, nil
}

type cvCoinOutputV2 struct {
	Invocation  []byte
	Certificate []byte
	Value       []byte
}

func cvSelectedPoolIndicesV2(poolSize, componentCount int, coinValue []byte) ([]int, error) {
	if poolSize <= 0 || componentCount <= 0 || componentCount > poolSize {
		return nil, fmt.Errorf("invalid CV V2 contributor selection dimensions")
	}
	indices := make([]int, poolSize)
	for i := range indices {
		indices[i] = i
	}
	return cvSampleWithoutReplacementV2(indices, coinValue, cvV2SelectionSampleTag, componentCount)
}

func cvEligibilityCoinInvocationV2(sid string, epoch uint64) ([]byte, error) {
	if sid == "" || epoch == 0 {
		return nil, fmt.Errorf("invalid CV V2 eligibility coin invocation")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvV2EligibilityCoinTag))
	_ = cvWriteBytes(&wire, []byte(sid))
	cvWriteUint64(&wire, epoch)
	return wire.Bytes(), nil
}

func cvContributorCoinInvocationV2(contextDigest []byte, proposerID int, poolDigest []byte) ([]byte, error) {
	if len(contextDigest) != 32 || proposerID < 0 || len(poolDigest) != 32 {
		return nil, fmt.Errorf("invalid CV V2 contributor coin invocation")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvV2ContributorCoinTag))
	_ = cvWriteBytes(&wire, contextDigest)
	cvWriteUint64(&wire, uint64(proposerID))
	_ = cvWriteBytes(&wire, poolDigest)
	return wire.Bytes(), nil
}

func cvCoinInvocationDigestV2(invocation []byte) ([]byte, error) {
	if len(invocation) == 0 || len(invocation) > cvMaxLeafWireBytes {
		return nil, fmt.Errorf("invalid CV V2 coin invocation")
	}
	return hashBytes([]byte(cvV2CoinDomain), invocation), nil
}

func cvBuildCoinOutputV2(invocation, certificate []byte, signer *tblsThresholdSigner) (*cvCoinOutputV2, error) {
	digest, err := cvCoinInvocationDigestV2(invocation)
	if err != nil || !cvV2SignerHasRole(signer, cvV2RoleCoin) || len(certificate) == 0 || !signer.VerifyRecovered(cvV2CoinDomain, digest, certificate) {
		return nil, fmt.Errorf("invalid CV V2 coin certificate")
	}
	output := &cvCoinOutputV2{Invocation: append([]byte(nil), invocation...), Certificate: append([]byte(nil), certificate...)}
	output.Value = hashBytes([]byte(cvV2CoinOutputDomain), output.Invocation, output.Certificate)
	return output, nil
}

func cvVerifyCoinOutputV2(output *cvCoinOutputV2, expectedInvocation []byte, signer *tblsThresholdSigner) error {
	if output == nil || !cvV2SignerHasRole(signer, cvV2RoleCoin) || len(output.Invocation) == 0 || len(output.Certificate) == 0 || len(output.Value) != 32 ||
		len(expectedInvocation) == 0 || !bytes.Equal(output.Invocation, expectedInvocation) {
		return fmt.Errorf("invalid CV V2 coin output")
	}
	digest, err := cvCoinInvocationDigestV2(output.Invocation)
	if err != nil || !signer.VerifyRecovered(cvV2CoinDomain, digest, output.Certificate) {
		return fmt.Errorf("invalid CV V2 coin output certificate")
	}
	wantValue := hashBytes([]byte(cvV2CoinOutputDomain), output.Invocation, output.Certificate)
	if !bytes.Equal(wantValue, output.Value) {
		return fmt.Errorf("invalid CV V2 coin output value")
	}
	return nil
}

func cvCoinOutputV2CanonicalBytes(output *cvCoinOutputV2) ([]byte, error) {
	if output == nil || len(output.Invocation) == 0 || len(output.Invocation) > cvMaxLeafWireBytes ||
		len(output.Certificate) == 0 || len(output.Certificate) > cvMaxComponentSignatureBytes || len(output.Value) != 32 {
		return nil, fmt.Errorf("invalid CV V2 coin output")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvV2CoinOutputDomain))
	_ = cvWriteBytes(&wire, output.Invocation)
	_ = cvWriteBytes(&wire, output.Certificate)
	_ = cvWriteBytes(&wire, output.Value)
	return wire.Bytes(), nil
}

func cvDecodeCoinOutputV2(wire []byte) (*cvCoinOutputV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvV2CoinOutputDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvV2CoinOutputDomain)) {
		return nil, fmt.Errorf("invalid CV V2 coin output domain")
	}
	invocation, err := r.bytes(cvMaxLeafWireBytes)
	if err != nil || len(invocation) == 0 {
		return nil, fmt.Errorf("invalid CV V2 coin output invocation")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 {
		return nil, fmt.Errorf("invalid CV V2 coin output certificate")
	}
	value, err := r.bytes(32)
	if err != nil || len(value) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 coin output value")
	}
	output := &cvCoinOutputV2{Invocation: invocation, Certificate: certificate, Value: value}
	canonical, err := cvCoinOutputV2CanonicalBytes(output)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 coin output")
	}
	return output, nil
}

// cvSampleWithoutReplacementV2 derives a Fisher-Yates permutation from a
// domain-separated coin value. Rejection sampling removes modulo bias, and
// sorting the roster makes the result independent of input map/order state.
func cvSampleWithoutReplacementV2(roster []int, coinValue []byte, tag string, count int) ([]int, error) {
	ordered := sortedUnique(roster)
	if len(ordered) == 0 || len(ordered) != len(roster) || len(coinValue) == 0 ||
		tag == "" || count <= 0 || count > len(ordered) {
		return nil, fmt.Errorf("invalid CV V2 sampling input")
	}
	permutation := append([]int(nil), ordered...)
	stream := &cvV2CoinStream{coinValue: append([]byte(nil), coinValue...), tag: tag}
	for i := len(permutation) - 1; i > 0; i-- {
		j, err := stream.index(uint64(i + 1))
		if err != nil {
			return nil, err
		}
		permutation[i], permutation[j] = permutation[j], permutation[i]
	}
	return append([]int(nil), permutation[:count]...), nil
}

type cvV2CoinStream struct {
	coinValue []byte
	tag       string
	counter   uint64
}

func (s *cvV2CoinStream) nextUint64() uint64 {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], s.counter)
	s.counter++
	digest := hashBytes([]byte(cvV2SamplerDomain), s.coinValue, []byte(s.tag), counter[:])
	return binary.BigEndian.Uint64(digest[:8])
}

func (s *cvV2CoinStream) index(bound uint64) (int, error) {
	if bound == 0 || bound > uint64(^uint(0)>>1)+1 {
		return 0, fmt.Errorf("invalid CV V2 sampler bound")
	}
	// Values below threshold are discarded. The remaining 2^64-threshold
	// values form an exact multiple of bound.
	threshold := -bound % bound
	for {
		value := s.nextUint64()
		if value >= threshold {
			return int(value % bound), nil
		}
	}
}

func cvDeriveEligibilitySamplesV2(roster []int, coinValue []byte, proposerCount, validatorCount int) ([]int, []int, error) {
	proposers, err := cvSampleWithoutReplacementV2(roster, coinValue, cvV2ProposerSampleTag, proposerCount)
	if err != nil {
		return nil, nil, err
	}
	validators, err := cvSampleWithoutReplacementV2(roster, coinValue, cvV2ValidatorSampleTag, validatorCount)
	if err != nil {
		return nil, nil, err
	}
	return proposers, validators, nil
}
