package core

import (
	"bytes"
	"context"
	"fmt"
	"time"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvMaterializedAggRLOWitnessDomain = "ARL-CV-sAPVSS/materialized-aggrlo-certificate"

func cvMaterializedAggRLOWitnessCanonicalBytes(rlo *AggRLO) ([]byte, error) {
	if rlo == nil || rlo.Aggregate.Provider != "cv-sapvss" || rlo.Lock.Threshold <= 0 ||
		len(rlo.Lock.Certificate) == 0 || len(rlo.Lock.Certificate) > cvMaxComponentSignatureBytes ||
		len(rlo.Digest) != 32 || !bytes.Equal(rlo.Digest, digestAggRLO(*rlo)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO witness")
	}
	headerWire, err := cvNetworkAggHeaderCanonicalBytes(rlo.Header)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvMaterializedAggRLOWitnessDomain))
	_ = cvWriteBytes(&wire, headerWire)
	_ = cvWriteUint32(&wire, rlo.Lock.Threshold)
	_ = cvWriteBytes(&wire, rlo.Lock.Certificate)
	_ = cvWriteBytes(&wire, rlo.Digest)
	return wire.Bytes(), nil
}

func cvDecodeMaterializedAggRLOWitness(wire []byte, cfg Config) (*AggRLO, error) {
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvMaterializedAggRLOWitnessDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvMaterializedAggRLOWitnessDomain)) {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO witness domain")
	}
	headerWire, err := r.bytes(1 << 20)
	if err != nil {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO header")
	}
	header, err := cvDecodeNetworkAggHeader(headerWire, c)
	if err != nil {
		return nil, err
	}
	threshold, err := r.uint32()
	if err != nil || threshold != len(c.OldCommittee)-c.FOld {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS ARC threshold")
	}
	certificate, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(certificate) == 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS ARC certificate")
	}
	digest, err := r.bytes(32)
	if err != nil || len(digest) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid compact CV-sAPVSS materialized AggRLO digest")
	}
	rlo := &AggRLO{Header: header, Lock: AggLock{Threshold: threshold, Certificate: certificate}, Aggregate: APVSSAggregate{
		Provider: "cv-sapvss", Dealers: append([]int(nil), header.Dealers...),
		AggregateDigest: append([]byte(nil), header.AggregateDigest...)}, Digest: digest}
	if _, err := validateAggRLOShape(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLOLock(c, rlo); err != nil {
		return nil, err
	}
	if err := validateAggRLODigest(rlo); err != nil {
		return nil, err
	}
	canonical, err := cvMaterializedAggRLOWitnessCanonicalBytes(rlo)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical compact CV-sAPVSS materialized AggRLO witness")
	}
	return rlo, nil
}

func cvRunMaterializedAgreement(ctx context.Context, cfg Config, localRLO *AggRLO) (*AggRLO, time.Duration, error) {
	if localRLO == nil {
		return nil, 0, fmt.Errorf("missing local CV-sAPVSS materialized AggRLO")
	}
	wire, err := cvMaterializedAggRLOWitnessCanonicalBytes(localRLO)
	if err != nil {
		return nil, 0, err
	}
	predicate := func(_ int, payload []byte) bool {
		_, decodeErr := cvDecodeMaterializedAggRLOWitness(payload, cfg)
		return decodeErr == nil
	}
	payloads, peerWait, err := runArladkrMVBACCommonSubsetTCPInstance(ctx, cfg, "cv-materialized-aggrlo", wire, predicate)
	if err != nil {
		return nil, peerWait, err
	}
	if len(payloads) == 0 {
		return nil, peerWait, fmt.Errorf("CV-sAPVSS compact materialized agreement returned no witness")
	}
	decided, err := cvDecodeMaterializedAggRLOWitness(payloads[0], cfg)
	return decided, peerWait, err
}

func cvBuildEpochLeafContext(cfg Config, material *cvReceiverKeyMaterial) (cvLeafContext, error) {
	c := NormalizeConfig(cfg)
	if err := validateAPVSSProductionAdmission(c); err != nil {
		return cvLeafContext{}, err
	}
	if material == nil || len(material.receiverPublicKeys) != len(c.NewCommittee) ||
		len(material.receiverSigningPublicKeys) != len(material.receiverPublicKeys) || len(material.registryDigest) != 32 {
		return cvLeafContext{}, fmt.Errorf("invalid CV-sAPVSS epoch receiver material")
	}
	policy := append([]byte("ARL-CV-sAPVSS/first-f-plus-one|registry="), material.registryDigest...)
	policy = append(policy, encodeInts(sortedUnique(c.OldCommittee))...)
	policy = append(policy, byte(c.Kappa>>24), byte(c.Kappa>>16), byte(c.Kappa>>8), byte(c.Kappa))
	proofProfile := cvLeafStructuralProofProfile
	if c.APVSSMode == APVSSModeFullPublicVE {
		switch c.APVSSFullProofProfile {
		case APVSSFullProofExact:
			proofProfile = cvLeafGrothProofProfile
		case APVSSFullProofCompactBatch:
			proofProfile = cvLeafFullCompactProofProfile
		case APVSSFullProofFieldCongruent:
			proofProfile = cvLeafFullFieldProofProfile
		default:
			return cvLeafContext{}, fmt.Errorf("unsupported full-public-ve proof profile %q", c.APVSSFullProofProfile)
		}
	}
	context := cvLeafContext{
		sessionID:                 []byte(c.SID),
		epoch:                     uint64(c.Epoch),
		previousStateDigest:       append([]byte(nil), c.PreviousEpochStateDigest...),
		sharingDegree:             c.FNew,
		profile:                   cvChunkProfile{chunkBits: 8, maxComponents: c.Kappa},
		receiverPublicKeys:        append([]bls12381.G1Affine(nil), material.receiverPublicKeys...),
		receiverSigningPublicKeys: append([]bls12381.G1Affine(nil), material.receiverSigningPublicKeys...),
		dealerSetPolicy:           policy,
		proofProfile:              proofProfile,
	}
	if err := cvValidateLeafContext(&context); err != nil {
		return cvLeafContext{}, err
	}
	return context, nil
}

func cvRandomDealerLeaf(context cvLeafContext, dealer int) (*cvLeaf, error) {
	leaf, _, err := cvRandomDealerLeafWithWitness(context, dealer)
	return leaf, err
}

func cvRandomDealerLeafWithWitness(
	context cvLeafContext,
	dealer int,
) (*cvLeaf, *apvssDealerWitness, error) {
	if dealer < 0 {
		return nil, nil, fmt.Errorf("invalid CV-sAPVSS dealer")
	}
	coefficientCount := context.sharingDegree + 1
	scalarCoefficients := make([]fr.Element, coefficientCount)
	blindingCoefficients := make([]fr.Element, coefficientCount)
	for i := 0; i < coefficientCount; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, nil, fmt.Errorf("sample CV-sAPVSS scalar coefficient: %w", err)
		}
		if context.proofProfile != cvLeafStructuralProofProfile {
			if _, err := blindingCoefficients[i].SetRandom(); err != nil {
				return nil, nil, fmt.Errorf("sample CV-sAPVSS blinding coefficient: %w", err)
			}
		}
	}
	chunks, err := cvChunkCount(context.profile)
	if err != nil {
		return nil, nil, err
	}
	scalarCoins := make([][]fr.Element, len(context.receiverPublicKeys))
	blindingCoins := make([]fr.Element, len(context.receiverPublicKeys))
	if context.proofProfile == cvLeafGrothProofProfile {
		// The current full-proof prototype proves one shared-randomness relation.
		// It remains behind the backend gate until the cited multi-receiver
		// security theorem is matched to this exact statement.
		commonCoins := make([]fr.Element, chunks)
		for i := range commonCoins {
			if _, err := commonCoins[i].SetRandom(); err != nil {
				return nil, nil, fmt.Errorf("sample CV-sAPVSS chunk coin: %w", err)
			}
		}
		var commonBlindingCoin fr.Element
		if _, err := commonBlindingCoin.SetRandom(); err != nil {
			return nil, nil, fmt.Errorf("sample CV-sAPVSS blinding coin: %w", err)
		}
		for i := range scalarCoins {
			scalarCoins[i] = append([]fr.Element(nil), commonCoins...)
			blindingCoins[i] = commonBlindingCoin
		}
	} else {
		// ACK/fallback proofs are lane-local and do not need correlated coins.
		for receiver := range scalarCoins {
			scalarCoins[receiver] = make([]fr.Element, chunks)
			for chunk := range scalarCoins[receiver] {
				if _, err := scalarCoins[receiver][chunk].SetRandom(); err != nil {
					return nil, nil, fmt.Errorf("sample CV-sAPVSS receiver chunk coin: %w", err)
				}
			}
			if context.proofProfile != cvLeafStructuralProofProfile {
				if _, err := blindingCoins[receiver].SetRandom(); err != nil {
					return nil, nil, fmt.Errorf("sample CV-sAPVSS receiver blinding coin: %w", err)
				}
			}
		}
	}
	leaf, err := cvReferenceDeal(
		context, uint64(dealer), scalarCoefficients, blindingCoefficients, scalarCoins, blindingCoins,
	)
	if err != nil {
		return nil, nil, err
	}
	witness := &apvssDealerWitness{
		scalars:       make([]fr.Element, len(context.receiverPublicKeys)),
		blindings:     make([]fr.Element, len(context.receiverPublicKeys)),
		scalarCoins:   scalarCoins,
		blindingCoins: blindingCoins,
	}
	for i := range context.receiverPublicKeys {
		witness.scalars[i] = evalPolyInt(scalarCoefficients, int64(i+1))
		witness.blindings[i] = evalPolyInt(blindingCoefficients, int64(i+1))
	}
	return leaf, witness, nil
}

func cvFullPublicProofCanonicalBytes(leaf *cvLeaf) ([]byte, error) {
	if leaf == nil {
		return nil, fmt.Errorf("nil CV-sAPVSS full-public leaf")
	}
	switch leaf.context.proofProfile {
	case cvLeafGrothProofProfile:
		return cvLeafProofCanonicalBytes(leaf.proof)
	case cvLeafFullCompactProofProfile:
		return apvssCompactFallbackProofCanonicalBytes(leaf, leaf.compactProof)
	case cvLeafFullFieldProofProfile:
		return apvssCompactFieldProofCanonicalBytes(leaf, leaf.compactProof)
	default:
		return nil, fmt.Errorf("unsupported CV-sAPVSS full-public proof profile %q", leaf.context.proofProfile)
	}
}
