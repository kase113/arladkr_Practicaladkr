package core

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// cvBuildReferenceAllACKLeafScalar is retained solely as a deterministic test
// fixture for subgroup and APDB network tests. It is not an experiment or
// production epoch runner.
func cvBuildReferenceAllACKLeafScalar(
	dealer int, context *cvLeafContextScalar,
	receivers *cvReceiverKeyMaterialScalar, validators *cvValidatorKeyMaterialScalar,
) (*cvLeafScalar, error) {
	if context == nil || receivers == nil || validators == nil {
		return nil, fmt.Errorf("invalid V2 leaf fixture input")
	}
	count := context.SharingDegree + 1
	scalarCoefficients := make([]fr.Element, count)
	blindingCoefficients := make([]fr.Element, count)
	for i := 0; i < count; i++ {
		if _, err := scalarCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
		if _, err := blindingCoefficients[i].SetRandom(); err != nil {
			return nil, err
		}
	}
	commitments, coreProof, err := cvProveCoreScalar(context, dealer, scalarCoefficients, blindingCoefficients)
	if err != nil {
		return nil, err
	}
	offers := make([]*cvReceiverLaneOfferScalar, len(context.NewRoster))
	acks := make([]*cvACKEvidenceScalar, len(context.NewRoster))
	for i, receiverID := range context.NewRoster {
		index := i + 1
		scalar := cvEvaluateScalarPolynomialScalar(scalarCoefficients, index)
		blinding := cvEvaluateScalarPolynomialScalar(blindingCoefficients, index)
		offers[i], _, err = cvEncryptReceiverLanesScalar(context, dealer, receiverID, index,
			&receivers.encryptionPublicKeys[i], scalar, blinding)
		if err != nil {
			return nil, err
		}
		encryptionSecret, ok := receivers.localEncryptionSecrets[receiverID]
		if !ok {
			return nil, fmt.Errorf("fixture receiver %d lacks decryption secret", receiverID)
		}
		identitySecret, ok := receivers.localIdentitySecrets[receiverID]
		if !ok {
			return nil, fmt.Errorf("fixture receiver %d lacks identity secret", receiverID)
		}
		acks[i], _, _, err = cvVerifyDecryptAndSignACKScalar(context, dealer, offers[i],
			&receivers.encryptionPublicKeys[i], encryptionSecret,
			receivers.identityPublicKeys[i], identitySecret)
		if err != nil {
			return nil, err
		}
	}
	return cvBuildAllACKLeafScalar(context, dealer, commitments, coreProof, offers, acks, receivers, validators)
}

// cvRandomDealerLeaf builds the legacy leaf fixture still used by the
// component-service compatibility tests. It is test-only and is not a
// production protocol entry point.
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
