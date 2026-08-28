package core

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

func cvTestScalar(value uint64) fr.Element {
	var scalar fr.Element
	scalar.SetUint64(value)
	return scalar
}

func cvTestSigningKeys(tb testing.TB, count int, start uint64) []bls12381.G1Affine {
	tb.Helper()
	keys := make([]bls12381.G1Affine, count)
	for i := range keys {
		key, err := cvReceiverPublicKey(cvTestScalar(start + uint64(i)))
		if err != nil {
			tb.Fatal(err)
		}
		keys[i] = key
	}
	return keys
}

func cvTestCoins(count int, start uint64) []fr.Element {
	coins := make([]fr.Element, count)
	for i := range coins {
		coins[i].SetUint64(start + uint64(i))
	}
	return coins
}

func TestCVJointScalarHelpersMatchIndependentMultiplication(t *testing.T) {
	firstBase := cvTestScalar(7)
	secondBase := cvTestScalar(11)
	first := cvPointTimes(&genG1, &firstBase)
	second := cvPointTimes(&genG1, &secondBase)
	firstScalar := cvTestScalar(13)
	secondScalar := cvTestScalar(17)
	want := cvPointSum(
		pointPtr(cvPointTimes(&first, &firstScalar)),
		pointPtr(cvPointTimes(&second, &secondScalar)),
	)
	if got := cvPointJointTimes(&first, &firstScalar, &second, &secondScalar); !got.Equal(&want) {
		t.Fatal("joint scalar multiplication changed the two-base result")
	}
	want = cvPointSum(
		pointPtr(cvPointTimes(&genG1, &firstScalar)),
		pointPtr(cvPointTimes(&second, &secondScalar)),
	)
	if got := cvPointBaseAndTimes(&firstScalar, &second, &secondScalar); !got.Equal(&want) {
		t.Fatal("base joint scalar multiplication changed the result")
	}
}

func TestCVEvaluateCommitmentsUsesCachedPowersAndMatchesNaiveSum(t *testing.T) {
	commitments := make([]bls12381.G1Affine, 43)
	for i := range commitments {
		scalar := cvTestScalar(uint64(i + 2))
		commitments[i] = cvPointTimes(&genG1, &scalar)
	}
	powers := cvEvaluationPowers(len(commitments), 128)
	again := cvEvaluationPowers(len(commitments), 128)
	if &powers[0][0] != &again[0][0] {
		t.Fatal("CV evaluation powers were not cached")
	}
	got := cvEvaluateCommitmentsWithPowers(commitments, powers[127])
	zero := cvTestScalar(0)
	want := cvPointTimes(&genG1, &zero)
	for i := range commitments {
		term := cvPointTimes(&commitments[i], &powers[127][i])
		want.Add(&want, &term)
	}
	if !got.Equal(&want) {
		t.Fatal("MSM commitment evaluation changed the accepted relation")
	}
}

func TestCVAggregateVerifiedLeavesRejectsMutationAndContextReplay(t *testing.T) {
	_, context, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	accepted := make([]*cvVerifiedLeaf, len(leaves))
	for i := range leaves {
		accepted[i], err = cvAcceptedLeaf(&context, leaves[i], nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := cvAVerVerified(&context, agg, accepted); err != nil {
		t.Fatalf("verified aggregate rejected: %v", err)
	}

	originalDealer := leaves[0].dealerID
	leaves[0].dealerID++
	if err := cvAVerVerified(&context, agg, accepted); err == nil {
		t.Fatal("verified aggregate accepted a mutated leaf")
	}
	leaves[0].dealerID = originalDealer

	replayedContext := cvCloneLeafContext(context)
	replayedContext.epoch++
	if err := cvAVerVerified(&replayedContext, agg, accepted); err == nil {
		t.Fatal("verified aggregate accepted a cross-epoch token")
	}
}

func TestCVSAPVSSM0AggregateRoundTrip(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 4, maxComponents: 2}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	receiverSecret := cvTestScalar(19)
	receiverPK, err := cvReceiverPublicKey(receiverSecret)
	if err != nil {
		t.Fatal(err)
	}

	qMinusTwo := new(big.Int).Sub(fr.Modulus(), big.NewInt(2))
	var firstScalar fr.Element
	firstScalar.SetBigInt(qMinusTwo)
	first, err := cvReferenceEncryptShare(
		profile, receiverPK, firstScalar, cvTestScalar(7),
		cvTestCoins(chunks, 23), cvTestScalar(101),
	)
	if err != nil {
		t.Fatal(err)
	}
	second, err := cvReferenceEncryptShare(
		profile, receiverPK, cvTestScalar(5), cvTestScalar(11),
		cvTestCoins(chunks, 211), cvTestScalar(307),
	)
	if err != nil {
		t.Fatal(err)
	}

	aggregate, err := cvAggregate(profile, []*cvEncryptedShare{first, second})
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := cvDecryptShare(profile, receiverSecret, aggregate, 2)
	if err != nil {
		t.Fatal(err)
	}
	wantScalar := cvTestScalar(3)
	if !decrypted.scalar.Equal(&wantScalar) {
		t.Fatalf("aggregate scalar mismatch: got=%s want=3", decrypted.scalar.String())
	}
	var wantPublic bls12381.G1Affine
	wantPublic.ScalarMultiplication(&genG1, big.NewInt(3))
	if !decrypted.publicScalar.Equal(&wantPublic) {
		t.Fatal("aggregate public scalar mismatch")
	}
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	var wantBlinding bls12381.G1Affine
	wantBlinding.ScalarMultiplication(&h, big.NewInt(18))
	if !decrypted.blindingOpening.Equal(&wantBlinding) {
		t.Fatal("aggregate blinding opening mismatch")
	}
	if !cvVerifyRelation(aggregate, decrypted) {
		t.Fatal("aggregate Pedersen relation rejected")
	}
}

func TestCVSharedCoinBatchEncryptionMatchesReference(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 8, maxComponents: 3}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	keys := make([]bls12381.G1Affine, 4)
	scalars := make([]fr.Element, len(keys))
	blindings := make([]fr.Element, len(keys))
	for i := range keys {
		keys[i], err = cvReceiverPublicKey(cvTestScalar(uint64(101 + i)))
		if err != nil {
			t.Fatal(err)
		}
		scalars[i] = cvTestScalar(uint64(1001 + i*17))
		blindings[i] = cvTestScalar(uint64(2001 + i*19))
	}
	coins := cvTestCoins(chunks, 3001)
	blindingCoin := cvTestScalar(4001)
	batched, err := cvEncryptSharesSharedCoins(
		profile, keys, scalars, blindings, coins, blindingCoin,
	)
	if err != nil {
		t.Fatal(err)
	}
	for i := range keys {
		want, referenceErr := cvReferenceEncryptShare(
			profile, keys[i], scalars[i], blindings[i], coins, blindingCoin,
		)
		if referenceErr != nil {
			t.Fatal(referenceErr)
		}
		got := batched[i]
		if got == nil || !got.receiverPublicKey.Equal(&want.receiverPublicKey) ||
			!got.commitment.Equal(&want.commitment) ||
			!apvssEqualCiphertext(&got.blinding, &want.blinding) ||
			len(got.scalarChunks) != len(want.scalarChunks) {
			t.Fatalf("batched receiver %d differs from reference", i+1)
		}
		for chunk := range got.scalarChunks {
			if !apvssEqualCiphertext(&got.scalarChunks[chunk], &want.scalarChunks[chunk]) {
				t.Fatalf("batched receiver %d chunk %d differs from reference", i+1, chunk)
			}
		}
	}
}

func TestCVProductionJacobianAggregateMatchesAffineReference(t *testing.T) {
	_, context, _, leaves := cvM4Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	for receiverIndex := range agg.receivers {
		shares := make([]*cvEncryptedShare, len(leaves))
		for dealerIndex := range leaves {
			shares[dealerIndex] = leaves[dealerIndex].receivers[receiverIndex].encryptedShare
		}
		want, referenceErr := cvAggregate(context.profile, shares)
		if referenceErr != nil {
			t.Fatal(referenceErr)
		}
		got := &agg.receivers[receiverIndex]
		if !got.receiverPublicKey.Equal(&want.receiverPublicKey) ||
			!apvssEqualCiphertext(&got.blinding, &want.blinding) ||
			len(got.scalarChunks) != len(want.scalarChunks) {
			t.Fatalf("Jacobian receiver %d differs from affine reference", receiverIndex+1)
		}
		for chunk := range got.scalarChunks {
			if !apvssEqualCiphertext(&got.scalarChunks[chunk], &want.scalarChunks[chunk]) {
				t.Fatalf("Jacobian receiver %d chunk %d differs from affine reference", receiverIndex+1, chunk)
			}
		}
	}
}

func TestCVSAPVSSM0RejectsInfeasibleDLogProfile(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 20, maxComponents: 1 << 20}
	if _, err := cvChunkCount(profile); err == nil {
		t.Fatal("accepted CV-sAPVSS profile with infeasible bounded-DLog range")
	}
}

func TestCVBoundedDLogSolverReusesTableAcrossTargets(t *testing.T) {
	solver := cvNewBoundedDLogSolver(31)
	for _, want := range []uint64{0, 1, 15, 31} {
		var target bls12381.G1Affine
		target.ScalarMultiplication(&genG1, new(big.Int).SetUint64(want))
		if got, ok := solver.solve(&target); !ok || got != want {
			t.Fatalf("bounded DLog = %d, %v; want %d, true", got, ok, want)
		}
	}

	var outOfRange bls12381.G1Affine
	outOfRange.ScalarMultiplication(&genG1, big.NewInt(32))
	if got, ok := solver.solve(&outOfRange); ok {
		t.Fatalf("bounded DLog accepted out-of-range target as %d", got)
	}

	var invalid bls12381.G1Affine
	invalid.X.SetOne()
	invalid.Y.SetOne()
	if cvValidG1(&invalid, true) {
		t.Fatal("invalid-point fixture unexpectedly passed validation")
	}
	if got, ok := solver.solve(&invalid); ok {
		t.Fatalf("bounded DLog accepted invalid target as %d", got)
	}
}

func TestCVSAPVSSM1AReferenceDealAndLeaf(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 4, maxComponents: 2}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	receiverSecrets := []fr.Element{cvTestScalar(13), cvTestScalar(17), cvTestScalar(19)}
	receiverKeys := make([]bls12381.G1Affine, len(receiverSecrets))
	for i := range receiverSecrets {
		receiverKeys[i], err = cvReceiverPublicKey(receiverSecrets[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	context := cvLeafContext{
		sessionID:                 []byte("m1-a-session"),
		epoch:                     9,
		sharingDegree:             1,
		profile:                   profile,
		receiverPublicKeys:        receiverKeys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(receiverKeys), 20001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafStructuralProofProfile,
	}
	scalarCoins := make([][]fr.Element, len(receiverKeys))
	for i := range scalarCoins {
		scalarCoins[i] = cvTestCoins(chunks, uint64(1000+i*chunks))
	}
	leaf, err := cvReferenceDeal(
		context,
		41,
		[]fr.Element{cvTestScalar(5), cvTestScalar(7)},
		[]fr.Element{{}, {}},
		scalarCoins,
		make([]fr.Element, len(receiverKeys)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.hasLeafNIZK {
		t.Fatal("M1-A must not claim a leaf NIZK")
	}
	if err := cvVerifyLeaf(&context, leaf); err != nil {
		t.Fatalf("honest M1-A leaf rejected: %v", err)
	}
	firstWire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	secondWire, err := cvLeafCanonicalBytes(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(firstWire, secondWire) || len(leaf.digest) != 32 {
		t.Fatal("Leaf wire or digest is not canonical")
	}
	contextWire, err := cvLeafContextCanonicalBytes(&context)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cvLeafContextDigest(&context), hashBytes([]byte(cvLeafContextDigestDomain), contextWire)) {
		t.Fatal("Leaf context digest mismatch")
	}

	decrypted, err := cvDecryptShare(profile, receiverSecrets[1], leaf.receivers[1].encryptedShare, 1)
	if err != nil {
		t.Fatal(err)
	}
	want := cvTestScalar(19) // f(2) = 5 + 7*2.
	if !decrypted.scalar.Equal(&want) || !cvVerifyRelation(leaf.receivers[1].encryptedShare, decrypted) {
		t.Fatal("reference Deal did not evaluate and encrypt the degree-1 sharing")
	}
	for i := range leaf.receivers {
		if !cvIdentityCiphertext(&leaf.receivers[i].encryptedShare.blinding) {
			t.Fatalf("structural receiver %d did not carry the public identity blinding ciphertext", i+1)
		}
	}

	t.Run("rejects encrypted-zero blinding lane", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		var identity bls12381.G1Affine
		ciphertext, err := cvEncryptPoint(
			&bad.receivers[0].receiverPublicKey,
			&identity,
			cvTestScalar(2001),
		)
		if err != nil {
			t.Fatal(err)
		}
		bad.receivers[0].encryptedShare.blinding = ciphertext
		bad.digest = cvLeafDigest(bad)
		if bad.digest != nil || cvVerifyLeaf(&context, bad) == nil {
			t.Fatal("accepted a randomized encryption of zero in a structural blinding lane")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.receivers[0].receiverPublicKey = receiverKeys[1]
		bad.receivers[0].encryptedShare.receiverPublicKey = receiverKeys[1]
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted Leaf under the wrong receiver key")
		}
	})
	t.Run("wrong index", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.receivers[0].receiverIndex = 2
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted Leaf under the wrong receiver index")
		}
	})
	t.Run("replay", func(t *testing.T) {
		replayedContext := context
		replayedContext.epoch++
		if err := cvVerifyLeaf(&replayedContext, leaf); err == nil {
			t.Fatal("accepted Leaf replayed into another epoch")
		}
	})
	t.Run("commitment mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.coefficientCommitments[0].Add(&bad.coefficientCommitments[0], &genG1)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted coefficient commitment inconsistent with receiver evaluations")
		}
	})
	t.Run("ciphertext mutation", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[0].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted ciphertext mutation with a stale leaf digest")
		}
	})
}

func TestCVSAPVSSM1BGrothLeafProof(t *testing.T) {
	profile := cvChunkProfile{chunkBits: 8, maxComponents: 2}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	receiverSecrets := []fr.Element{cvTestScalar(23), cvTestScalar(29), cvTestScalar(31)}
	receiverKeys := make([]bls12381.G1Affine, len(receiverSecrets))
	for i := range receiverSecrets {
		receiverKeys[i], err = cvReceiverPublicKey(receiverSecrets[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	context := cvLeafContext{
		sessionID:                 []byte("m1-b-session"),
		epoch:                     10,
		sharingDegree:             1,
		profile:                   profile,
		receiverPublicKeys:        receiverKeys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(receiverKeys), 21001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	commonCoins := cvTestCoins(chunks, 3001)
	scalarCoins := make([][]fr.Element, len(receiverKeys))
	blindingCoins := make([]fr.Element, len(receiverKeys))
	for i := range receiverKeys {
		scalarCoins[i] = append([]fr.Element(nil), commonCoins...)
		blindingCoins[i] = cvTestScalar(4001)
	}
	leaf, err := cvReferenceDeal(
		context,
		43,
		[]fr.Element{cvTestScalar(17), cvTestScalar(5)},
		[]fr.Element{cvTestScalar(7), cvTestScalar(3)},
		scalarCoins,
		blindingCoins,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.hasLeafNIZK || leaf.proof == nil {
		t.Fatal("M1-B leaf did not carry a public proof")
	}
	statementDigest, err := cvLeafStatementDigest(leaf)
	if err != nil {
		t.Fatal(err)
	}
	wantY0, err := bls12381.HashToG1(statementDigest, []byte(cvChunkY0Domain))
	if err != nil {
		t.Fatal(err)
	}
	if !leaf.proof.chunking.y0.Equal(&wantY0) {
		t.Fatal("M1-B chunk base was dealer-selected instead of statement-derived")
	}
	if err := cvVerifyLeaf(&context, leaf); err != nil {
		t.Fatalf("honest M1-B leaf rejected: %v", err)
	}
	for i := 1; i < len(leaf.receivers); i++ {
		for chunk := range leaf.receivers[i].encryptedShare.scalarChunks {
			if !leaf.receivers[i].encryptedShare.scalarChunks[chunk].r.Equal(
				&leaf.receivers[0].encryptedShare.scalarChunks[chunk].r,
			) {
				t.Fatal("M1-B Deal did not use the Groth shared chunk coin")
			}
		}
		if !leaf.receivers[i].encryptedShare.blinding.r.Equal(
			&leaf.receivers[0].encryptedShare.blinding.r,
		) {
			t.Fatal("M1-B Deal did not use the shared blinding coin")
		}
	}

	t.Run("rejects independent coins", func(t *testing.T) {
		badCoins := make([][]fr.Element, len(scalarCoins))
		for i := range scalarCoins {
			badCoins[i] = append([]fr.Element(nil), scalarCoins[i]...)
		}
		one := fr.One()
		badCoins[1][0].Add(&badCoins[1][0], &one)
		if _, err := cvReferenceDeal(
			context,
			44,
			[]fr.Element{cvTestScalar(17), cvTestScalar(5)},
			[]fr.Element{cvTestScalar(7), cvTestScalar(3)},
			badCoins,
			blindingCoins,
		); err == nil {
			t.Fatal("accepted independent receiver coins for the Groth profile")
		}
	})
	t.Run("ciphertext mutation with refreshed digest", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.receivers[1].encryptedShare.scalarChunks[0].c.Add(
			&bad.receivers[1].encryptedShare.scalarChunks[0].c,
			&genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted ciphertext mutation after refreshing the leaf digest")
		}
	})
	t.Run("sharing response mutation with refreshed digest", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		one := fr.One()
		bad.proof.sharing.zScalar.Add(&bad.proof.sharing.zScalar, &one)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted a mutated correct-sharing response")
		}
	})
	t.Run("out of range chunk response with refreshed digest", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		tooLarge := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
		bad.proof.chunking.zDigits[0].SetBigInt(tooLarge)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted an out-of-range Groth chunk response")
		}
	})
	t.Run("exact range commitment mutation with refreshed digest", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.proof.chunking.exactRange.commitments[0].Add(
			&bad.proof.chunking.exactRange.commitments[0],
			&genG1,
		)
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted an exact range commitment mutation")
		}
	})
	t.Run("proof replay with refreshed digest", func(t *testing.T) {
		bad := cvCloneLeafForTest(leaf)
		bad.dealerID++
		bad.digest = cvLeafDigest(bad)
		if err := cvVerifyLeaf(&context, bad); err == nil {
			t.Fatal("accepted a proof replayed for another dealer")
		}
	})
}

func TestCVSAPVSSM1BRejectsOutOfRangeDigitProof(t *testing.T) {
	leaf, context := cvM1BLeafWithCustomPlaintexts(t, 256, 7, 256)
	if err := cvVerifyLeaf(&context, leaf); err == nil {
		t.Fatal("accepted a leaf whose scalar chunk plaintext is digit B")
	}
}

func TestCVSAPVSSM1BRejectsScalarBlindingCompensation(t *testing.T) {
	leaf, context := cvM1BLeafWithCustomPlaintexts(t, 17, 7, 19)
	decrypted, err := cvDecryptShare(context.profile, cvTestScalar(23), leaf.receivers[0].encryptedShare, 1)
	if err != nil {
		t.Fatalf("compensation ciphertext was not decryptable: %v", err)
	}
	wantScalar := cvTestScalar(17)
	if decrypted.scalar.Equal(&wantScalar) {
		t.Fatal("compensation fixture did not change the recovered scalar")
	}
	if !cvVerifyRelation(leaf.receivers[0].encryptedShare, decrypted) {
		t.Fatal("compensation fixture did not satisfy the current Pedersen relation")
	}
	if err := cvVerifyLeaf(&context, leaf); err == nil {
		t.Fatal("accepted scalar/blinding compensation with a mismatched scalar witness")
	}
}

func TestCVSAPVSSM1BRejectsRangeLinkHOffset(t *testing.T) {
	leaf, _ := cvM1BLeafWithCustomPlaintexts(t, 17, 7, 17)
	bad := cvCloneLeafForTest(leaf)
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	delta := cvTestScalar(3)
	offset := cvPointTimes(&h, &delta)
	bad.receivers[0].encryptedShare.scalarChunks[0].c.Add(
		&bad.receivers[0].encryptedShare.scalarChunks[0].c,
		&offset,
	)
	digits, err := cvScalarDigits(cvTestScalar(17), bad.context.profile)
	if err != nil {
		t.Fatal(err)
	}
	scalarCoins := cvTestCoins(len(bad.receivers[0].encryptedShare.scalarChunks), 7001)
	proof, err := cvProveExactRange(bad, [][]uint64{digits}, scalarCoins)
	if err != nil {
		t.Fatal(err)
	}
	statementDigest, err := cvLeafStatementDigest(bad)
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := cvExactRangeChallenge(statementDigest, &proof)
	if err != nil {
		t.Fatal(err)
	}
	var compensation fr.Element
	compensation.Mul(&challenge, &delta)
	proof.links[0].zRhos[0].Sub(&proof.links[0].zRhos[0], &compensation)
	if err := cvVerifyExactRange(bad, &proof); err == nil {
		t.Fatal("accepted a ciphertext H-offset compensated only in the old range-link response")
	}
}

func TestCVSAPVSSM2AggregateReceipt(t *testing.T) {
	context, secrets, leaves := cvM2Fixture(t)
	agg, err := cvAgg(&context, leaves)
	if err != nil {
		t.Fatal(err)
	}
	if err := cvAVer(&context, agg, leaves); err != nil {
		t.Fatalf("honest aggregate rejected: %v", err)
	}
	wire, err := cvAggregateCanonicalBytes(agg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, agg.digestWire) || len(agg.digest) != 32 {
		t.Fatal("Aggregate wire/digest is not canonical")
	}
	decrypted, receipt, err := cvDecShare(agg, secrets[0], 1)
	if err != nil {
		t.Fatalf("aggregate DecShare failed: %v", err)
	}
	if err := cvVerifyShare(&context, agg, 1, receipt); err != nil {
		t.Fatalf("honest receipt rejected: %v", err)
	}
	want := cvTestScalar(24) // (5+3*1) + (11+5*1).
	if !decrypted.scalar.Equal(&want) {
		t.Fatalf("aggregate scalar mismatch: got=%s want=24", decrypted.scalar.String())
	}

	t.Run("manifest mutation", func(t *testing.T) {
		bad := cvCloneAggregateForTest(agg)
		bad.dealerIDs[0], bad.dealerIDs[1] = bad.dealerIDs[1], bad.dealerIDs[0]
		if err := cvAVer(&context, bad, leaves); err == nil {
			t.Fatal("accepted noncanonical dealer manifest")
		}
	})
	t.Run("ciphertext mutation", func(t *testing.T) {
		bad := cvCloneAggregateForTest(agg)
		bad.receivers[0].scalarChunks[0].c.Add(&bad.receivers[0].scalarChunks[0].c, &genG1)
		if err := cvAVer(&context, bad, leaves); err == nil {
			t.Fatal("accepted aggregate ciphertext mutation")
		}
	})
	t.Run("randomized zero blinding ciphertext", func(t *testing.T) {
		bad := cvCloneAggregateForTest(agg)
		var identity bls12381.G1Affine
		ciphertext, err := cvEncryptPoint(
			&bad.receivers[0].receiverPublicKey,
			&identity,
			cvTestScalar(9001),
		)
		if err != nil {
			t.Fatal(err)
		}
		bad.receivers[0].blinding = ciphertext
		if _, err := cvAggregateCanonicalBytes(bad); err == nil {
			t.Fatal("encoded a structural aggregate with randomized zero blinding ciphertext")
		}
		if err := cvAVer(&context, bad, leaves); err == nil {
			t.Fatal("accepted a structural aggregate with randomized zero blinding ciphertext")
		}
	})
	t.Run("receipt mutation", func(t *testing.T) {
		bad := *receipt
		var one fr.Element
		one.SetOne()
		bad.proof.z.Add(&bad.proof.z, &one)
		if err := cvVerifyShare(&context, agg, 1, &bad); err == nil {
			t.Fatal("accepted mutated public receipt")
		}
	})
	t.Run("receipt mutation with refreshed digest", func(t *testing.T) {
		bad := *receipt
		var one fr.Element
		one.SetOne()
		bad.proof.z.Add(&bad.proof.z, &one)
		wire, err := cvReceiptCanonicalBytes(&bad)
		if err != nil {
			t.Fatal(err)
		}
		bad.digestWire = wire
		bad.digest = hashBytes([]byte(cvReceiptDomain), wire)
		if err := cvVerifyShare(&context, agg, 1, &bad); err == nil {
			t.Fatal("accepted a receipt mutation after refreshing its digest")
		}
	})
}

func cvM2Fixture(t *testing.T) (cvLeafContext, []fr.Element, []*cvLeaf) {
	t.Helper()
	profile := cvChunkProfile{chunkBits: 4, maxComponents: 2}
	secrets := []fr.Element{cvTestScalar(13), cvTestScalar(17)}
	keys := make([]bls12381.G1Affine, len(secrets))
	for i := range secrets {
		var err error
		keys[i], err = cvReceiverPublicKey(secrets[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	context := cvLeafContext{
		sessionID:                 []byte("m2-session"),
		epoch:                     12,
		sharingDegree:             1,
		profile:                   profile,
		receiverPublicKeys:        keys,
		receiverSigningPublicKeys: cvTestSigningKeys(t, len(keys), 22001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafStructuralProofProfile,
	}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	makeCoins := func(start uint64) [][]fr.Element {
		coins := make([][]fr.Element, len(keys))
		for i := range coins {
			coins[i] = cvTestCoins(chunks, start+uint64(i*chunks))
		}
		return coins
	}
	first, err := cvReferenceDeal(context, 10,
		[]fr.Element{cvTestScalar(5), cvTestScalar(3)},
		[]fr.Element{{}, {}},
		makeCoins(100), make([]fr.Element, len(keys)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := cvReferenceDeal(context, 11,
		[]fr.Element{cvTestScalar(11), cvTestScalar(5)},
		[]fr.Element{{}, {}},
		makeCoins(300), make([]fr.Element, len(keys)))
	if err != nil {
		t.Fatal(err)
	}
	return context, secrets, []*cvLeaf{first, second}
}

func cvCloneAggregateForTest(in *cvAggregateTranscript) *cvAggregateTranscript {
	out := *in
	out.dealerIDs = append([]uint64(nil), in.dealerIDs...)
	out.leafDigests = make([][]byte, len(in.leafDigests))
	for i := range in.leafDigests {
		out.leafDigests[i] = append([]byte(nil), in.leafDigests[i]...)
	}
	out.coefficientCommitments = append([]bls12381.G1Affine(nil), in.coefficientCommitments...)
	out.receivers = make([]cvAggregateReceiver, len(in.receivers))
	for i := range in.receivers {
		out.receivers[i] = in.receivers[i]
		out.receivers[i].scalarChunks = append([]cvElGamalCiphertext(nil), in.receivers[i].scalarChunks...)
	}
	return &out
}

// cvM1BLeafWithCustomPlaintexts builds a one-receiver fixture whose public
// commitments remain honest while the chunk and blinding plaintexts are chosen
// independently. It is intentionally a malicious-prover test fixture.
func cvM1BLeafWithCustomPlaintexts(
	t *testing.T,
	scalar, blinding, firstDigit uint64,
) (*cvLeaf, cvLeafContext) {
	t.Helper()
	profile := cvChunkProfile{chunkBits: 8, maxComponents: 2}
	secret := cvTestScalar(23)
	pk, err := cvReceiverPublicKey(secret)
	if err != nil {
		t.Fatal(err)
	}
	context := cvLeafContext{
		sessionID:                 []byte("m1-b-forgery"),
		epoch:                     11,
		sharingDegree:             0,
		profile:                   profile,
		receiverPublicKeys:        []bls12381.G1Affine{pk},
		receiverSigningPublicKeys: cvTestSigningKeys(t, 1, 23001),
		dealerSetPolicy:           []byte("first-f_o-plus-one"),
		proofProfile:              cvLeafGrothProofProfile,
	}
	chunks, err := cvChunkCount(profile)
	if err != nil {
		t.Fatal(err)
	}
	scalarWitness := cvTestScalar(scalar)
	blindingWitness := cvTestScalar(blinding)
	scalarCoin := cvTestCoins(chunks, 7001)
	blindingCoin := cvTestScalar(8001)
	h, err := cvPedersenBase()
	if err != nil {
		t.Fatal(err)
	}
	var scalarPoint, blindingPoint, commitment bls12381.G1Affine
	scalarPoint.ScalarMultiplication(&genG1, scalarWitness.BigInt(new(big.Int)))
	blindingPoint.ScalarMultiplication(&h, blindingWitness.BigInt(new(big.Int)))
	commitment.Add(&scalarPoint, &blindingPoint)
	customBlinding := commitment
	var customScalarPoint bls12381.G1Affine
	customScalarPoint.ScalarMultiplication(&genG1, new(big.Int).SetUint64(firstDigit))
	customBlinding.Sub(&customBlinding, &customScalarPoint)

	digits := make([]uint64, chunks)
	digits[0] = firstDigit
	scalarChunks := make([]cvElGamalCiphertext, chunks)
	for i := range digits {
		var message bls12381.G1Affine
		message.ScalarMultiplication(&genG1, new(big.Int).SetUint64(digits[i]))
		scalarChunks[i], err = cvEncryptPoint(&pk, &message, scalarCoin[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	blindingCiphertext, err := cvEncryptPoint(&pk, &customBlinding, blindingCoin)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &cvLeaf{
		context:                cvCloneLeafContext(context),
		dealerID:               91,
		coefficientCommitments: []bls12381.G1Affine{commitment},
		receivers: []cvLeafReceiver{{
			receiverIndex:     1,
			receiverPublicKey: pk,
			encryptedShare: &cvEncryptedShare{
				receiverPublicKey: pk,
				scalarChunks:      scalarChunks,
				blinding:          blindingCiphertext,
				commitment:        commitment,
			},
		}},
		hasLeafNIZK: true,
	}
	sharing, err := cvProveSharing(
		leaf,
		[]fr.Element{scalarWitness},
		[]fr.Element{blindingWitness},
		scalarCoin,
		blindingCoin,
	)
	if err != nil {
		t.Fatal(err)
	}
	chunking, err := cvProveChunking(leaf, [][]uint64{digits}, scalarCoin)
	if err != nil {
		t.Fatal(err)
	}
	chunking.exactRange, err = cvProveExactRange(leaf, [][]uint64{digits}, scalarCoin)
	if err != nil {
		t.Fatal(err)
	}
	leaf.proof = &cvLeafProof{sharing: sharing, chunking: chunking}
	leaf.digest = cvLeafDigest(leaf)
	if leaf.digest == nil {
		t.Fatal("failed to encode malicious fixture")
	}
	return leaf, context
}

func cvCloneLeafForTest(in *cvLeaf) *cvLeaf {
	out := *in
	out.context.sessionID = append([]byte(nil), in.context.sessionID...)
	out.context.receiverPublicKeys = append([]bls12381.G1Affine(nil), in.context.receiverPublicKeys...)
	out.context.receiverSigningPublicKeys = append([]bls12381.G1Affine(nil), in.context.receiverSigningPublicKeys...)
	out.context.dealerSetPolicy = append([]byte(nil), in.context.dealerSetPolicy...)
	out.coefficientCommitments = append([]bls12381.G1Affine(nil), in.coefficientCommitments...)
	out.receivers = append([]cvLeafReceiver(nil), in.receivers...)
	for i := range out.receivers {
		share := *in.receivers[i].encryptedShare
		share.scalarChunks = append([]cvElGamalCiphertext(nil), share.scalarChunks...)
		out.receivers[i].encryptedShare = &share
	}
	out.digest = append([]byte(nil), in.digest...)
	if in.proof != nil {
		proof := *in.proof
		proof.chunking.b = append([]bls12381.G1Affine(nil), in.proof.chunking.b...)
		proof.chunking.c = append([]bls12381.G1Affine(nil), in.proof.chunking.c...)
		proof.chunking.d = append([]bls12381.G1Affine(nil), in.proof.chunking.d...)
		proof.chunking.zCoins = append([]fr.Element(nil), in.proof.chunking.zCoins...)
		proof.chunking.zDigits = append([]fr.Element(nil), in.proof.chunking.zDigits...)
		proof.chunking.exactRange.commitments = append([]bls12381.G1Affine(nil), in.proof.chunking.exactRange.commitments...)
		proof.chunking.exactRange.bits = append([]cvBitProof(nil), in.proof.chunking.exactRange.bits...)
		proof.chunking.exactRange.links = append([]cvRangeLinkProof(nil), in.proof.chunking.exactRange.links...)
		for i := range proof.chunking.exactRange.links {
			proof.chunking.exactRange.links[i].tCommitments = append([]bls12381.G1Affine(nil), in.proof.chunking.exactRange.links[i].tCommitments...)
			proof.chunking.exactRange.links[i].tCiphertexts = append([]bls12381.G1Affine(nil), in.proof.chunking.exactRange.links[i].tCiphertexts...)
			proof.chunking.exactRange.links[i].zDigits = append([]fr.Element(nil), in.proof.chunking.exactRange.links[i].zDigits...)
			proof.chunking.exactRange.links[i].zRhos = append([]fr.Element(nil), in.proof.chunking.exactRange.links[i].zRhos...)
		}
		out.proof = &proof
	}
	out.compactProof = apvssCloneCompactFallbackProofForTest(in.compactProof)
	return &out
}
