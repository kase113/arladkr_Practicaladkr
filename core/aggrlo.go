package core

import (
	"fmt"
)

type aggRLOMaterializedBinding struct {
	payloadDigest  []byte
	freshShardRoot []byte
	beforeSign     func(int) error
}

func buildAggRLO(
	cfg Config,
	dealers []int,
	agg *APVSSAggregate,
	binding *aggRLOMaterializedBinding,
) (*AggRLO, error) {
	c := NormalizeConfig(cfg)
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	if c.runtime == nil || agg == nil || agg.Provider != "cv-sapvss" {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate input")
	}
	canonical, err := validateFinalDealerSet(c, dealers)
	if err != nil {
		return nil, err
	}
	if len(canonical) != len(agg.Dealers) {
		return nil, fmt.Errorf("aggregate dealer count mismatch")
	}
	for i := range canonical {
		if canonical[i] != agg.Dealers[i] {
			return nil, fmt.Errorf("aggregate dealer ordering mismatch at index=%d", i)
		}
	}
	header := AggHeader{
		SID: c.SID, Epoch: c.Epoch, Dealers: append([]int(nil), canonical...),
		AggregateDigest: append([]byte(nil), agg.AggregateDigest...),
	}
	if binding != nil {
		header.PayloadDigest = append([]byte(nil), binding.payloadDigest...)
		header.FreshShardRoot = append([]byte(nil), binding.freshShardRoot...)
	}
	header.MetadataHash = hashBytes(
		[]byte("aggrlo-meta"), []byte(c.SID), []byte(fmt.Sprintf("|epoch=%d", c.Epoch)),
		encodeInts(canonical), header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot,
	)
	threshold := len(c.runtime.oldOrder) - c.FOld
	holders := takeFirst(c.runtime.oldOrder, threshold)
	lockDigest := digestAggHeaderForLock(header)
	shares := make(map[int][]byte, len(holders))
	for _, holder := range holders {
		if binding != nil && binding.beforeSign != nil {
			if err := binding.beforeSign(holder); err != nil {
				return nil, fmt.Errorf("aggregate materialization check failed for holder=%d: %w", holder, err)
			}
		}
		signature, err := c.runtime.lockSigner.SignShare(holder, "RL_AGG_LOCK", lockDigest)
		if err != nil {
			return nil, fmt.Errorf("aggregate lock share failed for holder=%d: %w", holder, err)
		}
		shares[holder] = signature
	}
	certificate, err := c.runtime.lockSigner.Recover("RL_AGG_LOCK", lockDigest, shares)
	if err != nil {
		return nil, fmt.Errorf("aggregate lock certificate recovery failed: %w", err)
	}
	rlo := &AggRLO{
		Header:    header,
		Lock:      AggLock{Threshold: threshold, Certificate: certificate},
		Aggregate: *cloneAPVSSAggregate(agg),
	}
	rlo.Digest = digestAggRLO(*rlo)
	return rlo, nil
}

func validateAggRLOShape(cfg Config, rlo *AggRLO) ([]int, error) {
	if rlo == nil || rlo.Header.SID != cfg.SID || rlo.Header.Epoch != cfg.Epoch {
		return nil, fmt.Errorf("AggRLO sid/epoch mismatch")
	}
	dealers, err := validateFinalDealerSet(cfg, rlo.Header.Dealers)
	if err != nil {
		return nil, fmt.Errorf("AggRLO dealer set: %w", err)
	}
	if rlo.Aggregate.Provider != "cv-sapvss" || len(rlo.Aggregate.Dealers) != len(dealers) {
		return nil, fmt.Errorf("invalid CV-sAPVSS aggregate descriptor")
	}
	for i := range dealers {
		if dealers[i] != rlo.Aggregate.Dealers[i] {
			return nil, fmt.Errorf("AggRLO aggregate dealers mismatch at index=%d", i)
		}
	}
	if !bytesEq(rlo.Header.AggregateDigest, rlo.Aggregate.AggregateDigest) ||
		len(rlo.Header.PayloadDigest) != 32 || len(rlo.Header.FreshShardRoot) != 32 {
		return nil, fmt.Errorf("CV-sAPVSS AggRLO materialized binding mismatch")
	}
	return dealers, nil
}

func validateFinalDealerSet(cfg Config, dealers []int) ([]int, error) {
	if cfg.Kappa != cfg.FOld+1 {
		return nil, fmt.Errorf("aggregate dealer count must equal f_o+1")
	}
	canonical := sortedUnique(dealers)
	if len(canonical) != len(dealers) || len(canonical) != cfg.Kappa {
		return nil, fmt.Errorf("invalid aggregate dealer count or duplicates")
	}
	oldCommittee := nodeSet(cfg.OldCommittee)
	for _, dealer := range canonical {
		if _, ok := oldCommittee[dealer]; !ok {
			return nil, fmt.Errorf("dealer outside old committee: %d", dealer)
		}
	}
	return canonical, nil
}

func validateAggRLOLock(cfg Config, rlo *AggRLO) error {
	if cfg.runtime == nil || cfg.runtime.lockSigner == nil || rlo == nil {
		return fmt.Errorf("AggLock runtime is unavailable")
	}
	threshold := len(cfg.runtime.oldOrder) - cfg.FOld
	if rlo.Lock.Threshold != threshold {
		return fmt.Errorf("AggLock threshold mismatch")
	}
	digest := digestAggHeaderForLock(rlo.Header)
	if !cfg.runtime.lockSigner.VerifyRecovered("RL_AGG_LOCK", digest, rlo.Lock.Certificate) {
		return fmt.Errorf("AggLock recovered certificate invalid")
	}
	return nil
}

func validateAggRLODigest(rlo *AggRLO) error {
	if rlo == nil || !bytesEq(rlo.Digest, digestAggRLO(*rlo)) {
		return fmt.Errorf("AggRLO digest mismatch")
	}
	return nil
}

func digestAggHeaderForLock(header AggHeader) []byte {
	return hashBytes(
		[]byte("aggrlo-lock-digest"), []byte(header.SID),
		[]byte(fmt.Sprintf("|epoch=%d", header.Epoch)), encodeInts(header.Dealers),
		header.AggregateDigest, header.PayloadDigest, header.FreshShardRoot, header.MetadataHash,
	)
}

func digestAggRLO(rlo AggRLO) []byte {
	return hashBytes(
		[]byte("aggrlo"), []byte(rlo.Header.SID), []byte(fmt.Sprintf("|epoch=%d", rlo.Header.Epoch)),
		encodeInts(rlo.Header.Dealers), rlo.Header.AggregateDigest, rlo.Header.PayloadDigest,
		rlo.Header.FreshShardRoot, rlo.Header.MetadataHash, []byte(rlo.Aggregate.Provider),
		encodeInts(rlo.Aggregate.Dealers), rlo.Aggregate.AggregateDigest,
		[]byte(fmt.Sprintf("|threshold=%d", rlo.Lock.Threshold)), rlo.Lock.Certificate,
	)
}
