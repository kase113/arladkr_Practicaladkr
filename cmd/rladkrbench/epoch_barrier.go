package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"rladkr_go/core"
)

const benchmarkEpochMarkerVersion = 1

type benchmarkEpochMarker struct {
	Version int    `json:"version"`
	SID     string `json:"sid"`
	Run     int    `json:"run"`
	Epoch   int    `json:"epoch"`
	NodeID  int    `json:"node_id"`
	Digest  string `json:"digest"`
}

func arlResultDigest(cfg core.Config, result *core.EpochResult) (string, error) {
	if result == nil || len(result.NewPublicKey) == 0 || len(result.AggRLODigest) == 0 {
		return "", fmt.Errorf("benchmark result is missing public agreement output")
	}
	dealers := append([]int(nil), result.LockedSet...)
	sort.Ints(dealers)
	aggregateDigest := sha256.Sum256(result.RecoveredAggregate)
	statement := struct {
		Domain          string `json:"domain"`
		SID             string `json:"sid"`
		Epoch           int    `json:"epoch"`
		Dealers         []int  `json:"dealers"`
		AggRLODigest    []byte `json:"aggrlo_digest"`
		AggregateDigest []byte `json:"aggregate_digest"`
		PublicKey       []byte `json:"public_key"`
	}{
		Domain: "ARL_ADKR_BENCH_RESULT_V1", SID: cfg.SID, Epoch: cfg.Epoch,
		Dealers: dealers, AggRLODigest: result.AggRLODigest,
		AggregateDigest: aggregateDigest[:], PublicKey: result.NewPublicKey,
	}
	raw, err := json.Marshal(statement)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func waitForBenchmarkEpoch(
	ctx context.Context,
	dir, sid string,
	run, epoch int,
	committee, localNodes []int,
	digest string,
) error {
	return waitForBenchmarkEpochQuorum(ctx, dir, sid, run, epoch, committee, localNodes, digest, len(committee))
}

func waitForBenchmarkEpochQuorum(
	ctx context.Context,
	dir, sid string,
	run, epoch int,
	committee, localNodes []int,
	digest string,
	required int,
) error {
	if dir == "" {
		return nil
	}
	if ctx == nil || sid == "" || len(committee) == 0 || len(localNodes) == 0 || digest == "" {
		return fmt.Errorf("invalid benchmark epoch barrier input")
	}
	if required <= 0 || required > len(committee) {
		return fmt.Errorf("invalid benchmark epoch barrier quorum: required=%d committee=%d", required, len(committee))
	}
	sidDigest := sha256.Sum256([]byte(sid))
	epochDir := filepath.Join(
		dir,
		hex.EncodeToString(sidDigest[:8]),
		fmt.Sprintf("run-%06d", run),
		fmt.Sprintf("epoch-%020d", epoch),
	)
	if err := os.MkdirAll(epochDir, 0o700); err != nil {
		return fmt.Errorf("create benchmark epoch barrier: %w", err)
	}
	member := make(map[int]struct{}, len(committee))
	for _, id := range committee {
		member[id] = struct{}{}
	}
	for _, id := range localNodes {
		if _, ok := member[id]; !ok {
			return fmt.Errorf("benchmark epoch barrier local node %d is not in committee", id)
		}
		marker := benchmarkEpochMarker{
			Version: benchmarkEpochMarkerVersion, SID: sid, Run: run, Epoch: epoch, NodeID: id, Digest: digest,
		}
		if err := writeBenchmarkEpochMarker(epochDir, marker); err != nil {
			return err
		}
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		ready := 0
		for _, id := range committee {
			marker, err := readBenchmarkEpochMarker(epochDir, id)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				return err
			}
			if marker.Version != benchmarkEpochMarkerVersion || marker.SID != sid || marker.Run != run ||
				marker.Epoch != epoch || marker.NodeID != id {
				return fmt.Errorf("benchmark epoch barrier marker for node %d has the wrong context", id)
			}
			if marker.Digest != digest {
				return fmt.Errorf("benchmark epoch result mismatch at node %d: got=%s want=%s", id, marker.Digest, digest)
			}
			ready++
		}
		if ready >= required {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("benchmark epoch barrier ready=%d/%d: %w", ready, required, ctx.Err())
		case <-ticker.C:
		}
	}
}

func writeBenchmarkEpochMarker(dir string, marker benchmarkEpochMarker) error {
	path := filepath.Join(dir, fmt.Sprintf("node-%06d.json", marker.NodeID))
	raw, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".epoch-marker-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	err = os.Link(temporaryPath, path)
	if os.IsExist(err) {
		existing, readErr := readBenchmarkEpochMarker(dir, marker.NodeID)
		if readErr != nil {
			return readErr
		}
		if existing != marker {
			return fmt.Errorf("conflicting benchmark epoch marker for node %d", marker.NodeID)
		}
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

func readBenchmarkEpochMarker(dir string, nodeID int) (benchmarkEpochMarker, error) {
	path := filepath.Join(dir, fmt.Sprintf("node-%06d.json", nodeID))
	raw, err := os.ReadFile(path)
	if err != nil {
		return benchmarkEpochMarker{}, err
	}
	var marker benchmarkEpochMarker
	if err := json.Unmarshal(raw, &marker); err != nil {
		return benchmarkEpochMarker{}, fmt.Errorf("decode benchmark epoch marker for node %d: %w", nodeID, err)
	}
	return marker, nil
}
