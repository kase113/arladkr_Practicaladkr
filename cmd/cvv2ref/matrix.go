package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"rladkr_go/core"
)

const (
	cvV2ReferenceMatrixSchema       = "arladkr-cvv2-reference-matrix-v1"
	cvV2ReferenceMatrixReportSchema = "arladkr-cvv2-reference-matrix-report-v1"
	cvV2ReferenceMatrixMaxBytes     = 1 << 20
)

type cvV2ReferencePoint struct {
	Name            string `json:"name"`
	SIDPrefix       string `json:"sid_prefix"`
	ExecutionMode   string `json:"execution_mode"`
	Epoch           int    `json:"epoch"`
	Runs            int    `json:"runs"`
	OldNodes        int    `json:"old_nodes"`
	OldFaults       int    `json:"old_faults"`
	NewNodes        int    `json:"new_nodes"`
	NewFaults       int    `json:"new_faults"`
	FailureTarget   string `json:"failure_target"`
	ProposerSample  int    `json:"proposer_sample"`
	ValidatorSample int    `json:"validator_sample"`
}

type cvV2ReferenceMatrix struct {
	Schema string               `json:"schema"`
	Name   string               `json:"name"`
	Points []cvV2ReferencePoint `json:"points"`
}

type cvV2ReferenceMatrixPointReport struct {
	Name   string              `json:"name"`
	Report cvV2ReferenceReport `json:"report"`
}

type cvV2ReferenceMatrixReport struct {
	Schema   string                           `json:"schema"`
	MatrixID string                           `json:"matrix_id"`
	Name     string                           `json:"name"`
	Points   []cvV2ReferenceMatrixPointReport `json:"points"`
}

func loadCVV2ReferenceMatrix(path string) (cvV2ReferenceMatrix, error) {
	if strings.TrimSpace(path) == "" {
		return cvV2ReferenceMatrix{}, fmt.Errorf("empty CV V2 reference matrix path")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return cvV2ReferenceMatrix{}, err
	}
	if len(raw) == 0 || len(raw) > cvV2ReferenceMatrixMaxBytes {
		return cvV2ReferenceMatrix{}, fmt.Errorf("invalid CV V2 reference matrix size")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var matrix cvV2ReferenceMatrix
	if err := decoder.Decode(&matrix); err != nil {
		return cvV2ReferenceMatrix{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return cvV2ReferenceMatrix{}, fmt.Errorf("invalid CV V2 reference matrix suffix")
	}
	if err := validateCVV2ReferenceMatrix(matrix); err != nil {
		return cvV2ReferenceMatrix{}, err
	}
	return matrix, nil
}

func validateCVV2ReferenceMatrix(matrix cvV2ReferenceMatrix) error {
	if matrix.Schema != cvV2ReferenceMatrixSchema || !cvV2MatrixName(matrix.Name) || len(matrix.Points) == 0 {
		return fmt.Errorf("invalid CV V2 reference matrix header")
	}
	seenNames := make(map[string]struct{}, len(matrix.Points))
	seenSIDs := make(map[string]struct{}, len(matrix.Points))
	for _, point := range matrix.Points {
		if !cvV2MatrixName(point.Name) || strings.TrimSpace(point.SIDPrefix) == "" ||
			(point.ExecutionMode != "reference-crypto" && point.ExecutionMode != "manifest-only") {
			return fmt.Errorf("invalid CV V2 reference matrix point %q", point.Name)
		}
		if _, duplicate := seenNames[point.Name]; duplicate {
			return fmt.Errorf("duplicate CV V2 reference matrix point %q", point.Name)
		}
		if _, duplicate := seenSIDs[point.SIDPrefix]; duplicate {
			return fmt.Errorf("duplicate CV V2 reference matrix SID prefix %q", point.SIDPrefix)
		}
		seenNames[point.Name] = struct{}{}
		seenSIDs[point.SIDPrefix] = struct{}{}
	}
	return nil
}

func cvV2MatrixName(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

func executeCVV2ReferenceMatrix(matrix cvV2ReferenceMatrix, forceManifestOnly bool) (cvV2ReferenceMatrixReport, error) {
	if err := validateCVV2ReferenceMatrix(matrix); err != nil {
		return cvV2ReferenceMatrixReport{}, err
	}
	wire, err := json.Marshal(matrix)
	if err != nil {
		return cvV2ReferenceMatrixReport{}, err
	}
	digest := sha256.Sum256(append([]byte("ARL-ADKR/CV-V2/reference-matrix/v1\x00"), wire...))
	report := cvV2ReferenceMatrixReport{
		Schema: cvV2ReferenceMatrixReportSchema, MatrixID: hex.EncodeToString(digest[:16]), Name: matrix.Name,
		Points: make([]cvV2ReferenceMatrixPointReport, 0, len(matrix.Points)),
	}
	for _, point := range matrix.Points {
		pointReport, runErr := executeCVV2ReferencePoint(point, forceManifestOnly)
		if runErr != nil {
			return cvV2ReferenceMatrixReport{}, fmt.Errorf("CV V2 reference matrix point %s: %w", point.Name, runErr)
		}
		report.Points = append(report.Points, cvV2ReferenceMatrixPointReport{Name: point.Name, Report: pointReport})
	}
	return report, nil
}

func executeCVV2ReferencePoint(point cvV2ReferencePoint, forceManifestOnly bool) (cvV2ReferenceReport, error) {
	sampling, err := core.ResolveCVV2Sampling(
		point.OldNodes, point.OldFaults, point.FailureTarget, point.ProposerSample, point.ValidatorSample,
	)
	if err != nil {
		return cvV2ReferenceReport{}, err
	}
	unionBound, err := core.CVV2SamplingUnionBound(sampling, point.Runs)
	if err != nil {
		return cvV2ReferenceReport{}, err
	}
	manifestOnly := forceManifestOnly || point.ExecutionMode == "manifest-only"
	manifest, err := buildCVV2ReferenceManifest(
		point.SIDPrefix, point.Epoch, point.Runs, point.OldNodes, point.OldFaults, point.NewNodes, point.NewFaults,
		sampling, unionBound, manifestOnly,
	)
	if err != nil {
		return cvV2ReferenceReport{}, err
	}
	if manifestOnly {
		return cvV2ReferenceReport{Schema: cvV2ReferenceReportSchema, Manifest: manifest}, nil
	}
	oldRoster := make([]int, point.OldNodes)
	newRoster := make([]int, point.NewNodes)
	for i := range oldRoster {
		oldRoster[i] = i
	}
	for i := range newRoster {
		newRoster[i] = point.OldNodes + i
	}
	results := make([]*core.CVV2ReferenceExperimentResult, 0, point.Runs)
	for run := 0; run < point.Runs; run++ {
		scratch, err := os.MkdirTemp("", "arladkr-cvv2ref-")
		if err != nil {
			return cvV2ReferenceReport{}, err
		}
		cfg := core.Config{
			SID: fmt.Sprintf("%s-run-%d", point.SIDPrefix, run+1), Epoch: point.Epoch,
			OldCommittee: oldRoster, NewCommittee: newRoster,
			OldFaults: point.OldFaults, NewFaults: point.NewFaults,
			CVProposerSampleSize: sampling.ProposerSampleSize, CVValidatorSampleSize: sampling.ValidatorSampleSize,
			CVSamplingFailureTarget: sampling.Target,
		}
		result, runErr := core.RunCVV2ReferenceExperiment(cfg, scratch)
		removeErr := os.RemoveAll(scratch)
		if runErr != nil {
			return cvV2ReferenceReport{}, fmt.Errorf("run %d: %w", run+1, runErr)
		}
		if removeErr != nil {
			return cvV2ReferenceReport{}, fmt.Errorf("run %d cleanup: %w", run+1, removeErr)
		}
		result.SamplingEpochs = point.Runs
		result.SamplingUnionBound = unionBound
		results = append(results, result)
	}
	return buildCVV2ReferenceReport(manifest, results)
}
