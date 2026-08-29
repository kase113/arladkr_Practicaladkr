package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	var (
		sid                = flag.String("sid", "cv-v2-reference", "experiment session identifier")
		epoch              = flag.Int("epoch", 1, "experiment epoch")
		oldNodes           = flag.Int("old-n", 7, "old committee size")
		oldFaults          = flag.Int("old-f", 2, "old committee fault bound")
		newNodes           = flag.Int("new-n", 4, "new committee size")
		newFaults          = flag.Int("new-f", 1, "new committee fault bound")
		proposerSample     = flag.Int("proposer-sample", 3, "eligibility proposer sample size")
		validatorSample    = flag.Int("validator-sample", 3, "eligibility validator sample size")
		failureTarget      = flag.String("failure-target", "smoke", "total sampling budget: smoke|original|high-assurance|1e-*|2^-*")
		runs               = flag.Int("runs", 1, "number of independent reference epochs")
		manifestOnly       = flag.Bool("manifest-only", false, "validate one point and emit its manifest without cryptographic execution")
		matrixFile         = flag.String("matrix-file", "", "versioned local reference matrix JSON")
		matrixManifestOnly = flag.Bool("matrix-manifest-only", false, "validate all matrix points without cryptographic execution")
	)
	flag.Parse()

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if *matrixFile != "" {
		matrix, err := loadCVV2ReferenceMatrix(*matrixFile)
		if err != nil {
			failCVV2Reference(2, "matrix", err)
		}
		report, err := executeCVV2ReferenceMatrix(matrix, *matrixManifestOnly)
		if err != nil {
			failCVV2Reference(1, "matrix", err)
		}
		if err := encoder.Encode(report); err != nil {
			failCVV2Reference(1, "matrix_encode", err)
		}
		return
	}

	point := cvV2ReferencePoint{
		Name: "single", SIDPrefix: *sid, Epoch: *epoch, Runs: *runs,
		OldNodes: *oldNodes, OldFaults: *oldFaults, NewNodes: *newNodes, NewFaults: *newFaults,
		FailureTarget: *failureTarget, ProposerSample: *proposerSample, ValidatorSample: *validatorSample,
		ExecutionMode: "reference-crypto",
	}
	if *manifestOnly {
		point.ExecutionMode = "manifest-only"
	}
	report, err := executeCVV2ReferencePoint(point, false)
	if err != nil {
		failCVV2Reference(1, "point", err)
	}
	if err := encoder.Encode(report); err != nil {
		failCVV2Reference(1, "report_encode", err)
	}
}

func failCVV2Reference(code int, stage string, err error) {
	fmt.Fprintf(os.Stderr, "CV_V2_REFERENCE_ERROR stage=%s err=%v\n", stage, err)
	os.Exit(code)
}
