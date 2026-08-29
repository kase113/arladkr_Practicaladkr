package main

import (
	"path/filepath"
	"testing"
)

func TestReferenceMatrixV1LoadsAndDryRunsEveryPoint(t *testing.T) {
	path := filepath.Join("..", "..", "experiments", "cvv2_reference_matrix_v1.json")
	matrix, err := loadCVV2ReferenceMatrix(path)
	if err != nil {
		t.Fatal(err)
	}
	report, err := executeCVV2ReferenceMatrix(matrix, true)
	if err != nil {
		t.Fatal(err)
	}
	if report.Schema != cvV2ReferenceMatrixReportSchema || report.MatrixID == "" || len(report.Points) != 13 {
		t.Fatalf("invalid matrix dry-run report: %+v", report)
	}
	seenSecure := 0
	seenFunctional := 0
	for _, point := range report.Points {
		if point.Report.Manifest.ExecutionMode != "manifest-only" || len(point.Report.Runs) != 0 || point.Report.Summary != nil {
			t.Fatalf("dry-run executed point %s: %+v", point.Name, point.Report)
		}
		switch point.Report.Manifest.ExperimentClass {
		case "functional-smoke":
			seenFunctional++
		case "finite-population-secure":
			seenSecure++
		default:
			t.Fatalf("unknown experiment class for %s", point.Name)
		}
	}
	if seenFunctional != 3 || seenSecure != 10 {
		t.Fatalf("unexpected matrix partition functional=%d secure=%d", seenFunctional, seenSecure)
	}
}

func TestValidateCVV2ReferenceMatrixRejectsDuplicateAndUnknownMode(t *testing.T) {
	point := cvV2ReferencePoint{Name: "p", SIDPrefix: "sid", ExecutionMode: "manifest-only"}
	matrix := cvV2ReferenceMatrix{Schema: cvV2ReferenceMatrixSchema, Name: "m", Points: []cvV2ReferencePoint{point, point}}
	if err := validateCVV2ReferenceMatrix(matrix); err == nil {
		t.Fatal("accepted duplicate matrix points")
	}
	matrix.Points = matrix.Points[:1]
	matrix.Points[0].ExecutionMode = "remote-cluster"
	if err := validateCVV2ReferenceMatrix(matrix); err == nil {
		t.Fatal("accepted deployment-oriented matrix execution mode")
	}
}
