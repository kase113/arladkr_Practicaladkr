package core

import "testing"

func TestCVAPDBScalingV2HasExactLinearWireEnvelope(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	sizes := []int{1, 2, 257, 1024, 4097, 16384}
	report, err := cvMeasureAPDBScalingV2(public.APDBSigner, public.OldCommittee, sizes)
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalShards != len(public.OldCommittee) ||
		report.DataShards != public.Params.recoveryThreshold || len(report.Points) != len(sizes) {
		t.Fatalf("unexpected APDB scaling report: %+v", report)
	}
	dispersalFixed := report.Points[0].DispersalFixedBytes
	recoveryFixed := report.Points[0].RecoveryFixedBytes
	for index, point := range report.Points {
		wantShardBytes := (8 + point.PayloadBytes + report.DataShards - 1) / report.DataShards
		if point.PayloadBytes != sizes[index] || point.ShardBytes != wantShardBytes {
			t.Fatalf("point %d payload/shard=%d/%d want %d/%d", index,
				point.PayloadBytes, point.ShardBytes, sizes[index], wantShardBytes)
		}
		if point.DispersalFixedBytes != dispersalFixed || point.RecoveryFixedBytes != recoveryFixed {
			t.Fatalf("point %d fixed overhead changed: dispersal=%d/%d recovery=%d/%d", index,
				point.DispersalFixedBytes, dispersalFixed, point.RecoveryFixedBytes, recoveryFixed)
		}
		if point.DispersalProtocolBytes != dispersalFixed+report.TotalShards*point.ShardBytes ||
			point.RecoveryProtocolBytes != recoveryFixed+report.TotalShards*point.ShardBytes {
			t.Fatalf("point %d violates exact affine wire formula: %+v", index, point)
		}
		if point.EncodeNanoseconds <= 0 || point.RecoveryNanoseconds <= 0 {
			t.Fatalf("point %d missing timing: %+v", index, point)
		}
		if index > 0 && (point.DispersalProtocolBytes < report.Points[index-1].DispersalProtocolBytes ||
			point.RecoveryProtocolBytes < report.Points[index-1].RecoveryProtocolBytes) {
			t.Fatalf("APDB wire cost decreased at point %d", index)
		}
	}
}

func TestCVAPDBScalingV2RejectsInvalidSizes(t *testing.T) {
	_, public := cvAgreementObjectV2Fixture(t)
	for _, sizes := range [][]int{nil, {0}, {cvMaxLeafWireBytes + 1}} {
		if _, err := cvMeasureAPDBScalingV2(public.APDBSigner, public.OldCommittee, sizes); err == nil {
			t.Fatalf("accepted invalid APDB scaling sizes %v", sizes)
		}
	}
}
