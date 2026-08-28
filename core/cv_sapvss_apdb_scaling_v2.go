package core

import (
	"bytes"
	"fmt"
	"time"
)

type CVV2APDBScalingPoint struct {
	PayloadBytes           int   `json:"payload_bytes"`
	ShardBytes             int   `json:"shard_bytes"`
	DispersalProtocolBytes int   `json:"dispersal_protocol_bytes"`
	DispersalFixedBytes    int   `json:"dispersal_fixed_bytes"`
	RecoveryProtocolBytes  int   `json:"recovery_protocol_bytes"`
	RecoveryFixedBytes     int   `json:"recovery_fixed_bytes"`
	EncodeNanoseconds      int64 `json:"encode_nanoseconds"`
	RecoveryNanoseconds    int64 `json:"recovery_nanoseconds"`
}

type CVV2APDBScalingReport struct {
	TotalShards int                    `json:"total_shards"`
	DataShards  int                    `json:"data_shards"`
	Points      []CVV2APDBScalingPoint `json:"points"`
}

func cvMeasureAPDBScalingV2(
	signer *tblsThresholdSigner, oldRoster, payloadSizes []int,
) (CVV2APDBScalingReport, error) {
	if !cvV2SignerHasRole(signer, cvV2RoleAPDB) || !equalInts(oldRoster, signer.memberOrder) ||
		len(oldRoster) == 0 || len(payloadSizes) == 0 {
		return CVV2APDBScalingReport{}, fmt.Errorf("invalid CV V2 APDB scaling input")
	}
	dataShards := len(oldRoster) - 2*(len(oldRoster)-signer.Threshold())
	if dataShards <= 0 || dataShards > len(oldRoster) {
		return CVV2APDBScalingReport{}, fmt.Errorf("invalid CV V2 APDB scaling recovery threshold")
	}
	report := CVV2APDBScalingReport{TotalShards: len(oldRoster), DataShards: dataShards}
	for _, payloadBytes := range payloadSizes {
		if payloadBytes <= 0 || payloadBytes > cvMaxLeafWireBytes {
			return CVV2APDBScalingReport{}, fmt.Errorf("invalid CV V2 APDB scaling payload size %d", payloadBytes)
		}
		payload := make([]byte, payloadBytes)
		for i := range payload {
			payload[i] = byte((i*131 + payloadBytes) & 0xff)
		}
		instance, err := cvAPDBInstanceDigestV2("SCALING", []byte(fmt.Sprintf("payload=%d", payloadBytes)))
		if err != nil {
			return CVV2APDBScalingReport{}, err
		}
		encodeStarted := time.Now()
		encoded, err := cvAPDBEncodeV2(instance, payload, dataShards, len(oldRoster), cvMaxLeafWireBytes)
		encodeElapsed := time.Since(encodeStarted)
		if err != nil {
			return CVV2APDBScalingReport{}, err
		}
		if encoded.shardBytes != (8+payloadBytes+dataShards-1)/dataShards {
			return CVV2APDBScalingReport{}, fmt.Errorf("CV V2 APDB scaling shard formula mismatch")
		}
		lock, err := cvReferenceAPDBLockV2(encoded, oldRoster, signer)
		if err != nil {
			return CVV2APDBScalingReport{}, err
		}
		lockWire, err := cvAPDBLockV2CanonicalBytes(lock)
		if err != nil {
			return CVV2APDBScalingReport{}, err
		}
		statement, err := cvAPDBStoredStatementV2(instance, encoded.root)
		if err != nil {
			return CVV2APDBScalingReport{}, err
		}
		dispersalBytes := 0
		recoveryBytes := len(oldRoster) * len(lockWire)
		stores := make([]cvAPDBStoreV2, dataShards)
		for index, member := range oldRoster {
			storeWire, encodeErr := cvAPDBStoreV2CanonicalBytes(
				&encoded.stores[index], len(oldRoster), encoded.shardBytes,
			)
			if encodeErr != nil {
				return CVV2APDBScalingReport{}, encodeErr
			}
			share, signErr := signer.SignShare(member, cvAPDBStoredDomain, statement)
			if signErr != nil {
				return CVV2APDBScalingReport{}, signErr
			}
			storedWire, encodeErr := cvAPDBStoredShareV2CanonicalBytes(&cvAPDBStoredShareV2{
				InstanceDigest: instance, Root: encoded.root, Share: share,
			})
			if encodeErr != nil {
				return CVV2APDBScalingReport{}, encodeErr
			}
			dispersalBytes += len(storeWire) + len(storedWire)
			recoveryBytes += len(storeWire)
			if index < dataShards {
				stores[index] = encoded.stores[index]
			}
		}
		recoveryStarted := time.Now()
		recovered, err := cvRecoverAPDBV2(
			lock, stores, dataShards, len(oldRoster), encoded.shardBytes, cvMaxLeafWireBytes, nil,
		)
		recoveryElapsed := time.Since(recoveryStarted)
		if err != nil {
			return CVV2APDBScalingReport{}, fmt.Errorf("CV V2 APDB scaling recovery: %w", err)
		}
		if !bytes.Equal(recovered, payload) {
			return CVV2APDBScalingReport{}, fmt.Errorf("CV V2 APDB scaling recovery payload mismatch")
		}
		report.Points = append(report.Points, CVV2APDBScalingPoint{
			PayloadBytes: payloadBytes, ShardBytes: encoded.shardBytes,
			DispersalProtocolBytes: dispersalBytes,
			DispersalFixedBytes:    dispersalBytes - len(oldRoster)*encoded.shardBytes,
			RecoveryProtocolBytes:  recoveryBytes,
			RecoveryFixedBytes:     recoveryBytes - len(oldRoster)*encoded.shardBytes,
			EncodeNanoseconds:      encodeElapsed.Nanoseconds(), RecoveryNanoseconds: recoveryElapsed.Nanoseconds(),
		})
	}
	return report, nil
}
