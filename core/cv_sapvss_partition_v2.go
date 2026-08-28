package core

import (
	"bytes"
	"fmt"
)

const cvEvidencePartitionWireDomainV2 = "ARL-CV-sAPVSS/v2-scalar-group/evidence-partition"

type cvEvidencePartitionV2 struct {
	ACKReceiverIndices      []int
	FallbackReceiverIndices []int
}

func cvValidateEvidencePartitionV2(context *cvLeafContextV2, partition *cvEvidencePartitionV2) error {
	newFaults := cvNewFaultBoundFromContextV2(context)
	if err := cvValidateLeafContextV2(context); err != nil || partition == nil ||
		newFaults < 0 || len(partition.FallbackReceiverIndices) > newFaults {
		return fmt.Errorf("invalid CV V2 evidence partition")
	}
	total := len(context.NewRoster)
	if len(partition.ACKReceiverIndices)+len(partition.FallbackReceiverIndices) != total {
		return fmt.Errorf("CV V2 evidence partition does not cover receiver roster")
	}
	seen := make([]bool, total+1)
	for _, indices := range [][]int{partition.ACKReceiverIndices, partition.FallbackReceiverIndices} {
		previous := 0
		for _, index := range indices {
			if index <= previous || index > total || seen[index] {
				return fmt.Errorf("invalid CV V2 evidence receiver index")
			}
			seen[index] = true
			previous = index
		}
	}
	for index := 1; index <= total; index++ {
		if !seen[index] {
			return fmt.Errorf("CV V2 evidence partition omits receiver %d", index)
		}
	}
	return nil
}

func cvEvidencePartitionV2CanonicalBytes(
	context *cvLeafContextV2, partition *cvEvidencePartitionV2,
) ([]byte, error) {
	if err := cvValidateEvidencePartitionV2(context, partition); err != nil {
		return nil, err
	}
	contextDigest, err := cvLeafContextDigestV2(context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvEvidencePartitionWireDomainV2))
	_ = cvWriteBytes(&wire, contextDigest)
	if err := cvWriteIndexVectorV2(&wire, partition.ACKReceiverIndices); err != nil {
		return nil, err
	}
	if err := cvWriteIndexVectorV2(&wire, partition.FallbackReceiverIndices); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeEvidencePartitionV2(
	wire []byte, context *cvLeafContextV2,
) (*cvEvidencePartitionV2, error) {
	if err := cvValidateLeafContextV2(context); err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvEvidencePartitionWireDomainV2))
	if err != nil || !bytes.Equal(domain, []byte(cvEvidencePartitionWireDomainV2)) {
		return nil, fmt.Errorf("invalid CV V2 evidence partition domain")
	}
	contextDigest, err := r.bytes(32)
	expectedDigest, digestErr := cvLeafContextDigestV2(context)
	if err != nil || digestErr != nil || !bytes.Equal(contextDigest, expectedDigest) {
		return nil, fmt.Errorf("invalid CV V2 evidence partition context")
	}
	acks, err := cvReadIndexVectorV2(r, len(context.NewRoster))
	if err != nil {
		return nil, err
	}
	fallbacks, err := cvReadIndexVectorV2(r, cvNewFaultBoundFromContextV2(context))
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 evidence partition framing")
	}
	partition := &cvEvidencePartitionV2{
		ACKReceiverIndices: acks, FallbackReceiverIndices: fallbacks,
	}
	canonical, err := cvEvidencePartitionV2CanonicalBytes(context, partition)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 evidence partition")
	}
	return partition, nil
}

func cvNewFaultBoundFromContextV2(context *cvLeafContextV2) int {
	if context == nil {
		return -1
	}
	// The V2 sharing polynomial has t_n=n_n-f_n-1. Therefore f_n is
	// determined by the roster size and the context's canonical degree.
	return len(context.NewRoster) - context.SharingDegree - 1
}

func cvWriteIndexVectorV2(wire *bytes.Buffer, indices []int) error {
	if err := cvWriteUint32(wire, len(indices)); err != nil {
		return err
	}
	for _, index := range indices {
		if err := cvWriteUint32(wire, index); err != nil {
			return err
		}
	}
	return nil
}

func cvReadIndexVectorV2(r *cvWireReader, maximum int) ([]int, error) {
	count, err := r.uint32()
	if err != nil || count < 0 || count > maximum {
		return nil, fmt.Errorf("invalid CV V2 evidence index count")
	}
	indices := make([]int, count)
	for i := range indices {
		indices[i], err = r.uint32()
		if err != nil {
			return nil, fmt.Errorf("invalid CV V2 evidence index")
		}
	}
	return indices, nil
}
