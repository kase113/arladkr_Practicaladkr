package core

import (
	"bytes"
	"fmt"
)

const cvEvidencePartitionWireDomainScalar = "ARL-CV-sAPVSS/v2-scalar-group/evidence-partition"

type cvEvidencePartitionScalar struct {
	ACKReceiverIndices      []int
	FallbackReceiverIndices []int
}

func cvValidateEvidencePartitionScalar(context *cvLeafContextScalar, partition *cvEvidencePartitionScalar) error {
	newFaults := cvNewFaultBoundFromContextScalar(context)
	if err := cvValidateLeafContextScalar(context); err != nil || partition == nil ||
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

func cvEvidencePartitionScalarCanonicalBytes(
	context *cvLeafContextScalar, partition *cvEvidencePartitionScalar,
) ([]byte, error) {
	if err := cvValidateEvidencePartitionScalar(context, partition); err != nil {
		return nil, err
	}
	contextDigest, err := cvLeafContextDigestScalar(context)
	if err != nil {
		return nil, err
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvEvidencePartitionWireDomainScalar))
	_ = cvWriteBytes(&wire, contextDigest)
	if err := cvWriteIndexVectorScalar(&wire, partition.ACKReceiverIndices); err != nil {
		return nil, err
	}
	if err := cvWriteIndexVectorScalar(&wire, partition.FallbackReceiverIndices); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

func cvDecodeEvidencePartitionScalar(
	wire []byte, context *cvLeafContextScalar,
) (*cvEvidencePartitionScalar, error) {
	if err := cvValidateLeafContextScalar(context); err != nil {
		return nil, err
	}
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvEvidencePartitionWireDomainScalar))
	if err != nil || !bytes.Equal(domain, []byte(cvEvidencePartitionWireDomainScalar)) {
		return nil, fmt.Errorf("invalid CV V2 evidence partition domain")
	}
	contextDigest, err := r.bytes(32)
	expectedDigest, digestErr := cvLeafContextDigestScalar(context)
	if err != nil || digestErr != nil || !bytes.Equal(contextDigest, expectedDigest) {
		return nil, fmt.Errorf("invalid CV V2 evidence partition context")
	}
	acks, err := cvReadIndexVectorScalar(r, len(context.NewRoster))
	if err != nil {
		return nil, err
	}
	fallbacks, err := cvReadIndexVectorScalar(r, cvNewFaultBoundFromContextScalar(context))
	if err != nil || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 evidence partition framing")
	}
	partition := &cvEvidencePartitionScalar{
		ACKReceiverIndices: acks, FallbackReceiverIndices: fallbacks,
	}
	canonical, err := cvEvidencePartitionScalarCanonicalBytes(context, partition)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 evidence partition")
	}
	return partition, nil
}

func cvNewFaultBoundFromContextScalar(context *cvLeafContextScalar) int {
	if context == nil {
		return -1
	}
	// The scalar protocol sharing polynomial has t_n=n_n-f_n-1. Therefore f_n is
	// determined by the roster size and the context's canonical degree.
	return len(context.NewRoster) - context.SharingDegree - 1
}

func cvWriteIndexVectorScalar(wire *bytes.Buffer, indices []int) error {
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

func cvReadIndexVectorScalar(r *cvWireReader, maximum int) ([]int, error) {
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
