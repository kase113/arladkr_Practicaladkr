package core

import (
	"bytes"
	"fmt"
)

const cvComponentReadyCertificateDomain = "ARL-CV-sAPVSS/component-ready-certificate"

type cvComponentReadyReference struct {
	dealer         int
	leafDigest     []byte
	descriptorWire []byte
	descriptor     *cvComponentDescriptor
}

type cvComponentReadyCertificate struct {
	proposer   int
	references []cvComponentReadyReference
	root       []byte
}

func cvComponentReadyRoot(references []cvComponentReadyReference) ([]byte, error) {
	if len(references) == 0 {
		return nil, fmt.Errorf("empty CV-sAPVSS ReadyCert")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentReadyCertificateDomain+"/root"))
	last := -1
	for _, reference := range references {
		if reference.dealer <= last || len(reference.leafDigest) != 32 || len(reference.descriptorWire) == 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert reference")
		}
		last = reference.dealer
		cvWriteUint64(&wire, uint64(reference.dealer))
		_ = cvWriteBytes(&wire, reference.leafDigest)
		_ = cvWriteBytes(&wire, hashBytes([]byte(cvComponentReadyCertificateDomain+"/descriptor"), reference.descriptorWire))
	}
	return hashBytes([]byte(cvComponentReadyCertificateDomain+"/root"), wire.Bytes()), nil
}

func cvComponentReadyCertificateCanonicalBytes(certificate *cvComponentReadyCertificate) ([]byte, error) {
	if certificate == nil || certificate.proposer < 0 || len(certificate.root) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert")
	}
	root, err := cvComponentReadyRoot(certificate.references)
	if err != nil || !bytes.Equal(root, certificate.root) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert root")
	}
	return cvEncodeComponentReadyCertificate(certificate)
}

// cvEncodeComponentReadyCertificate serializes a certificate whose root was
// just computed or independently verified by the caller.
func cvEncodeComponentReadyCertificate(certificate *cvComponentReadyCertificate) ([]byte, error) {
	if certificate == nil || certificate.proposer < 0 || len(certificate.root) != 32 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvComponentReadyCertificateDomain))
	cvWriteUint64(&wire, uint64(certificate.proposer))
	if err := cvWriteUint32(&wire, len(certificate.references)); err != nil {
		return nil, err
	}
	for _, reference := range certificate.references {
		_ = cvWriteBytes(&wire, reference.descriptorWire)
	}
	_ = cvWriteBytes(&wire, certificate.root)
	return wire.Bytes(), nil
}

func cvDecodeComponentReadyCertificate(wire []byte, cfg Config) (*cvComponentReadyCertificate, error) {
	c := NormalizeConfig(cfg)
	if err := ValidateConfig(c); err != nil {
		return nil, err
	}
	if err := ensureRuntime(&c); err != nil {
		return nil, err
	}
	ready := len(c.OldCommittee) - c.FOld
	if ready <= 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert threshold")
	}
	oldMembers := nodeSet(c.OldCommittee)
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvComponentReadyCertificateDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvComponentReadyCertificateDomain)) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert domain")
	}
	proposer, err := r.uint64()
	if err != nil || proposer > uint64(^uint(0)>>1) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert proposer")
	}
	if _, ok := oldMembers[int(proposer)]; !ok {
		return nil, fmt.Errorf("CV-sAPVSS ReadyCert proposer outside old roster")
	}
	count, err := r.uint32()
	if err != nil || count != ready {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert size")
	}
	references := make([]cvComponentReadyReference, count)
	for i := range references {
		references[i].descriptorWire, err = r.bytes(cvMaxComponentSignatureBytes + 1<<12)
		if err != nil || len(references[i].descriptorWire) == 0 {
			return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert descriptor")
		}
		references[i].descriptor, err = cvDecodeAndValidateComponentDescriptorPrepared(
			&c, references[i].descriptorWire, oldMembers,
		)
		if err != nil {
			return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert component certificate: %w", err)
		}
		references[i].dealer = references[i].descriptor.dealer
		references[i].leafDigest = append([]byte(nil), references[i].descriptor.leafDigest...)
		if i > 0 && references[i].dealer <= references[i-1].dealer {
			return nil, fmt.Errorf("non-canonical CV-sAPVSS ReadyCert dealer order")
		}
	}
	root, err := r.bytes(32)
	if err != nil || len(root) != 32 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert framing")
	}
	certificate := &cvComponentReadyCertificate{proposer: int(proposer), references: references, root: root}
	canonical, err := cvComponentReadyCertificateCanonicalBytes(certificate)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV-sAPVSS ReadyCert")
	}
	return certificate, nil
}

func cvBuildComponentReadyCertificate(proposer int, descriptors []*cvComponentDescriptor) (*cvComponentReadyCertificate, error) {
	return cvBuildComponentReadyCertificateFromValidatedWires(proposer, descriptors, nil)
}

// cvBuildComponentReadyCertificateFromValidatedWires reuses immutable wires
// already accepted into the component service. A missing wire falls back to
// canonical encoding for fixtures and older in-memory state.
func cvBuildComponentReadyCertificateFromValidatedWires(
	proposer int, descriptors []*cvComponentDescriptor, descriptorWires [][]byte,
) (*cvComponentReadyCertificate, error) {
	if descriptorWires != nil && len(descriptorWires) != len(descriptors) {
		return nil, fmt.Errorf("invalid CV-sAPVSS ReadyCert descriptor wire cache")
	}
	references := make([]cvComponentReadyReference, len(descriptors))
	for i, descriptor := range descriptors {
		if descriptor == nil {
			return nil, fmt.Errorf("nil CV-sAPVSS ReadyCert descriptor")
		}
		var descriptorWire []byte
		if descriptorWires != nil {
			descriptorWire = descriptorWires[i]
		}
		if len(descriptorWire) == 0 {
			var err error
			descriptorWire, err = cvComponentDescriptorCanonicalBytes(descriptor)
			if err != nil {
				return nil, err
			}
		}
		references[i] = cvComponentReadyReference{
			dealer: descriptor.dealer, leafDigest: append([]byte(nil), descriptor.leafDigest...),
			descriptorWire: descriptorWire, descriptor: descriptor,
		}
	}
	root, err := cvComponentReadyRoot(references)
	if err != nil {
		return nil, err
	}
	return &cvComponentReadyCertificate{proposer: proposer, references: references, root: root}, nil
}

func cvBuildComponentReadyCertificateWireFromValidatedWires(
	proposer int, descriptors []*cvComponentDescriptor, descriptorWires [][]byte,
) (*cvComponentReadyCertificate, []byte, error) {
	certificate, err := cvBuildComponentReadyCertificateFromValidatedWires(proposer, descriptors, descriptorWires)
	if err != nil {
		return nil, nil, err
	}
	wire, err := cvEncodeComponentReadyCertificate(certificate)
	if err != nil {
		return nil, nil, err
	}
	return certificate, wire, nil
}
