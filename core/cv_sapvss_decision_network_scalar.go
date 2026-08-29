package core

import (
	"bytes"
	"fmt"
)

const cvDecisionShareWireScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/decision-share-wire"

type cvDecisionShareScalar struct {
	Statement []byte
	Signature []byte
}

func cvDecisionShareScalarCanonicalBytes(share *cvDecisionShareScalar) ([]byte, error) {
	if share == nil || len(share.Statement) != 32 || len(share.Signature) == 0 ||
		len(share.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 decision share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvDecisionShareWireScalarDomain))
	_ = cvWriteBytes(&wire, share.Statement)
	_ = cvWriteBytes(&wire, share.Signature)
	return wire.Bytes(), nil
}

func cvDecodeDecisionShareScalar(wire []byte) (*cvDecisionShareScalar, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvDecisionShareWireScalarDomain))
	if err != nil || !bytes.Equal(domain, []byte(cvDecisionShareWireScalarDomain)) {
		return nil, fmt.Errorf("invalid CV V2 decision share domain")
	}
	statement, err := r.bytes(32)
	if err != nil || len(statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 decision share statement")
	}
	signature, err := r.bytes(cvMaxComponentSignatureBytes)
	if err != nil || len(signature) == 0 || r.reader.Len() != 0 {
		return nil, fmt.Errorf("invalid CV V2 decision share signature")
	}
	share := &cvDecisionShareScalar{Statement: statement, Signature: signature}
	canonical, err := cvDecisionShareScalarCanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 decision share")
	}
	return share, nil
}
