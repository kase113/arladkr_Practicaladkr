package core

import (
	"bytes"
	"fmt"
)

const cvDecisionShareWireV2Domain = "ARL-CV-sAPVSS/v2-scalar-group/decision-share-wire"

type cvDecisionShareV2 struct {
	Statement []byte
	Signature []byte
}

func cvDecisionShareV2CanonicalBytes(share *cvDecisionShareV2) ([]byte, error) {
	if share == nil || len(share.Statement) != 32 || len(share.Signature) == 0 ||
		len(share.Signature) > cvMaxComponentSignatureBytes {
		return nil, fmt.Errorf("invalid CV V2 decision share")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvDecisionShareWireV2Domain))
	_ = cvWriteBytes(&wire, share.Statement)
	_ = cvWriteBytes(&wire, share.Signature)
	return wire.Bytes(), nil
}

func cvDecodeDecisionShareV2(wire []byte) (*cvDecisionShareV2, error) {
	r := newCVWireReader(wire)
	domain, err := r.bytes(len(cvDecisionShareWireV2Domain))
	if err != nil || !bytes.Equal(domain, []byte(cvDecisionShareWireV2Domain)) {
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
	share := &cvDecisionShareV2{Statement: statement, Signature: signature}
	canonical, err := cvDecisionShareV2CanonicalBytes(share)
	if err != nil || !bytes.Equal(canonical, wire) {
		return nil, fmt.Errorf("non-canonical CV V2 decision share")
	}
	return share, nil
}
