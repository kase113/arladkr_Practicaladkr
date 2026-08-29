package core

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

const cvDecisionSignRecordScalarDomain = "ARL-CV-sAPVSS/v2-scalar-group/decision-sign-record"

type cvDecisionSignStoreScalar struct {
	root string
}

func newCVDecisionSignStoreScalar(root string) (*cvDecisionSignStoreScalar, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV V2 decision-sign store root")
	}
	store := &cvDecisionSignStoreScalar{root: filepath.Join(root, "decision-sign-v2-scalar-group")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *cvDecisionSignStoreScalar) SignHandoffOnce(
	sid string, epoch uint64, member int, contextDigest []byte,
	header *cvAggregateHeaderScalar, arc *cvAPDBLockScalar, controlSigner *tblsThresholdSigner,
) ([]byte, error) {
	if s == nil || sid == "" || epoch == 0 || member < 0 || !cvScalarSignerHasRole(controlSigner, cvScalarRoleControl) ||
		!cvThresholdSignerCanSignScalar(controlSigner, member) {
		return nil, fmt.Errorf("invalid CV V2 decision-sign input")
	}
	handoffDigest, err := cvHandoffDigestScalar(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	statement, err := cvDecisionStatementScalar(contextDigest, header, arc)
	if err != nil {
		return nil, err
	}
	record, err := cvDecisionSignRecordScalarCanonicalBytes(sid, epoch, member, handoffDigest, statement)
	if err != nil {
		return nil, err
	}
	path, err := s.path(sid, epoch, member)
	if err != nil {
		return nil, err
	}
	// The immutable write is the one-shot transition. A signature is never
	// released before this record and its parent directory are durable.
	if err := cvPutImmutableFile(path, record); err != nil {
		return nil, fmt.Errorf("persist CV V2 decision-sign record: %w", err)
	}
	signature, err := controlSigner.SignShare(member, cvDecisionCertificateScalarDomain, statement)
	if err != nil {
		return nil, fmt.Errorf("sign persisted CV V2 decision: %w", err)
	}
	if !controlSigner.VerifyShare(member, cvDecisionCertificateScalarDomain, statement, signature) {
		return nil, fmt.Errorf("invalid local CV V2 decision signature share")
	}
	return signature, nil
}

func (s *cvDecisionSignStoreScalar) Read(sid string, epoch uint64, member int) ([]byte, error) {
	path, err := s.path(sid, epoch, member)
	if err != nil {
		return nil, err
	}
	return cvReadImmutableFile(path)
}

func (s *cvDecisionSignStoreScalar) path(sid string, epoch uint64, member int) (string, error) {
	if s == nil || sid == "" || epoch == 0 || epoch > uint64(^uint(0)>>1) || member < 0 {
		return "", fmt.Errorf("invalid CV V2 decision-sign store key")
	}
	sidComponent, _, err := cvStoreKeyParts(sid, int(epoch), member, hashBytes([]byte(cvDecisionSignRecordScalarDomain)))
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, sidComponent, fmt.Sprintf("epoch-%d", epoch), fmt.Sprintf("member-%d.decision", member)), nil
}

func cvDecisionSignRecordScalarCanonicalBytes(sid string, epoch uint64, member int, handoffDigest, statement []byte) ([]byte, error) {
	if sid == "" || epoch == 0 || member < 0 || len(handoffDigest) != 32 || len(statement) != 32 {
		return nil, fmt.Errorf("invalid CV V2 decision-sign record")
	}
	var wire bytes.Buffer
	_ = cvWriteBytes(&wire, []byte(cvDecisionSignRecordScalarDomain))
	_ = cvWriteBytes(&wire, []byte(sid))
	cvWriteUint64(&wire, epoch)
	cvWriteUint64(&wire, uint64(member))
	_ = cvWriteBytes(&wire, handoffDigest)
	_ = cvWriteBytes(&wire, statement)
	return wire.Bytes(), nil
}

func cvThresholdSignerCanSignScalar(signer *tblsThresholdSigner, member int) bool {
	if signer == nil {
		return false
	}
	index, ok := signer.memberIndex[member]
	if !ok || index < 0 || index >= len(signer.shares) || signer.shares[index].IsZero() {
		return false
	}
	if signer.signingMembers != nil {
		_, ok = signer.signingMembers[member]
	}
	return ok
}
