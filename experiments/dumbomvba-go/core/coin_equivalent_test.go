package core

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type failingCoinThresholdSigner struct {
	recoverErr     error
	recoveredValid bool
}

func (s *failingCoinThresholdSigner) ID() int { return 0 }

func (s *failingCoinThresholdSigner) Sign(string, []byte) ([]byte, error) {
	return []byte("share"), nil
}

func (s *failingCoinThresholdSigner) Verify(int, string, []byte, []byte) bool {
	return true
}

func (s *failingCoinThresholdSigner) Threshold(string) int { return 1 }

func (s *failingCoinThresholdSigner) Recover(string, []byte, map[int][]byte) ([]byte, error) {
	if s.recoverErr != nil {
		return nil, s.recoverErr
	}
	return []byte("recovered"), nil
}

func (s *failingCoinThresholdSigner) VerifyRecovered(string, []byte, []byte) bool {
	return s.recoveredValid
}

func TestEquivalentThresholdCoinFailsClosed(t *testing.T) {
	tests := []struct {
		name        string
		signer      *failingCoinThresholdSigner
		wantErrPart string
	}{
		{
			name:        "recovery failure",
			signer:      &failingCoinThresholdSigner{recoverErr: errors.New("forced recovery failure")},
			wantErrPart: "recover equivalent threshold coin",
		},
		{
			name:        "invalid recovered signature",
			signer:      &failingCoinThresholdSigner{recoveredValid: false},
			wantErrPart: "verify recovered equivalent threshold coin",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := &DumboMVBA{
				cfg:    Config{SID: "fail-closed", ID: 0, N: 1, F: 0, EquivalentCoinMode: "signature"},
				net:    &noopNetwork{},
				signer: test.signer,
			}
			coin := m.makeSharedCoin(context.Background(), "coin-sid", TagMVBACoin, 0, make(chan ReceivedMessage))
			if _, err := coin("nonce"); err == nil || !strings.Contains(err.Error(), test.wantErrPart) {
				t.Fatalf("coin error=%v, want substring %q", err, test.wantErrPart)
			}
		})
	}
}
