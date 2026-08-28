package core

import (
	"context"
	"time"
)

type Config struct {
	SID string
	ID  int
	N   int
	F   int

	MaxRounds int

	WaitSPBCTimeout  time.Duration
	RouteSendTimeout time.Duration

	// UseEquivalentPath enables the MVBA flow that mirrors the original
	// dumbomvba core phases (PD -> quit -> coin/ABA -> RC).
	UseEquivalentPath bool

	// EquivalentCoinMode controls coin derivation in equivalent path.
	// Supported values: "signature" (default), "deterministic".
	EquivalentCoinMode string

	// ValidatePayload is the application validity predicate for MVBA values.
	// When set, both the local input and the decided payload must satisfy it.
	ValidatePayload func([]byte) bool
}

type ProtocolTag string

const (
	TagSPBC            ProtocolTag = "SPBC"
	TagMVBACoin        ProtocolTag = "MVBA_COIN"
	TagMVBAPD          ProtocolTag = "MVBA_PD"
	TagMVBAPDFinish    ProtocolTag = "MVBA_PD_FINISH"
	TagMVBARCPrepare   ProtocolTag = "MVBA_RC_PREPARE"
	TagMVBARC          ProtocolTag = "MVBA_RC"
	TagMVBARCPull      ProtocolTag = "MVBA_RC_PULL"
	TagMVBAABA         ProtocolTag = "MVBA_ABA"
	TagMVBAABACoin     ProtocolTag = "MVBA_ABA_COIN"
	TagMVBAABADecision ProtocolTag = "MVBA_ABA_DECISION"
	TagACSDiffuse      ProtocolTag = "ACS_DIFFUSE"
	TagACSMVBA         ProtocolTag = "ACS_MVBA"
)

type SigShare struct {
	Signer int
	Sig    []byte
}

type ProposalValue struct {
	Payload []byte
	Round   int
	Hint    string
	Proof   []SigShare
}

type ProtocolMessage struct {
	Tag    ProtocolTag
	Round  int
	Leader int
	Body   interface{}
}

type ReceivedMessage struct {
	From int
	Msg  ProtocolMessage
}

type RoutedSPBCMessage struct {
	From int
	Body interface{}
}

type SPBCS1Result struct {
	Leader  int
	Value   ProposalValue
	S1Proof []SigShare
	OK      bool
}

type SPBCFinalResult struct {
	Leader     int
	Value      ProposalValue
	FinalProof []SigShare
	OK         bool
}

type SPBCHandle struct {
	Inbound  chan RoutedSPBCMessage
	S1Out    chan SPBCS1Result
	FinalOut chan SPBCFinalResult
	Close    func()
}

type Network interface {
	Broadcast(msg ProtocolMessage) error
	Send(to int, msg ProtocolMessage) error
}

type Signer interface {
	ID() int
	Sign(domain string, digest []byte) ([]byte, error)
	Verify(from int, domain string, digest, sig []byte) bool
}

type ThresholdSigner interface {
	Signer
	Threshold(domain string) int
	Recover(domain string, digest []byte, shares map[int][]byte) ([]byte, error)
	VerifyRecovered(domain string, digest, sig []byte) bool
}

type SPBCDriver interface {
	Start(
		ctx context.Context,
		sid string,
		id, n, f, round, leader int,
		input *ProposalValue,
	) (*SPBCHandle, error)
}

type Logger interface {
	Printf(format string, args ...interface{})
}
