// types.go — 配置、数据结构（基于 adkr-go 扩展，适配 Practical ADKR）
package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"time"
)

// Config holds the configuration for a Practical ADKR instance.
type Config struct {
	SID          string
	Epoch        uint64 // reconfiguration epoch, bound into Coin.Get
	OldCommittee []int  // 旧委员会节点 ID 列表
	NewCommittee []int  // 新委员会节点 ID 列表
	F            int    // 容错上限 (n >= 3f+1)

	// Kappa is the number of transcripts to select in the Recast phase.
	// It must not exceed 2F+1. If 0, the core derives the smallest value for
	// the default 10-year, 128-bit lifetime profile (525600 epochs) from the
	// committee size and F; benchmark callers can resolve a different profile.
	Kappa int

	// PaillierBits controls key size for Verifiable Encryption.
	PaillierBits int

	// MVBA configuration
	MVBARounds       int
	WaitSPBCTimeout  time.Duration
	RouteSendTimeout time.Duration
	// MVBANetwork selects MVBA transport mode. Supported: "tcp".
	MVBANetwork string
	// MVBANodeAddrs maps node ids to addresses: "0=host:port,1=host:port,...".
	MVBANodeAddrs string
	// MVBALocalNodeIDs selects which node listeners to bind on this process: "0,1,...".
	MVBALocalNodeIDs string
	// DisableAgreementFallback makes MVBA failure fatal instead of using the
	// local quorum fallback. Benchmarks set this to keep agreement metrics strict.
	DisableAgreementFallback bool

	// ProtocolNodeAddrs maps ids (old+new committees) to addresses for DXT/APDB stage messaging.
	ProtocolNodeAddrs string
	// ProtocolLocalNodeIDs selects locally hosted ids (old+new) for DXT/APDB stage listeners.
	ProtocolLocalNodeIDs string
	// PartialVerifyNodeAddrs maps new-committee verifier ids to the dedicated
	// partial-result multicast listeners. If empty, addresses are derived from
	// ProtocolNodeAddrs in a separate port namespace.
	PartialVerifyNodeAddrs string
	// DXTNodeAddrs optionally gives setup-long DXT lane/transcript listener
	// addresses. If empty, ports are derived from ProtocolNodeAddrs.
	DXTNodeAddrs string
	// CoinNodeAddrs optionally gives dedicated, setup-long threshold Coin.Get
	// listener addresses. If empty, ports are derived from ProtocolNodeAddrs.
	CoinNodeAddrs string
	// CompNodeAddrs optionally gives dedicated, long-lived Algorithm 3 KEY
	// listener addresses. If empty, ports are derived from ProtocolNodeAddrs.
	CompNodeAddrs string

	// UsePythonBridge enables Python cryptography bridge (fallback).
	UsePythonBridge bool
	BridgePythonBin string
	BridgeScript    string
	AblationMode    string
	CommMetrics     bool

	// StrictNetwork makes benchmark runs fail if protocol phases fall back to
	// process-local shortcuts instead of the configured network transport.
	StrictNetwork bool
}

// --- DXT+ Interactive PVSS Types ---

// SharePair holds the two-component share (s_i, ŝ_i) sent to each recipient.
type SharePair struct {
	S  *big.Int // f(i) — main share
	SR *big.Int // r(i) — randomness share
}

// DealerMsg is the private message from dealer to a single recipient (Phase 1 of DXT+).
type DealerMsg struct {
	Dealer    int
	Recipient int
	Share     SharePair
	// Commitment to the share: g^{s_i} * h^{ŝ_i} (elliptic curve point, compressed)
	Commitment []byte
}

// ShareAck is the signed acknowledgment from a recipient back to the dealer.
type ShareAck struct {
	Recipient int
	Signature []byte // ed25519 signature over (dealer, recipient, commitment)
}

// DXTTranscript is the final assembled PVSS transcript in DXT+ style.
// Built after collecting 2f+1 acks; unresponsive recipients get VE-encrypted shares.
type DXTTranscript struct {
	Dealer int

	// Commitments for ALL recipients: recipient_id -> compressed EC point
	Commitments map[int][]byte

	// Ciphertexts only for non-responsive recipients: recipient_id -> Paillier ciphertext
	Ciphertexts map[int][]byte
	// BlindingCiphertexts encrypt h^{r_i} under the receiver's independent
	// CompProve ElGamal key for every VE lane.
	BlindingCiphertexts map[int]DXTBlindingCiphertext

	// Proofs for non-responsive recipients: recipient_id -> EncryptedDLogProof
	Proofs map[int][]byte

	// Collected signatures from responsive recipients: recipient_id -> ed25519 sig
	Signatures map[int][]byte
}

// --- APDB Types (Async Provable Dispersal) ---

// APDBChunk is one piece of an erasure-coded transcript sent to a single node.
type APDBChunk struct {
	Sender   int
	ChunkIdx int
	Data     []byte
	// Merkle proof for this chunk against the root hash
	MerkleProof [][]byte
	MerkleRoot  []byte
}

// APDBReceipt is the signed receipt from a node confirming chunk reception.
type APDBReceipt struct {
	NodeID    int
	Sender    int
	ChunkHash []byte
	Signature []byte
	// ThresholdShare is an optional BLS receipt share used to form the
	// compact APDB certificate. The Ed25519 Signature remains for legacy
	// receipt validation and local compatibility paths.
	ThresholdShare []byte `json:",omitempty"`
}

// APDBCertificate proves a transcript was successfully dispersed (n-f receipts).
type APDBCertificate struct {
	Sender      int
	Root        []byte
	ValueDigest []byte
	MerkleRoot  []byte
	DataShards  int
	TotalShards int
	Receipts    []APDBReceipt
	// Compact threshold proof. When present, Receipts may be omitted from the
	// wire; the root/digest/RS metadata remains the same. ThresholdPublic is a
	// legacy compatibility field; new wires use the trusted setup registry.
	ThresholdSignature []byte `json:",omitempty"`
	ThresholdPublic    []byte `json:",omitempty"`
}

// APDBDispersalResult summarizes the dispersal outcome needed by later recover.
type APDBDispersalResult struct {
	LocalValid   map[int][]int
	Certificates map[int]APDBCertificate
}

type RecoverShard struct {
	Dealer      int      `json:"dealer"`
	Index       int      `json:"index"`
	Root        []byte   `json:"root"`
	ValueDigest []byte   `json:"value_digest"`
	MerkleRoot  []byte   `json:"merkle_root"`
	DataShards  int      `json:"data_shards"`
	TotalShards int      `json:"total_shards"`
	Data        []byte   `json:"data"`
	Proof       [][]byte `json:"proof"`
}

type RecoverAttestation struct {
	Dealer    int    `json:"dealer"`
	Holder    int    `json:"holder"`
	Recipient int    `json:"recipient"`
	Index     int    `json:"index"`
	Root      []byte `json:"root"`
	ShardHash []byte `json:"shard_hash"`
	Signature []byte `json:"signature"`
}

type RecoverStoreAttestation struct {
	Dealer    int    `json:"dealer"`
	Holder    int    `json:"holder"`
	Root      []byte `json:"root"`
	CertRoot  []byte `json:"cert_root"`
	Signature []byte `json:"signature"`
}

type RecoverTimingBreakdown struct {
	ReadyWait      time.Duration
	CompletionWait time.Duration
	StoreVerify    time.Duration
	ShardVerify    time.Duration
	FullVerify     time.Duration
	StoreSeen      uint64
	FetchReqSent   uint64
	FetchRespRecv  uint64
	RecipientSeen  uint64
}

// --- Distributed Verification Types ---

// VerifyVote is a 1-bit vote on whether a particular transcript chunk is valid.
type VerifyVote struct {
	NodeID       int
	TranscriptID int
	ItemIndex    int
	Valid        bool
	Signature    []byte
}

// --- Key Derivation Types ---

// NIZKProof is a Non-Interactive Zero-Knowledge proof for dLog or DH tuple.
type NIZKProof struct {
	Challenge []byte
	Response  []byte
}

type DXTBlindingCiphertext struct {
	C0 []byte `json:"c0"`
	C1 []byte `json:"c1"`
}

type CompProof struct {
	AckBlinding []byte    `json:"ack_blinding"`
	Y           []byte    `json:"y"`
	Secret      NIZKProof `json:"secret"`
	AckOpening  NIZKProof `json:"ack_opening"`
	DH          NIZKProof `json:"dh"`
}

type CompPublicKeyShare struct {
	NodeID  int       `json:"node_id"`
	PKShare []byte    `json:"pk_share"`
	Proof   CompProof `json:"proof"`
}

// PublicKeyShare is a node's contribution to the new threshold public key.
type PublicKeyShare struct {
	NodeID  int
	PKShare []byte // compressed EC point
	Proof   NIZKProof
}

// --- Result ---

// NodeOutput records per-node metrics.
type NodeOutput struct {
	NodeID     int
	DecidedSet []int
	Latency    time.Duration
	Completed  bool
	FinalPhase string
	Error      string
}

// Result holds the complete output of a Practical ADKR execution.
type Result struct {
	DecidedSet           []int
	SelectedTranscripts  []int // κ selected transcript IDs after Coin
	RecoveredTranscripts map[int]*DXTTranscript
	AgreementMode        string
	AgreementFallback    bool
	AblationMode         string
	SelectedCount        int
	VerifiedCount        int

	// NewShares: new committee node_id -> decrypted share bytes
	NewShares map[int][]byte

	// Aggregate commitments/ciphertexts indexed by new-committee node id.
	AggregateCommitments map[int][]byte
	AggregateCiphertexts map[int][]byte

	// New threshold public key (compressed EC point)
	NewThresholdPK                []byte
	NewPublicShares               map[int][]byte
	CompKeyCompletionCertificates map[int]CompKeyCompletionCertificate
	CoinSignature                 []byte
	CoinThreshold                 int

	PerNode                    []NodeOutput
	PhaseTimings               map[string]time.Duration
	TotalSentBytes             uint64
	TotalRecvBytes             uint64
	PhaseSentBytes             map[string]uint64
	PhaseRecvBytes             map[string]uint64
	PartialVerifyMode          string
	PartialVerifyPositiveVotes map[string]int
}

// CompKeyCompletionCertificate is a receiver-signed completion attestation
// created only after that receiver verifies n-f Algorithm 3 public-key shares.
// It does not let third parties skip verification of the underlying shares.
type CompKeyCompletionCertificate struct {
	Recipient      int
	Threshold      int
	SelectedDigest []byte
	GroupPublicKey []byte
	ShareDigests   map[int][]byte
	Signature      []byte
}

type PartialResultError struct {
	Err    error
	Result *Result
}

func (e *PartialResultError) Error() string {
	if e == nil || e.Err == nil {
		return "partial practical-adkr failure"
	}
	return e.Err.Error()
}

func (e *PartialResultError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// --- Shared crypto helpers ---

func commitScalar(curve elliptic.Curve, s *big.Int) []byte {
	k := new(big.Int).Mod(s, curve.Params().N).Bytes()
	x, y := curve.ScalarBaseMult(k)
	return elliptic.MarshalCompressed(curve, x, y)
}

func addCommit(a, b []byte) []byte {
	if len(a) == 0 {
		cp := make([]byte, len(b))
		copy(cp, b)
		return cp
	}
	curve := elliptic.P256()
	ax, ay := elliptic.UnmarshalCompressed(curve, a)
	bx, by := elliptic.UnmarshalCompressed(curve, b)
	if ax == nil || bx == nil {
		return nil
	}
	x, y := curve.Add(ax, ay, bx, by)
	return elliptic.MarshalCompressed(curve, x, y)
}

func equalCommit(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func hashDealerMsg(dealer, recipient int, commitment []byte) []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(dealer))
	binary.BigEndian.PutUint64(buf[8:], uint64(recipient))
	h := sha256.New()
	h.Write([]byte("PADKR-DXT-SHARE-ACK"))
	h.Write(buf[:])
	h.Write(commitment)
	return h.Sum(nil)
}

func signAck(sk *ecdsa.PrivateKey, dealer, recipient int, commitment []byte) []byte {
	msg := hashDealerMsg(dealer, recipient, commitment)
	sig, err := ecdsa.SignASN1(rand.Reader, sk, msg)
	if err != nil {
		return nil
	}
	return sig
}

func verifyAck(pk *ecdsa.PublicKey, dealer, recipient int, commitment []byte, sig []byte) bool {
	msg := hashDealerMsg(dealer, recipient, commitment)
	return ecdsa.VerifyASN1(pk, msg, sig)
}

func evalPoly(coeff []*big.Int, x *big.Int, mod *big.Int) *big.Int {
	out := new(big.Int)
	pow := big.NewInt(1)
	for _, a := range coeff {
		term := new(big.Int).Mul(a, pow)
		out.Add(out, term)
		out.Mod(out, mod)
		pow.Mul(pow, x)
		pow.Mod(pow, mod)
	}
	return out
}
