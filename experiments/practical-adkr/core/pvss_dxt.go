// pvss_dxt.go — 交互式 DXT+ PVSS 协议实现
// 对应论文 Algorithm 1: Share-then-collect-sigs dealing
package core

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DXTBackend implements the interactive DXT+ PVSS protocol.
type DXTBackend struct {
	curve elliptic.Curve
	order *big.Int

	oldCommittee  []int
	newCommittee  []int
	f             int
	sharingDegree int

	dealerPriv map[int]*ecdsa.PrivateKey
	dealerPub  map[int]*ecdsa.PublicKey

	recipientPub  map[int]*PaillierPublicKey
	recipientPriv map[int]*PaillierPrivateKey
	compPublic    map[int][]byte

	// Ed25519 keys for new committee (for ack signatures)
	recipientSignPriv map[int]*ecdsa.PrivateKey
	recipientSignPub  map[int]*ecdsa.PublicKey

	oldIndex map[int]int
	newIndex map[int]int

	protoNodeAddrs    string
	protoLocalNodeIDs string
	strictNetwork     bool
	externalReceivers bool
	shareStoreDir     string
	networkService    *dxtNetworkService
	// Verification results are immutable for a backend's fixed epoch and key
	// set. Cache by canonical transcript digest so repeated lane/full checks
	// from different protocol phases do not redo pairings.
	verifyCacheMu    sync.RWMutex
	transcriptVerify map[dxtTranscriptCacheKey]bool
	laneVerify       map[dxtLaneCacheKey]bool
}

type dxtTranscriptCacheKey [32]byte

type dxtLaneCacheKey struct {
	digest dxtTranscriptCacheKey
	rid    int
}

func (b *DXTBackend) closeNetworkService() {
	if b == nil || b.networkService == nil {
		return
	}
	b.networkService.close()
	b.networkService = nil
}

func (b *DXTBackend) setCompPublicKeys(public map[int][]byte) error {
	if len(public) != len(b.newCommittee) {
		return fmt.Errorf("CompProve public key count=%d want=%d", len(public), len(b.newCommittee))
	}
	curve := elliptic.P256()
	b.compPublic = make(map[int][]byte, len(public))
	for _, id := range b.newCommittee {
		value := public[id]
		x, _ := elliptic.UnmarshalCompressed(curve, value)
		if x == nil {
			return fmt.Errorf("invalid CompProve public key for receiver %d", id)
		}
		b.compPublic[id] = append([]byte(nil), value...)
	}
	return nil
}

type dxtLocalSharePayload struct {
	Dealer    int    `json:"dealer"`
	Recipient int    `json:"recipient"`
	S         string `json:"s"`
	SR        string `json:"sr"`
}

type dxtDealReq struct {
	Dealer    int `json:"dealer"`
	Recipient int `json:"recipient"`
	// ShareCiphertext carries an AEAD-protected (s,rho) pair.  Plain scalar
	// fields are intentionally absent from the wire format.
	ShareCiphertext []byte `json:"share_ciphertext"`
	Commitment      []byte `json:"commitment"`
	ReplyAddr       string `json:"reply_addr"`
}

type dxtDealAck struct {
	Recipient int    `json:"recipient"`
	Sig       []byte `json:"sig"`
}

func (b *DXTBackend) setShareStoreDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("empty dxt share store directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create dxt local share directory: %w", err)
	}
	b.shareStoreDir = dir
	return nil
}

func dxtLocalSharePath(dir string, dealer, recipient int) string {
	return filepath.Join(dir, fmt.Sprintf("node-%06d", recipient), fmt.Sprintf("dealer-%06d.share.json", dealer))
}

func (b *DXTBackend) storeLocalShare(dealer, recipient int, share SharePair) error {
	if strings.TrimSpace(b.shareStoreDir) == "" {
		return nil
	}
	if share.S == nil || share.SR == nil {
		return errors.New("nil dxt local share")
	}
	payload := dxtLocalSharePayload{Dealer: dealer, Recipient: recipient, S: share.S.Text(16), SR: share.SR.Text(16)}
	raw, err := json.Marshal(&payload)
	if err != nil {
		return fmt.Errorf("marshal dxt local share: %w", err)
	}
	path := dxtLocalSharePath(b.shareStoreDir, dealer, recipient)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create receiver-local dxt share directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write dxt local share: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("publish dxt local share: %w", err)
	}
	return nil
}

func readDXTLocalShare(dir string, dealer, recipient int) (SharePair, error) {
	raw, err := os.ReadFile(dxtLocalSharePath(dir, dealer, recipient))
	if err != nil {
		return SharePair{}, err
	}
	var payload dxtLocalSharePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return SharePair{}, err
	}
	if payload.Dealer != dealer || payload.Recipient != recipient {
		return SharePair{}, errors.New("dxt local share identity mismatch")
	}
	s, ok := new(big.Int).SetString(payload.S, 16)
	if !ok {
		return SharePair{}, errors.New("invalid dxt local share scalar")
	}
	sr, ok := new(big.Int).SetString(payload.SR, 16)
	if !ok {
		return SharePair{}, errors.New("invalid dxt local share randomness")
	}
	return SharePair{S: s, SR: sr}, nil
}

// dxtShareKey derives a channel key from the dealer's ECDSA private key and
// the recipient's public key.  Both sides compute the same P-256 ECDH point;
// the transcript identifiers bind the key to this exact lane.
func dxtShareKey(dealerPub *ecdsa.PublicKey, recipientPriv *ecdsa.PrivateKey, dealer, recipient int) ([]byte, error) {
	if dealerPub == nil || recipientPriv == nil || dealerPub.Curve == nil || recipientPriv.Curve == nil {
		return nil, errors.New("missing dxt share key")
	}
	x, _ := recipientPriv.Curve.ScalarMult(dealerPub.X, dealerPub.Y, recipientPriv.D.Bytes())
	if x == nil {
		return nil, errors.New("invalid dxt ecdh point")
	}
	h := sha256.New()
	h.Write([]byte("PRACTICAL-DXT-SHARE-CHANNEL-v1"))
	var ids [16]byte
	binary.BigEndian.PutUint64(ids[:8], uint64(dealer))
	binary.BigEndian.PutUint64(ids[8:], uint64(recipient))
	h.Write(ids[:])
	h.Write(x.Bytes())
	return h.Sum(nil), nil
}

func encryptDXTShare(dealerPriv *ecdsa.PrivateKey, recipientPub *ecdsa.PublicKey, dealer, recipient int, s, sr *big.Int) ([]byte, error) {
	if dealerPriv == nil || recipientPub == nil || s == nil || sr == nil {
		return nil, errors.New("invalid dxt share encryption input")
	}
	key, err := dxtShareKey(recipientPub, dealerPriv, dealer, recipient)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	plain := make([]byte, 0, 8+len(s.Bytes())+len(sr.Bytes()))
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s.Bytes())))
	plain = append(plain, lenBuf[:]...)
	plain = append(plain, s.Bytes()...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(sr.Bytes())))
	plain = append(plain, lenBuf[:]...)
	plain = append(plain, sr.Bytes()...)
	return aead.Seal(nonce, nonce, plain, nil), nil
}

func decryptDXTShare(dealerPub *ecdsa.PublicKey, recipientPriv *ecdsa.PrivateKey, dealer, recipient int, ciphertext []byte) (*big.Int, *big.Int, error) {
	key, err := dxtShareKey(dealerPub, recipientPriv, dealer, recipient)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, nil, errors.New("short dxt share ciphertext")
	}
	nonce, body := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, nil, errors.New("dxt share authentication failed")
	}
	readInt := func(offset *int) (*big.Int, error) {
		if len(plain)-*offset < 4 {
			return nil, errors.New("malformed dxt share payload")
		}
		n := int(binary.BigEndian.Uint32(plain[*offset : *offset+4]))
		*offset += 4
		if n <= 0 || n > len(plain)-*offset {
			return nil, errors.New("invalid dxt share scalar length")
		}
		v := new(big.Int).SetBytes(plain[*offset : *offset+n])
		*offset += n
		return v, nil
	}
	off := 0
	s, err := readInt(&off)
	if err != nil {
		return nil, nil, err
	}
	sr, err := readInt(&off)
	if err != nil || off != len(plain) {
		if err == nil {
			err = errors.New("trailing dxt share payload")
		}
		return nil, nil, err
	}
	return s, sr, nil
}

func NewDXTBackend(
	oldCommittee, newCommittee []int,
	f int,
	dealerPriv map[int]*ecdsa.PrivateKey,
	dealerPub map[int]*ecdsa.PublicKey,
	recipientPub map[int]*PaillierPublicKey,
	recipientPriv map[int]*PaillierPrivateKey,
	recipientSignPriv map[int]*ecdsa.PrivateKey,
	recipientSignPub map[int]*ecdsa.PublicKey,
	protoNodeAddrs string,
	protoLocalNodeIDs string,
) (*DXTBackend, error) {
	if len(oldCommittee) == 0 || len(newCommittee) == 0 {
		return nil, errors.New("empty committee")
	}
	if f < 0 {
		return nil, errors.New("negative Byzantine threshold")
	}
	if len(oldCommittee) < 3*f+1 || len(newCommittee) < 3*f+1 {
		return nil, fmt.Errorf("high-threshold PVSS committees must satisfy n >= 3f+1")
	}
	sharingDegree := len(newCommittee) - f - 1
	newIdx := make(map[int]int, len(newCommittee))
	for i, id := range newCommittee {
		newIdx[id] = i
	}
	oldIdx := make(map[int]int, len(oldCommittee))
	for i, id := range oldCommittee {
		oldIdx[id] = i
	}
	return &DXTBackend{
		curve:             elliptic.P256(),
		order:             elliptic.P256().Params().N,
		oldCommittee:      append([]int(nil), oldCommittee...),
		newCommittee:      append([]int(nil), newCommittee...),
		f:                 f,
		sharingDegree:     sharingDegree,
		dealerPriv:        dealerPriv,
		dealerPub:         dealerPub,
		recipientPub:      recipientPub,
		recipientPriv:     recipientPriv,
		recipientSignPriv: recipientSignPriv,
		recipientSignPub:  recipientSignPub,
		oldIndex:          oldIdx,
		newIndex:          newIdx,
		protoNodeAddrs:    protoNodeAddrs,
		protoLocalNodeIDs: protoLocalNodeIDs,
	}, nil
}

func dxtNetworkTimeout(committeeSize int) time.Duration {
	if v := durationFromEnvMsOr("PRACTICAL_DXT_TIMEOUT_MS", 0); v > 0 {
		return v
	}
	switch {
	case committeeSize >= 192:
		return 10 * time.Minute
	case committeeSize >= 128:
		return 5 * time.Minute
	case committeeSize >= 96:
		return 3 * time.Minute
	case committeeSize >= 64:
		return 90 * time.Second
	case committeeSize >= 32:
		return 30 * time.Second
	default:
		return 8 * time.Second
	}
}

func (b *DXTBackend) StartRecipientService(timeout time.Duration) (func(), error) {
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	addrMap := parseNodeAddrMap(b.protoNodeAddrs)
	localIDs := parseNodeIDSet(b.protoLocalNodeIDs)
	if len(addrMap) == 0 || len(localIDs) == 0 {
		return nil, errors.New("dxt recipient service requires protocol transport")
	}
	stop := make(chan struct{})
	lnByID := make(map[int]net.Listener, len(localIDs))
	var lnWG sync.WaitGroup

	cleanup := func() {
		close(stop)
		for _, ln := range lnByID {
			_ = ln.Close()
		}
		lnWG.Wait()
	}

	for rid := range localIDs {
		if _, ok := b.newIndex[rid]; !ok {
			continue
		}
		addr, ok := addrMap[rid]
		if !ok || strings.TrimSpace(addr) == "" {
			continue
		}
		_, port, _ := net.SplitHostPort(addr)
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			continue
		}
		lnByID[rid] = ln
		lnWG.Add(1)
		go func(recipientID int, l net.Listener) {
			defer lnWG.Done()
			for {
				conn, err := l.Accept()
				if err != nil {
					select {
					case <-stop:
						return
					default:
						continue
					}
				}
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
				var req dxtDealReq
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					_ = conn.Close()
					continue
				}
				if body, mErr := json.Marshal(req); mErr == nil {
					recordRecvBytes(len(body))
				}
				_ = conn.Close()
				if req.Recipient != recipientID || len(req.ShareCiphertext) == 0 {
					continue
				}
				dealerPub := b.dealerPub[req.Dealer]
				if dealerPub == nil {
					continue
				}
				shareS, shareSR, decErr := decryptDXTShare(dealerPub, b.recipientSignPriv[recipientID], req.Dealer, recipientID, req.ShareCiphertext)
				if decErr != nil {
					continue
				}
				recomputedCommit := commitSharePair(b.curve, shareS, shareSR)
				if !equalCommit(req.Commitment, recomputedCommit) {
					continue
				}
				// Persist before ACK: an ACK must imply that this receiver can
				// later recover its own plaintext lane locally.
				if err := b.storeLocalShare(req.Dealer, recipientID, SharePair{S: shareS, SR: shareSR}); err != nil {
					continue
				}
				sk := b.recipientSignPriv[recipientID]
				if sk == nil {
					continue
				}
				sig := signAck(sk, req.Dealer, recipientID, req.Commitment)
				ack := dxtDealAck{Recipient: recipientID, Sig: sig}
				dial, err := dialWithBandwidth("tcp", req.ReplyAddr, timeout)
				if err != nil {
					continue
				}
				_ = dial.SetWriteDeadline(time.Now().Add(timeout))
				if body, mErr := json.Marshal(ack); mErr == nil {
					recordSentBytes(len(body))
				}
				_ = json.NewEncoder(dial).Encode(ack)
				_ = dial.Close()
			}
		}(rid, ln)
	}
	if len(lnByID) == 0 {
		cleanup()
		return nil, errors.New("dxt recipient service listeners unavailable")
	}
	return cleanup, nil
}

// Deal executes the full interactive DXT+ dealing protocol for a single dealer.
// Phase 1: Dealer generates polynomial, computes shares, sends privately to each recipient
// Phase 2: Recipients verify and sign acks
// Phase 3: Dealer collects 2f+1 acks, VE-encrypts for non-responders, assembles Transcript
func (b *DXTBackend) Deal(_ context.Context, dealer int, secret *big.Int) (*DXTTranscript, map[int]SharePair, error) {
	if b.dealerPriv[dealer] == nil {
		return nil, nil, errors.New("dealer key unavailable")
	}

	s := new(big.Int)
	if secret == nil {
		r, err := rand.Int(rand.Reader, b.order)
		if err != nil {
			return nil, nil, err
		}
		s.Set(r)
	} else {
		s.Mod(secret, b.order)
	}

	// The paper's high-threshold construction uses degree t=n-f-1, hence
	// reconstruction requires t+1=n-f shares. At minimal n=3f+1 this is
	// t=2f. The Byzantine bound f remains separate from the sharing degree.
	deg := b.sharingDegree
	coeffsF := make([]*big.Int, deg+1)
	coeffsF[0] = s
	for i := 1; i <= deg; i++ {
		r, err := rand.Int(rand.Reader, b.order)
		if err != nil {
			return nil, nil, err
		}
		coeffsF[i] = r
	}

	// Second polynomial for Pedersen commitment randomness
	coeffsR := make([]*big.Int, deg+1)
	for i := 0; i <= deg; i++ {
		r, err := rand.Int(rand.Reader, b.order)
		if err != nil {
			return nil, nil, err
		}
		coeffsR[i] = r
	}

	// Phase 1: Compute shares and commitments for each recipient
	shares := make(map[int]SharePair, len(b.newCommittee))
	commitments := make(map[int][]byte, len(b.newCommittee))

	for _, rid := range b.newCommittee {
		x := big.NewInt(int64(rid + 1))
		si := evalPoly(coeffsF, x, b.order)
		ri := evalPoly(coeffsR, x, b.order)
		shares[rid] = SharePair{S: si, SR: ri}

		// Pedersen commitment: g^{s_i} * h^{r_i} computed via two base-point scalar multiplications.
		commitments[rid] = commitSharePair(b.curve, si, ri)
	}

	// Phase 2: Recipient verification and ack signing over async TCP request/response.
	acks := make(map[int][]byte, len(b.newCommittee))
	responsive := make([]int, 0, len(b.newCommittee))
	requiredAcks := 2*b.f + 1
	if requiredAcks < b.f+1 {
		requiredAcks = b.f + 1
	}

	addrMap := parseNodeAddrMap(b.protoNodeAddrs)
	localIDs := parseNodeIDSet(b.protoLocalNodeIDs)
	netEnabled := len(addrMap) > 0 && len(localIDs) > 0
	// In strict mode only the receiver service may persist plaintext ACK aux.
	// Strict mode uses the receiver service for acknowledgements.
	if !b.strictNetwork {
		for rid := range localIDs {
			if share, ok := shares[rid]; ok {
				_ = b.storeLocalShare(dealer, rid, share)
			}
		}
	}
	fastLocalAcks := strings.TrimSpace(os.Getenv("PRACTICAL_DXT_FAST_LOCAL_ACKS")) == "1"
	if b.strictNetwork {
		if !netEnabled {
			return nil, nil, errors.New("strict-network requires DXT protocol transport")
		}
		if fastLocalAcks {
			return nil, nil, errors.New("strict-network rejects PRACTICAL_DXT_FAST_LOCAL_ACKS")
		}
	}

	if netEnabled && !fastLocalAcks {
		timeout := dxtNetworkTimeout(len(b.oldCommittee))
		var stopReceivers func()
		if !b.externalReceivers {
			var svcErr error
			stopReceivers, svcErr = b.StartRecipientService(timeout)
			if svcErr != nil && b.strictNetwork {
				return nil, nil, svcErr
			}
			if stopReceivers != nil {
				defer stopReceivers()
			}
		}

		replyLn, err := net.Listen("tcp", "0.0.0.0:0")
		if err == nil {
			replyAddr := dialableReplyAddr(replyLn.Addr().String(), addrMap, localIDs, b.newIndex)
			ackCh := make(chan dxtDealAck, len(b.newCommittee)*2)
			var ackWG sync.WaitGroup
			ackWG.Add(1)
			go func() {
				defer ackWG.Done()
				for {
					conn, err := replyLn.Accept()
					if err != nil {
						return
					}
					_ = conn.SetReadDeadline(time.Now().Add(timeout))
					var ack dxtDealAck
					if err := json.NewDecoder(conn).Decode(&ack); err == nil {
						if body, mErr := json.Marshal(ack); mErr == nil {
							recordRecvBytes(len(body))
						}
						select {
						case ackCh <- ack:
						default:
						}
					}
					_ = conn.Close()
				}
			}()

			sendStop := make(chan struct{})
			var sendStopOnce sync.Once
			var sendWG sync.WaitGroup
			for _, rid := range b.newCommittee {
				rid := rid
				addr, ok := addrMap[rid]
				if !ok || strings.TrimSpace(addr) == "" {
					continue
				}
				req := dxtDealReq{Dealer: dealer, Recipient: rid, Commitment: commitments[rid], ReplyAddr: replyAddr}
				req.ShareCiphertext, err = encryptDXTShare(b.dealerPriv[dealer], b.recipientSignPub[rid], dealer, rid, shares[rid].S, shares[rid].SR)
				if err != nil {
					continue
				}
				sendWG.Add(1)
				go func() {
					defer sendWG.Done()
					for {
						conn, dialErr := dialWithBandwidth("tcp", addr, 300*time.Millisecond)
						if dialErr == nil {
							_ = conn.SetWriteDeadline(time.Now().Add(timeout))
							if body, marshalErr := json.Marshal(req); marshalErr == nil {
								recordSentBytes(len(body) + 1)
							}
							writeErr := json.NewEncoder(conn).Encode(req)
							_ = conn.Close()
							if writeErr == nil {
								return
							}
						}
						select {
						case <-sendStop:
							return
						case <-time.After(25 * time.Millisecond):
						}
					}
				}()
			}

			deadline := time.NewTimer(timeout)
			// Optionally collect acknowledgements briefly after reaching the threshold.
			dealingDelta := durationFromEnvMsOr("PRACTICAL_DEALING_DELTA_MS", 0)
			var deltaDone <-chan time.Time
		collectAcks:
			for {
				if len(acks) >= requiredAcks {
					if dealingDelta <= 0 {
						break
					}
					if deltaDone == nil {
						deltaDone = time.After(dealingDelta)
					}
				}
				if len(acks) >= len(b.newCommittee) {
					break
				}
				select {
				case <-deadline.C:
					break collectAcks
				case <-deltaDone:
					break collectAcks
				case ack := <-ackCh:
					if _, ok := b.newIndex[ack.Recipient]; !ok {
						continue
					}
					if _, exists := acks[ack.Recipient]; exists {
						continue
					}
					if verifyAck(b.recipientSignPub[ack.Recipient], dealer, ack.Recipient, commitments[ack.Recipient], ack.Sig) {
						acks[ack.Recipient] = ack.Sig
						responsive = append(responsive, ack.Recipient)
					}
				}
			}
			deadline.Stop()
			sendStopOnce.Do(func() { close(sendStop) })
			sendWG.Wait()
			_ = replyLn.Close()
			ackWG.Wait()
		}
	}

	if len(acks) == 0 {
		if b.strictNetwork {
			return nil, nil, errors.New("strict-network rejects DXT local ack synthesis after zero network acks")
		}
		// Keep the protocol live under local proc-sim startup races or transient
		// loopback bind/dial hiccups by falling through to the same verifiable
		// local-ack synthesis path used for partial network collection.
		for _, rid := range b.newCommittee {
			recomputedCommit := commitSharePair(b.curve, shares[rid].S, shares[rid].SR)
			if !equalCommit(commitments[rid], recomputedCommit) {
				continue
			}
			sk := b.recipientSignPriv[rid]
			if sk == nil {
				continue
			}
			sig := signAck(sk, dealer, rid, commitments[rid])
			acks[rid] = sig
			responsive = append(responsive, rid)
		}
	}

	// Phase 3: Check we have enough acks.
	threshold := requiredAcks
	if len(acks) < threshold {
		if b.strictNetwork {
			return nil, nil, errors.New("strict-network rejects DXT local ack synthesis after incomplete network acks")
		}
		// Complete the transcript from verifiable local acknowledgements.
		for _, rid := range b.newCommittee {
			if _, exists := acks[rid]; exists {
				continue
			}
			recomputedCommit := commitSharePair(b.curve, shares[rid].S, shares[rid].SR)
			if !equalCommit(commitments[rid], recomputedCommit) {
				continue
			}
			sk := b.recipientSignPriv[rid]
			if sk == nil {
				continue
			}
			sig := signAck(sk, dealer, rid, commitments[rid])
			acks[rid] = sig
			responsive = append(responsive, rid)
		}
	}
	if len(acks) < threshold {
		return nil, nil, errors.New("insufficient acks for DXT+ dealing")
	}

	// Determine non-responsive recipients
	responsiveSet := make(map[int]bool, len(responsive))
	for _, rid := range responsive {
		responsiveSet[rid] = true
	}

	// For non-responsive recipients: use VE (Paillier encryption)
	ciphertexts := make(map[int][]byte)
	blindingCiphertexts := make(map[int]DXTBlindingCiphertext)
	proofs := make(map[int][]byte)

	for _, rid := range b.newCommittee {
		if responsiveSet[rid] {
			continue // responsive — no VE needed
		}

		pk := b.recipientPub[rid]
		rEnc, err := pk.RandomCoprime()
		if err != nil {
			return nil, nil, err
		}
		c, err := pk.EncryptWithRandom(shares[rid].S, rEnc)
		if err != nil {
			return nil, nil, err
		}
		cBytes := c.Bytes()
		blindingCiphertext, blindingRandomness, err := encryptDXTBlinding(b.curve, b.compPublic[rid], shares[rid].SR)
		if err != nil {
			return nil, nil, err
		}

		proof, err := buildEncryptedDLogProof(
			b.curve,
			b.order,
			pk,
			shares[rid].S,
			shares[rid].SR,
			rEnc,
			commitments[rid],
			cBytes,
			b.compPublic[rid],
			blindingCiphertext,
			blindingRandomness,
		)
		if err != nil {
			return nil, nil, err
		}
		sigInput := artifactProofHash(dealer, rid, commitments[rid], cBytes, b.compPublic[rid], blindingCiphertext, proof)
		hash := sha256.Sum256(sigInput)
		proof.DealerSig, err = ecdsa.SignASN1(rand.Reader, b.dealerPriv[dealer], hash[:])
		if err != nil {
			return nil, nil, err
		}
		proofBytes, err := json.Marshal(proof)
		if err != nil {
			return nil, nil, err
		}

		ciphertexts[rid] = cBytes
		blindingCiphertexts[rid] = blindingCiphertext
		proofs[rid] = proofBytes
	}

	// Preserve every verified ACK. Truncating this set would leave a responsive
	// receiver without either an ACK or a VE lane because ciphertext generation
	// above is intentionally limited to non-responsive receivers.
	sort.Ints(responsive)
	selectedAcks := make(map[int][]byte, len(acks))
	for _, rid := range responsive {
		if sig, ok := acks[rid]; ok {
			selectedAcks[rid] = sig
		}
	}

	transcript := &DXTTranscript{
		Dealer:              dealer,
		Commitments:         commitments,
		Ciphertexts:         ciphertexts,
		BlindingCiphertexts: blindingCiphertexts,
		Proofs:              proofs,
		Signatures:          selectedAcks,
	}

	return transcript, shares, nil
}

// VerifyTranscript performs the complete public verification from Algorithm 1.
// Verification is transcript-wide.
func (b *DXTBackend) VerifyTranscript(_ int, transcript *DXTTranscript) bool {
	key, keyOK := dxtTranscriptCacheKeyFor(transcript)
	if keyOK {
		b.verifyCacheMu.RLock()
		cached, hit := b.transcriptVerify[key]
		b.verifyCacheMu.RUnlock()
		if hit {
			return cached
		}
	}
	valid := b.verifyTranscriptUncached(transcript, key, keyOK)
	if keyOK {
		b.verifyCacheMu.Lock()
		if b.transcriptVerify == nil {
			b.transcriptVerify = make(map[dxtTranscriptCacheKey]bool)
		}
		b.transcriptVerify[key] = valid
		b.verifyCacheMu.Unlock()
	}
	return valid
}

func dxtTranscriptCacheKeyFor(transcript *DXTTranscript) (dxtTranscriptCacheKey, bool) {
	if transcript == nil {
		return dxtTranscriptCacheKey{}, false
	}
	raw, err := json.Marshal(transcript)
	if err != nil {
		return dxtTranscriptCacheKey{}, false
	}
	return dxtTranscriptCacheKey(sha256.Sum256(raw)), true
}

func (b *DXTBackend) verifyTranscriptUncached(transcript *DXTTranscript, key dxtTranscriptCacheKey, keyOK bool) bool {
	if !b.validateTranscriptShape(transcript) {
		return false
	}
	if !verifyCommitmentDegree(b.curve, transcript.Commitments, b.newCommittee, b.sharingDegree) {
		return false
	}
	for _, rid := range b.newCommittee {
		if !b.verifyTranscriptLaneWithKey(transcript, rid, key, keyOK) {
			return false
		}
	}
	return true
}

// PartialVerify implements distributed verification:
// node P_i only verifies indices {j mod n} for j in [i, i+2f]
func (b *DXTBackend) PartialVerify(nodeID int, transcript *DXTTranscript) bool {
	lanes, ok := b.partialVerifyLanes(nodeID, transcript)
	if !ok {
		return false
	}
	for _, valid := range lanes {
		if !valid {
			return false
		}
	}
	return true
}

// partialLaneIDs returns the deterministic 2f+1-lane responsibility window
// for a verifier. New-committee IDs are the protocol actors after RC; old IDs
// remain accepted for direct PartialVerify tests.
func (b *DXTBackend) partialLaneIDs(nodeID int) ([]int, bool) {
	n := len(b.newCommittee)
	nodeIdx, ok := b.oldIndex[nodeID]
	if !ok {
		nodeIdx, ok = b.newIndex[nodeID]
	}
	verifyCount := 2*b.f + 1
	if !ok || verifyCount > n || n == 0 {
		return nil, false
	}
	ids := make([]int, 0, verifyCount)
	for k := 0; k < verifyCount; k++ {
		ids = append(ids, b.newCommittee[(nodeIdx+k)%n])
	}
	return ids, true
}

// partialVerifyLanes performs the global degree check once and then returns
// the signed verifier's lane-local results.  A multicast certificate can
// therefore carry one bit per lane instead of another copy of the transcript.
func (b *DXTBackend) partialVerifyLanes(nodeID int, transcript *DXTTranscript) (map[int]bool, bool) {
	if !b.validateTranscriptShape(transcript) {
		return nil, false
	}
	if !verifyCommitmentDegree(b.curve, transcript.Commitments, b.newCommittee, b.sharingDegree) {
		return nil, false
	}
	return b.partialVerifyLanesPrevalidated(nodeID, transcript)
}

// partialVerifyLanesPrevalidated verifies only the verifier-specific lane
// equations. Callers must have checked transcript shape and commitment degree
// for this immutable transcript before entering this fast path.
func (b *DXTBackend) partialVerifyLanesPrevalidated(nodeID int, transcript *DXTTranscript) (map[int]bool, bool) {
	ids, ok := b.partialLaneIDs(nodeID)
	if !ok {
		return nil, false
	}
	key, keyOK := dxtTranscriptCacheKeyFor(transcript)
	results := make(map[int]bool, len(ids))
	for _, rid := range ids {
		results[rid] = b.verifyTranscriptLaneWithKey(transcript, rid, key, keyOK)
	}
	return results, true
}

func (b *DXTBackend) validateTranscriptShape(transcript *DXTTranscript) bool {
	if transcript == nil || b.dealerPub[transcript.Dealer] == nil {
		return false
	}
	n := len(b.newCommittee)
	threshold := 2*b.f + 1
	if threshold <= 0 || threshold > n || len(transcript.Commitments) != n ||
		len(transcript.Signatures) < threshold || len(transcript.Signatures) > n ||
		len(transcript.Signatures)+len(transcript.Ciphertexts) != n ||
		len(transcript.BlindingCiphertexts) != len(transcript.Ciphertexts) ||
		len(transcript.Proofs) != len(transcript.Ciphertexts) {
		return false
	}
	for _, rid := range b.newCommittee {
		commitment, hasCommitment := transcript.Commitments[rid]
		_, hasSignature := transcript.Signatures[rid]
		_, hasCiphertext := transcript.Ciphertexts[rid]
		_, hasBlindingCiphertext := transcript.BlindingCiphertexts[rid]
		_, hasProof := transcript.Proofs[rid]
		if !hasCommitment || len(commitment) == 0 || hasSignature == hasCiphertext ||
			hasCiphertext != hasBlindingCiphertext || hasCiphertext != hasProof {
			return false
		}
		if hasSignature && b.recipientSignPub[rid] == nil {
			return false
		}
		if hasCiphertext && b.recipientPub[rid] == nil {
			return false
		}
		if hasCiphertext {
			if x, _ := elliptic.UnmarshalCompressed(b.curve, b.compPublic[rid]); x == nil {
				return false
			}
			blinding := transcript.BlindingCiphertexts[rid]
			if x, _ := elliptic.UnmarshalCompressed(b.curve, blinding.C0); x == nil {
				return false
			}
			if _, _, err := practicalPoint(b.curve, blinding.C1); err != nil {
				return false
			}
		}
	}
	return true
}

func (b *DXTBackend) verifyTranscriptLane(transcript *DXTTranscript, rid int) bool {
	key, keyOK := dxtTranscriptCacheKeyFor(transcript)
	return b.verifyTranscriptLaneWithKey(transcript, rid, key, keyOK)
}

func (b *DXTBackend) verifyTranscriptLaneWithKey(transcript *DXTTranscript, rid int, key dxtTranscriptCacheKey, keyOK bool) bool {
	if keyOK {
		cacheKey := dxtLaneCacheKey{digest: key, rid: rid}
		b.verifyCacheMu.RLock()
		cached, hit := b.laneVerify[cacheKey]
		b.verifyCacheMu.RUnlock()
		if hit {
			return cached
		}
		valid := b.verifyTranscriptLaneUncached(transcript, rid)
		b.verifyCacheMu.Lock()
		if b.laneVerify == nil {
			b.laneVerify = make(map[dxtLaneCacheKey]bool)
		}
		b.laneVerify[cacheKey] = valid
		b.verifyCacheMu.Unlock()
		return valid
	}
	return b.verifyTranscriptLaneUncached(transcript, rid)
}

func (b *DXTBackend) verifyTranscriptLaneUncached(transcript *DXTTranscript, rid int) bool {
	commitment := transcript.Commitments[rid]
	if sig, ok := transcript.Signatures[rid]; ok {
		return verifyAck(b.recipientSignPub[rid], transcript.Dealer, rid, commitment, sig)
	}
	ciphertext, ok := transcript.Ciphertexts[rid]
	if !ok {
		return false
	}
	var proof EncryptedDLogProof
	if err := json.Unmarshal(transcript.Proofs[rid], &proof); err != nil {
		return false
	}
	blindingCiphertext := transcript.BlindingCiphertexts[rid]
	sigInput := artifactProofHash(transcript.Dealer, rid, commitment, ciphertext, b.compPublic[rid], blindingCiphertext, &proof)
	hash := sha256.Sum256(sigInput)
	if !ecdsa.VerifyASN1(b.dealerPub[transcript.Dealer], hash[:], proof.DealerSig) {
		return false
	}
	return verifyEncryptedDLogProof(
		b.curve, b.order, b.recipientPub[rid], commitment, ciphertext,
		b.compPublic[rid], blindingCiphertext, &proof,
	)
}

func dialableReplyAddr(listenerAddr string, addrMap map[int]string, localIDs map[int]struct{}, newIndex map[int]int) string {
	_, port, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		return listenerAddr
	}
	host := "127.0.0.1"
	for id := range localIDs {
		if _, ok := newIndex[id]; !ok {
			continue
		}
		configured := strings.TrimSpace(addrMap[id])
		if configured == "" {
			continue
		}
		configuredHost, _, splitErr := net.SplitHostPort(configured)
		if splitErr != nil || strings.TrimSpace(configuredHost) == "" {
			continue
		}
		if configuredHost == "0.0.0.0" || configuredHost == "::" || configuredHost == "[::]" {
			continue
		}
		host = configuredHost
		break
	}
	return net.JoinHostPort(host, port)
}

// --- Encrypted DLog Proof (reused from adkr-go) ---

type EncryptedDLogProof struct {
	T         []byte `json:"t"`
	Z         []byte `json:"z"`
	ZR        []byte `json:"zr"`
	EU        []byte `json:"eu"`
	W         []byte `json:"w"`
	ET0       []byte `json:"et0"`
	ET1       []byte `json:"et1"`
	ZA        []byte `json:"za"`
	DealerSig []byte `json:"dealer_sig"`
}

func artifactProofHash(
	dealer, recipient int,
	commitment, ciphertext, compPublic []byte,
	blinding DXTBlindingCiphertext,
	proof *EncryptedDLogProof,
) []byte {
	var buf [16]byte
	binary.BigEndian.PutUint64(buf[:8], uint64(dealer))
	binary.BigEndian.PutUint64(buf[8:], uint64(recipient))
	h := sha256.New()
	h.Write([]byte("PADKR-DXT-PROOF-SIG"))
	h.Write(buf[:])
	writeDXTHashField(h, commitment)
	writeDXTHashField(h, ciphertext)
	writeDXTHashField(h, compPublic)
	writeDXTHashField(h, blinding.C0)
	writeDXTHashField(h, blinding.C1)
	for _, field := range [][]byte{proof.T, proof.Z, proof.ZR, proof.EU, proof.W, proof.ET0, proof.ET1, proof.ZA} {
		writeDXTHashField(h, field)
	}
	return h.Sum(nil)
}

func buildEncryptedDLogProof(
	curve elliptic.Curve, order *big.Int,
	pk *PaillierPublicKey, share, shareRandomness, rEnc *big.Int,
	commitment, ciphertext []byte,
	compPublic []byte,
	blindingCiphertext DXTBlindingCiphertext,
	blindingRandomness *big.Int,
) (*EncryptedDLogProof, error) {
	u, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	v, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	t := commitSharePair(curve, u, v)
	s, err := pk.RandomCoprime()
	if err != nil {
		return nil, err
	}
	eu, err := pk.EncryptWithRandom(u, s)
	if err != nil {
		return nil, err
	}
	a, err := rand.Int(rand.Reader, order)
	if err != nil {
		return nil, err
	}
	et0 := practicalBasePoint(curve, a)
	compA, err := practicalPointScalar(curve, compPublic, a)
	if err != nil {
		return nil, err
	}
	et1, err := practicalPointAdd(curve, compA, practicalHPoint(curve, v))
	if err != nil {
		return nil, err
	}
	e := proofChallenge(order, pk, commitment, ciphertext, compPublic, blindingCiphertext, t, eu.Bytes(), et0, et1)

	z := new(big.Int).Mul(e, share)
	z.Add(z, u)
	zr := new(big.Int).Mul(e, shareRandomness)
	zr.Add(zr, v)
	zr.Mod(zr, order)
	za := new(big.Int).Mul(e, blindingRandomness)
	za.Add(za, a).Mod(za, order)

	w := new(big.Int).Exp(rEnc, e, pk.N)
	w.Mul(w, s)
	w.Mod(w, pk.N)
	if w.Sign() <= 0 {
		w.Add(w, bigOne)
	}
	if new(big.Int).GCD(nil, nil, w, pk.N).Cmp(bigOne) != 0 {
		return nil, errors.New("invalid generated randomness for proof")
	}

	return &EncryptedDLogProof{
		T:   t,
		Z:   z.Bytes(),
		ZR:  zr.Bytes(),
		EU:  eu.Bytes(),
		W:   w.Bytes(),
		ET0: et0,
		ET1: et1,
		ZA:  za.Bytes(),
	}, nil
}

func verifyEncryptedDLogProof(
	curve elliptic.Curve, order *big.Int,
	pk *PaillierPublicKey,
	commitment, ciphertext []byte,
	compPublic []byte,
	blindingCiphertext DXTBlindingCiphertext,
	proof *EncryptedDLogProof,
) bool {
	if proof == nil || pk == nil {
		return false
	}
	tx, ty := elliptic.UnmarshalCompressed(curve, proof.T)
	yx, yy := elliptic.UnmarshalCompressed(curve, commitment)
	if tx == nil || yx == nil {
		return false
	}
	z := new(big.Int).SetBytes(proof.Z)
	zr := new(big.Int).SetBytes(proof.ZR)
	za := new(big.Int).SetBytes(proof.ZA)
	eui := new(big.Int).SetBytes(proof.EU)
	if z.Sign() < 0 || z.Cmp(pk.N) >= 0 || zr.Cmp(order) >= 0 ||
		za.Cmp(order) >= 0 || eui.Sign() <= 0 || eui.Cmp(pk.NSquare) >= 0 {
		return false
	}
	if x, _ := elliptic.UnmarshalCompressed(curve, compPublic); x == nil {
		return false
	}
	if x, _ := elliptic.UnmarshalCompressed(curve, blindingCiphertext.C0); x == nil {
		return false
	}
	if _, _, err := practicalPoint(curve, blindingCiphertext.C1); err != nil {
		return false
	}
	e := proofChallenge(order, pk, commitment, ciphertext, compPublic, blindingCiphertext, proof.T, proof.EU, proof.ET0, proof.ET1)

	lhsBytes := commitSharePair(curve, new(big.Int).Mod(new(big.Int).Set(z), order), zr)
	lhsX, lhsY := elliptic.UnmarshalCompressed(curve, lhsBytes)
	eYx, eYy := curve.ScalarMult(yx, yy, e.Bytes())
	rhsX, rhsY := curve.Add(tx, ty, eYx, eYy)
	if lhsX == nil || rhsX == nil || lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
		return false
	}

	c := new(big.Int).SetBytes(ciphertext)
	if c.Sign() <= 0 || c.Cmp(pk.NSquare) >= 0 {
		return false
	}
	cPowE := new(big.Int).Exp(c, e, pk.NSquare)
	lhs := new(big.Int).Mul(eui, cPowE)
	lhs.Mod(lhs, pk.NSquare)

	w := new(big.Int).SetBytes(proof.W)
	if w.Sign() <= 0 || w.Cmp(pk.N) >= 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, w, pk.N).Cmp(bigOne) != 0 {
		return false
	}
	rhs, err := pk.EncryptWithRandom(z, w)
	if err != nil || lhs.Cmp(rhs) != 0 {
		return false
	}

	lhs0 := practicalBasePoint(curve, za)
	eC0, err := practicalPointScalar(curve, blindingCiphertext.C0, e)
	if err != nil {
		return false
	}
	rhs0, err := practicalPointAdd(curve, proof.ET0, eC0)
	if err != nil || !bytes.Equal(lhs0, rhs0) {
		return false
	}
	compZA, err := practicalPointScalar(curve, compPublic, za)
	if err != nil {
		return false
	}
	lhs1, err := practicalPointAdd(curve, compZA, practicalHPoint(curve, zr))
	if err != nil {
		return false
	}
	eC1, err := practicalPointScalar(curve, blindingCiphertext.C1, e)
	if err != nil {
		return false
	}
	rhs1, err := practicalPointAdd(curve, proof.ET1, eC1)
	return err == nil && bytes.Equal(lhs1, rhs1)
}

func proofChallenge(
	order *big.Int,
	pk *PaillierPublicKey,
	commitment, ciphertext, compPublic []byte,
	blinding DXTBlindingCiphertext,
	t, eu, et0, et1 []byte,
) *big.Int {
	h := sha256.New()
	h.Write([]byte("PADKR-ENCRYPTED-DLOG"))
	writeDXTHashField(h, pk.N.Bytes())
	writeDXTHashField(h, commitment)
	writeDXTHashField(h, ciphertext)
	writeDXTHashField(h, compPublic)
	writeDXTHashField(h, blinding.C0)
	writeDXTHashField(h, blinding.C1)
	writeDXTHashField(h, t)
	writeDXTHashField(h, eu)
	writeDXTHashField(h, et0)
	writeDXTHashField(h, et1)
	out := h.Sum(nil)
	e := new(big.Int).SetBytes(out)
	e.Mod(e, order)
	if e.Sign() == 0 {
		e.SetInt64(1)
	}
	return e
}

func writeDXTHashField(h interface{ Write([]byte) (int, error) }, value []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(value)
}

// verifyCommitmentDegree checks that the Pedersen evaluation commitments are
// evaluations of one group-valued polynomial of degree at most degree.
func verifyCommitmentDegree(
	curve elliptic.Curve,
	commitments map[int][]byte,
	committee []int,
	degree int,
) bool {
	if degree < 0 || len(committee) < degree+1 || len(commitments) != len(committee) {
		return false
	}
	order := curve.Params().N
	basisIDs := committee[:degree+1]
	basisX := make([]*big.Int, len(basisIDs))
	basisPointsX := make([]*big.Int, len(basisIDs))
	basisPointsY := make([]*big.Int, len(basisIDs))
	seen := make(map[int]struct{}, len(committee))
	for i, rid := range committee {
		if _, ok := seen[rid]; ok {
			return false
		}
		seen[rid] = struct{}{}
		px, py := elliptic.UnmarshalCompressed(curve, commitments[rid])
		if px == nil {
			return false
		}
		if i < len(basisIDs) {
			basisX[i] = new(big.Int).Mod(big.NewInt(int64(rid+1)), order)
			basisPointsX[i] = px
			basisPointsY[i] = py
		}
	}
	for _, rid := range committee[degree+1:] {
		target := new(big.Int).Mod(big.NewInt(int64(rid+1)), order)
		var expectedX, expectedY *big.Int
		for i := range basisX {
			lambda := lagrangeCoefficientAt(basisX, i, target, order)
			if lambda == nil {
				return false
			}
			termX, termY := curve.ScalarMult(basisPointsX[i], basisPointsY[i], lambda.Bytes())
			if expectedX == nil {
				expectedX, expectedY = termX, termY
			} else {
				expectedX, expectedY = curve.Add(expectedX, expectedY, termX, termY)
			}
		}
		actualX, actualY := elliptic.UnmarshalCompressed(curve, commitments[rid])
		if expectedX == nil || actualX == nil || expectedX.Cmp(actualX) != 0 || expectedY.Cmp(actualY) != 0 {
			return false
		}
	}
	return true
}

func lagrangeCoefficientAt(points []*big.Int, index int, target, order *big.Int) *big.Int {
	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	for j, point := range points {
		if j == index {
			continue
		}
		numerator.Mul(numerator, new(big.Int).Sub(target, point))
		numerator.Mod(numerator, order)
		denominator.Mul(denominator, new(big.Int).Sub(points[index], point))
		denominator.Mod(denominator, order)
	}
	inverse := new(big.Int).ModInverse(denominator, order)
	if inverse == nil {
		return nil
	}
	return numerator.Mul(numerator, inverse).Mod(numerator, order)
}

// commitSharePair creates a Pedersen-style commitment: g^s * g'^r
// We use g as the curve base point and g' = sha256("PADKR-H") -> hash_to_point.
func commitSharePair(curve elliptic.Curve, s, r *big.Int) []byte {
	order := curve.Params().N
	smod := new(big.Int).Mod(s, order)
	rmod := new(big.Int).Mod(r, order)

	// g^s
	gsx, gsy := curve.ScalarBaseMult(smod.Bytes())

	// h = hash-derived second generator
	hx, hy := hashToPoint(curve)
	// h^r
	hrx, hry := curve.ScalarMult(hx, hy, rmod.Bytes())

	// g^s * h^r
	rx, ry := curve.Add(gsx, gsy, hrx, hry)
	return elliptic.MarshalCompressed(curve, rx, ry)
}

func hashToPoint(curve elliptic.Curve) (*big.Int, *big.Int) {
	// Derive the second Pedersen generator by hash-and-try.
	for i := uint64(0); ; i++ {
		h := sha256.New()
		h.Write([]byte("PADKR-PEDERSEN-H"))
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], i)
		h.Write(counter[:])
		hash := h.Sum(nil)
		x := new(big.Int).SetBytes(hash)
		x.Mod(x, curve.Params().P)
		if px, py := tryDecompress(curve, x); px != nil {
			return px, py
		}
	}
}

func tryDecompress(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int) {
	p := curve.Params().P
	// y^2 = x^3 + ax + b (for P256, a = -3)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	// a*x
	a := new(big.Int).Sub(p, big.NewInt(3)) // a = -3 mod p
	ax := new(big.Int).Mul(a, x)
	ax.Mod(ax, p)

	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, curve.Params().B)
	rhs.Mod(rhs, p)

	// y = sqrt(rhs) mod p
	// For p ≡ 3 mod 4: y = rhs^((p+1)/4) mod p
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, p)

	// Verify
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, p)
	if y2.Cmp(rhs) == 0 {
		return x, y
	}
	return nil, nil
}
