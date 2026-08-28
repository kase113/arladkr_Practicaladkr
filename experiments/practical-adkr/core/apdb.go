package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type apdbReceiptRequest struct {
	Dealer int           `json:"dealer"`
	Root   []byte        `json:"root"`
	Reply  string        `json:"reply"`
	TR     DXTTranscript `json:"tr"`
}

type apdbReceiptResponse struct {
	Dealer  int         `json:"dealer"`
	Receipt APDBReceipt `json:"receipt"`
}

func runAPDBDispersal(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
	networkService *networkAPDBService,
) (*APDBDispersalResult, error) {
	if cfg.StrictNetwork {
		return runNetworkRSAPDB(ctx, cfg, old, transcripts, nodePub, networkService)
	}
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	localValid := make(map[int][]int, len(old))
	certs := make(map[int]APDBCertificate, len(old))
	for _, nodeID := range old {
		localValid[nodeID] = make([]int, 0, len(old))
	}

	addrMap := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	if len(addrMap) < len(old) {
		return nil, fmt.Errorf("protocol node addresses incomplete: have=%d need_at_least=%d", len(addrMap), len(old))
	}
	localIDs := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	if len(localIDs) == 0 {
		return nil, fmt.Errorf("protocol local node ids empty")
	}

	receiptTO := 8 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > receiptTO {
			receiptTO = candidate
		}
	}

	lnByID := make(map[int]net.Listener, len(localIDs))
	var lnWG sync.WaitGroup
	stop := make(chan struct{})
	defer func() {
		close(stop)
		for _, ln := range lnByID {
			_ = ln.Close()
		}
		lnWG.Wait()
	}()

	for nodeID := range localIDs {
		if _, ok := nodePriv[nodeID]; !ok {
			continue
		}
		addr, ok := addrMap[nodeID]
		if !ok || strings.TrimSpace(addr) == "" {
			continue
		}
		_, port, _ := net.SplitHostPort(addr)
		ln, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			continue
		}
		lnByID[nodeID] = ln
		lnWG.Add(1)
		go func(id int, l net.Listener) {
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
				_ = conn.SetReadDeadline(time.Now().Add(receiptTO))
				var req apdbReceiptRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					_ = conn.Close()
					continue
				}
				if body, mErr := json.Marshal(req); mErr == nil {
					recordRecvBytes(len(body))
				}
				_ = conn.Close()
				raw, err := canonicalAPDBReceiptData(&req)
				if err != nil || !dxt.VerifyTranscript(id, &req.TR) {
					continue
				}
				// A receipt is an availability statement. Publish it only after
				// the exact root-bound bytes are durable in this holder's store.
				if err := persistAPDBTranscript(cfg, old, id, req.Dealer, req.Root, raw); err != nil {
					continue
				}
				chunkHash := hashChunk(req.Root, req.Dealer, id, raw)
				msg := hashReceiptMsg(req.Dealer, id, req.Root, chunkHash)
				sig := ed25519.Sign(nodePriv[id], msg)
				resp := apdbReceiptResponse{
					Dealer: req.Dealer,
					Receipt: APDBReceipt{
						NodeID:    id,
						Sender:    req.Dealer,
						ChunkHash: chunkHash,
						Signature: sig,
					},
				}
				dial, err := dialWithBandwidth("tcp", req.Reply, receiptTO)
				if err != nil {
					continue
				}
				_ = dial.SetWriteDeadline(time.Now().Add(receiptTO))
				if body, mErr := json.Marshal(resp); mErr == nil {
					recordSentBytes(len(body))
				}
				_ = json.NewEncoder(dial).Encode(resp)
				_ = dial.Close()
			}
		}(nodeID, ln)
	}
	if len(lnByID) == 0 {
		return nil, fmt.Errorf("apdb listeners unavailable for configured protocol transport")
	}
	for _, dealer := range old {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}
		root := sha256.Sum256(raw)

		replyLn, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			return nil, err
		}
		replyAddr := dialableProtocolReplyAddr(replyLn.Addr().String(), addrMap, localIDs)

		respCh := make(chan apdbReceiptResponse, len(old)*2)
		var replyWG sync.WaitGroup
		replyWG.Add(1)
		go func() {
			defer replyWG.Done()
			for {
				conn, err := replyLn.Accept()
				if err != nil {
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(receiptTO))
				var resp apdbReceiptResponse
				if err := json.NewDecoder(conn).Decode(&resp); err == nil {
					if body, mErr := json.Marshal(resp); mErr == nil {
						recordRecvBytes(len(body))
					}
					select {
					case respCh <- resp:
					default:
					}
				}
				_ = conn.Close()
			}
		}()

		req := apdbReceiptRequest{
			Dealer: dealer,
			Root:   root[:],
			Reply:  replyAddr,
			TR:     *tr,
		}
		reqBytes, err := json.Marshal(req)
		if err != nil {
			_ = replyLn.Close()
			replyWG.Wait()
			return nil, err
		}
		for _, nodeID := range old {
			addr, ok := addrMap[nodeID]
			if !ok || strings.TrimSpace(addr) == "" {
				continue
			}
			conn, err := dialWithBandwidth("tcp", addr, receiptTO)
			if err != nil {
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(receiptTO))
			written, _ := conn.Write(reqBytes)
			recordSentBytes(written)
			_ = conn.Close()
		}

		receipts := make([]APDBReceipt, 0, len(old))
		seen := make(map[int]struct{}, len(old))
		deadline := time.NewTimer(receiptTO)
	collectReceipts:
		for len(receipts) < threshold {
			select {
			case <-ctx.Done():
				deadline.Stop()
				_ = replyLn.Close()
				replyWG.Wait()
				return nil, ctx.Err()
			case <-deadline.C:
				break collectReceipts
			case resp := <-respCh:
				if resp.Dealer != dealer {
					continue
				}
				if !verifyAPDBReceiptForData(resp.Receipt, dealer, root[:], raw, nodePub) {
					continue
				}
				if _, ok := seen[resp.Receipt.NodeID]; ok {
					continue
				}
				seen[resp.Receipt.NodeID] = struct{}{}
				receipts = append(receipts, resp.Receipt)
			}
		}
		deadline.Stop()
		_ = replyLn.Close()
		replyWG.Wait()

		if len(receipts) < threshold {
			continue
		}
		sort.Slice(receipts, func(i, j int) bool {
			return receipts[i].NodeID < receipts[j].NodeID
		})
		cert := APDBCertificate{
			Sender:   dealer,
			Root:     root[:],
			Receipts: append([]APDBReceipt(nil), receipts[:threshold]...),
		}
		certs[dealer] = cert

		for _, nodeID := range old {
			if verifyAPDBCertificate(cert, nodePub, cfg.F) {
				localValid[nodeID] = append(localValid[nodeID], dealer)
			}
		}
	}
	return &APDBDispersalResult{
		LocalValid:   localValid,
		Certificates: certs,
	}, nil
}

func dialableProtocolReplyAddr(listenerAddr string, addrMap map[int]string, localIDs map[int]struct{}) string {
	host, port, err := net.SplitHostPort(listenerAddr)
	if err != nil {
		return listenerAddr
	}
	if host != "" && host != "0.0.0.0" && host != "::" && host != "[::]" {
		return listenerAddr
	}
	for id := range localIDs {
		addr := strings.TrimSpace(addrMap[id])
		if addr == "" {
			continue
		}
		peerHost, _, splitErr := net.SplitHostPort(addr)
		if splitErr == nil && peerHost != "" && peerHost != "0.0.0.0" && peerHost != "::" && peerHost != "[::]" {
			return net.JoinHostPort(peerHost, port)
		}
	}
	return net.JoinHostPort("127.0.0.1", port)
}

func runAPDBDispersalLocal(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
) (*APDBDispersalResult, error) {
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	localValid := make(map[int][]int, len(old))
	certs := make(map[int]APDBCertificate, len(old))
	for _, nodeID := range old {
		localValid[nodeID] = make([]int, 0, len(old))
	}
	receiptTO := 8 * time.Second
	if cfg.RouteSendTimeout > 0 {
		candidate := 8 * cfg.RouteSendTimeout
		if candidate > receiptTO {
			receiptTO = candidate
		}
	}
	for _, dealer := range old {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		tr := transcripts[dealer]
		if tr == nil {
			continue
		}
		raw, err := json.Marshal(tr)
		if err != nil {
			return nil, err
		}
		root := sha256.Sum256(raw)
		receiptCh := make(chan APDBReceipt, len(old)*2)
		for _, nodeID := range old {
			nid := nodeID
			go func() {
				if !dxt.VerifyTranscript(nid, tr) {
					return
				}
				if err := persistAPDBTranscript(cfg, old, nid, dealer, root[:], raw); err != nil {
					return
				}
				chunkHash := hashChunk(root[:], dealer, nid, raw)
				msg := hashReceiptMsg(dealer, nid, root[:], chunkHash)
				sig := ed25519.Sign(nodePriv[nid], msg)
				select {
				case receiptCh <- APDBReceipt{
					NodeID:    nid,
					Sender:    dealer,
					ChunkHash: chunkHash,
					Signature: sig,
				}:
				case <-ctx.Done():
				}
			}()
		}
		receipts := make([]APDBReceipt, 0, len(old))
		seen := make(map[int]struct{}, len(old))
		deadline := time.NewTimer(receiptTO)
		for len(receipts) < threshold {
			select {
			case <-ctx.Done():
				deadline.Stop()
				return nil, ctx.Err()
			case <-deadline.C:
				goto doneCollect
			case rc := <-receiptCh:
				if _, ok := seen[rc.NodeID]; ok {
					continue
				}
				seen[rc.NodeID] = struct{}{}
				receipts = append(receipts, rc)
			}
		}
	doneCollect:
		deadline.Stop()
		if len(receipts) < threshold {
			continue
		}
		sort.Slice(receipts, func(i, j int) bool { return receipts[i].NodeID < receipts[j].NodeID })
		cert := APDBCertificate{
			Sender:   dealer,
			Root:     root[:],
			Receipts: append([]APDBReceipt(nil), receipts[:threshold]...),
		}
		certs[dealer] = cert
		for _, nodeID := range old {
			if verifyAPDBCertificate(cert, nodePub, cfg.F) {
				localValid[nodeID] = append(localValid[nodeID], dealer)
			}
		}
	}
	return &APDBDispersalResult{
		LocalValid:   localValid,
		Certificates: certs,
	}, nil
}

func verifyAPDBCertificate(cert APDBCertificate, nodePub map[int]ed25519.PublicKey, configuredFaults ...int) bool {
	if len(cert.Root) != sha256.Size {
		return false
	}
	committeeSize := len(nodePub)
	f := (committeeSize - 1) / 3
	if len(configuredFaults) > 1 || (len(configuredFaults) == 1 && configuredFaults[0] < 0) {
		return false
	}
	if len(configuredFaults) == 1 {
		f = configuredFaults[0]
	}
	if committeeSize <= 0 || committeeSize < 3*f+1 {
		return false
	}
	if len(cert.Receipts) == 0 {
		// Compact proofs require a trusted setup key. Never authenticate one
		// using only the group key carried by the untrusted certificate.
		return false
	}
	if len(cert.MerkleRoot) > 0 || len(cert.ValueDigest) > 0 || cert.DataShards > 0 || cert.TotalShards > 0 {
		if len(cert.MerkleRoot) != sha256.Size || len(cert.ValueDigest) != sha256.Size ||
			cert.TotalShards != committeeSize || cert.DataShards != committeeSize-2*f ||
			!bytes.Equal(cert.Root, apdbCommitmentRoot(cert.Sender, cert.ValueDigest, cert.MerkleRoot, cert.DataShards, cert.TotalShards)) {
			return false
		}
	}
	required := apdbCertificateThreshold(f, committeeSize)
	if required > 0 && len(cert.Receipts) < required {
		return false
	}
	seen := make(map[int]struct{}, len(cert.Receipts))
	for _, rc := range cert.Receipts {
		if rc.Sender != cert.Sender || len(rc.ChunkHash) != sha256.Size {
			return false
		}
		if _, ok := seen[rc.NodeID]; ok {
			return false
		}
		seen[rc.NodeID] = struct{}{}
		pk, ok := nodePub[rc.NodeID]
		if !ok {
			return false
		}
		msg := hashReceiptMsg(cert.Sender, rc.NodeID, cert.Root, rc.ChunkHash)
		if !ed25519.Verify(pk, msg, rc.Signature) {
			return false
		}
	}
	return true
}

func verifyAPDBCertificateWithThresholdPublic(
	cert APDBCertificate,
	nodePub map[int]ed25519.PublicKey,
	f int,
	trustedPublic []byte,
) bool {
	if len(cert.Receipts) > 0 {
		return verifyAPDBCertificate(cert, nodePub, f)
	}
	return verifyAPDBThresholdCertificate(cert, f, trustedPublic)
}

func apdbCertificateThreshold(f int, committeeSize int) int {
	threshold := committeeSize - f
	if threshold < f+1 {
		threshold = f + 1
	}
	if committeeSize > 0 && threshold > committeeSize {
		threshold = committeeSize
	}
	return threshold
}

func apdbFinishedSetThreshold(f int, committeeSize int) int {
	threshold := 2*f + 1
	if threshold < f+1 {
		threshold = f + 1
	}
	if committeeSize > 0 && threshold > committeeSize {
		threshold = committeeSize
	}
	return threshold
}

func hashChunk(root []byte, dealer int, nodeID int, data []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-APDB-CHUNK"))
	h.Write(root)
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(nodeID))
	h.Write(b[:])
	dataDigest := sha256.Sum256(data)
	h.Write(dataDigest[:])
	return h.Sum(nil)
}

func canonicalAPDBReceiptData(req *apdbReceiptRequest) ([]byte, error) {
	if req == nil || req.Dealer != req.TR.Dealer {
		return nil, fmt.Errorf("APDB dealer/transcript mismatch")
	}
	raw, err := json.Marshal(&req.TR)
	if err != nil {
		return nil, fmt.Errorf("marshal APDB transcript: %w", err)
	}
	root := sha256.Sum256(raw)
	if len(req.Root) != sha256.Size || !bytes.Equal(req.Root, root[:]) {
		return nil, fmt.Errorf("APDB root does not bind transcript")
	}
	return raw, nil
}

func verifyAPDBReceiptForData(
	receipt APDBReceipt,
	dealer int,
	root []byte,
	data []byte,
	nodePub map[int]ed25519.PublicKey,
) bool {
	if receipt.Sender != dealer || len(root) != sha256.Size {
		return false
	}
	pk, ok := nodePub[receipt.NodeID]
	if !ok {
		return false
	}
	expected := hashChunk(root, dealer, receipt.NodeID, data)
	if !bytes.Equal(receipt.ChunkHash, expected) {
		return false
	}
	return ed25519.Verify(pk, hashReceiptMsg(dealer, receipt.NodeID, root, expected), receipt.Signature)
}

func apdbTranscriptStorePath(cfg Config, old []int, nodeID, dealer int, root []byte) string {
	base := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if base == "" {
		base = filepath.Join(os.TempDir(), "practical-adkr-artifacts")
	}
	return filepath.Join(
		base,
		"apdb-transcripts",
		practicalRunID(cfg, old, cfg.NewCommittee),
		fmt.Sprintf("node-%06d", nodeID),
		fmt.Sprintf("dealer-%06d-%x.tr.json", dealer, root),
	)
}

func persistAPDBTranscript(cfg Config, old []int, nodeID, dealer int, root, raw []byte) error {
	computed := sha256.Sum256(raw)
	if len(root) != sha256.Size || !bytes.Equal(root, computed[:]) {
		return fmt.Errorf("refuse to store APDB transcript with mismatched root")
	}
	path := apdbTranscriptStorePath(cfg, old, nodeID, dealer, root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create APDB transcript store: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apdb-transcript-*.tmp")
	if err != nil {
		return fmt.Errorf("create APDB transcript temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}
	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod APDB transcript temp file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		cleanup()
		return fmt.Errorf("write APDB transcript: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync APDB transcript: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close APDB transcript: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("publish APDB transcript: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open APDB transcript directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync APDB transcript directory: %w", err)
	}
	return nil
}

func hashReceiptMsg(dealer int, nodeID int, root []byte, chunkHash []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PADKR-APDB-RECEIPT"))
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(dealer))
	binary.BigEndian.PutUint64(b[8:], uint64(nodeID))
	h.Write(b[:])
	h.Write(root)
	h.Write(chunkHash)
	return h.Sum(nil)
}
