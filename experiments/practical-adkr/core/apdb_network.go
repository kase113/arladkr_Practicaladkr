package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type apdbNetworkWire struct {
	Kind        string          `json:"kind"`
	SID         string          `json:"sid"`
	Epoch       uint64          `json:"epoch"`
	Dealer      int             `json:"dealer"`
	Holder      int             `json:"holder"`
	Root        []byte          `json:"root,omitempty"`
	ValueDigest []byte          `json:"value_digest,omitempty"`
	MerkleRoot  []byte          `json:"merkle_root,omitempty"`
	DataShards  int             `json:"data_shards,omitempty"`
	TotalShards int             `json:"total_shards,omitempty"`
	ShardIndex  int             `json:"shard_index,omitempty"`
	Shard       []byte          `json:"shard,omitempty"`
	Proof       [][]byte        `json:"proof,omitempty"`
	Receipt     APDBReceipt     `json:"receipt,omitempty"`
	Certificate APDBCertificate `json:"certificate,omitempty"`
}

var apdbFrameMagic = [2]byte{'A', 'P'}

type apdbDealerResult struct {
	certificate APDBCertificate
	err         error
}

// verifiedAPDBCertificate is the only type admitted to the service's private
// certificate channel. Network deliveries are verified by the listener and
// locally produced certificates are verified before publication.
type verifiedAPDBCertificate struct {
	certificate APDBCertificate
}

// networkAPDBService stays alive from the end of DXT dealing through the MVBA
// decision. This lets a node leave APDB after a finished quorum without making
// its protocol port unavailable to slower certificate broadcasters.
type networkAPDBService struct {
	cfg           Config
	old           []int
	addresses     map[int]string
	listeners     map[int]net.Listener
	certificates  chan verifiedAPDBCertificate
	ctx           context.Context
	cancel        context.CancelFunc
	closeOnce     sync.Once
	listenerWG    sync.WaitGroup
	sendWG        sync.WaitGroup
	thresholdKeys *thresholdCoinKeySet
}

func startNetworkAPDBService(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePriv map[int]ed25519.PrivateKey,
	nodePub map[int]ed25519.PublicKey,
	dxt *DXTBackend,
	thresholdKeys ...*thresholdCoinKeySet,
) (*networkAPDBService, error) {
	addresses := parseNodeAddrMap(cfg.ProtocolNodeAddrs)
	configuredLocal := parseNodeIDSet(cfg.ProtocolLocalNodeIDs)
	serviceCtx, cancel := context.WithCancel(ctx)
	service := &networkAPDBService{
		cfg: cfg, old: append([]int(nil), old...), addresses: addresses,
		listeners: make(map[int]net.Listener), certificates: make(chan verifiedAPDBCertificate, len(old)*len(old)*2),
		ctx: serviceCtx, cancel: cancel,
	}
	if len(thresholdKeys) > 0 {
		service.thresholdKeys = thresholdKeys[0]
	}
	for _, id := range old {
		if _, ok := configuredLocal[id]; !ok {
			continue
		}
		if len(nodePriv[id]) != ed25519.PrivateKeySize {
			service.close()
			return nil, fmt.Errorf("network APDB local node %d signing key unavailable", id)
		}
		_, port, err := net.SplitHostPort(addresses[id])
		if err != nil {
			service.close()
			return nil, err
		}
		listener, err := net.Listen("tcp", net.JoinHostPort("0.0.0.0", port))
		if err != nil {
			service.close()
			return nil, fmt.Errorf("network APDB listen node %d: %w", id, err)
		}
		service.listeners[id] = listener
		service.listenerWG.Add(1)
		go serveNetworkAPDB(serviceCtx, cfg, old, id, listener, transcripts, nodePriv[id], nodePub, dxt, service.thresholdKeys, service.certificates, &service.listenerWG)
	}
	if len(service.listeners) == 0 {
		service.close()
		return nil, errors.New("network APDB has no local old identity")
	}
	return service, nil
}

func (service *networkAPDBService) close() {
	if service == nil {
		return
	}
	service.closeOnce.Do(func() {
		service.cancel()
		for _, listener := range service.listeners {
			_ = listener.Close()
		}
		service.listenerWG.Wait()
		service.sendWG.Wait()
	})
}

func (service *networkAPDBService) broadcast(certificate APDBCertificate) {
	for _, target := range service.old {
		if _, local := service.listeners[target]; local {
			continue
		}
		service.sendWG.Add(1)
		go func(target int) {
			defer service.sendWG.Done()
			sendNetworkAPDBCertificate(service.ctx, service.cfg, certificate.Sender, target, service.addresses[target], certificate)
		}(target)
	}
}

func writeAPDBNetworkWire(conn net.Conn, wire apdbNetworkWire) error {
	frame, err := marshalPracticalJSONFrame(apdbFrameMagic, wire)
	if err != nil {
		return err
	}
	return writeAPDBNetworkFrame(conn, frame)
}

func writeAPDBNetworkFrame(conn net.Conn, frame []byte) error {
	wireBytes := len(frame)
	for len(frame) > 0 {
		n, err := conn.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("short APDB network write")
		}
		frame = frame[n:]
	}
	recordSentBytes(wireBytes)
	return nil
}

func readAPDBNetworkWire(conn net.Conn, wire *apdbNetworkWire) error {
	wireBytes, err := readPracticalJSONFrame(conn, apdbFrameMagic, wire)
	if err != nil {
		return err
	}
	recordRecvBytes(wireBytes)
	return nil
}

func apdbShardLeaf(dealer, index int, shard []byte) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-APDB-RS-SHARD-v1"))
	var ids [16]byte
	binary.BigEndian.PutUint64(ids[:8], uint64(dealer))
	binary.BigEndian.PutUint64(ids[8:], uint64(index))
	h.Write(ids[:])
	digest := sha256.Sum256(shard)
	h.Write(digest[:])
	return h.Sum(nil)
}

func apdbCommitmentRoot(dealer int, valueDigest, merkleRoot []byte, dataShards, totalShards int) []byte {
	h := sha256.New()
	h.Write([]byte("PRACTICAL-APDB-RS-COMMITMENT-v1"))
	var numbers [24]byte
	binary.BigEndian.PutUint64(numbers[:8], uint64(dealer))
	binary.BigEndian.PutUint64(numbers[8:16], uint64(dataShards))
	binary.BigEndian.PutUint64(numbers[16:], uint64(totalShards))
	h.Write(numbers[:])
	h.Write(valueDigest)
	h.Write(merkleRoot)
	return h.Sum(nil)
}

func apdbMerkleTree(leaves [][]byte) ([]byte, [][][]byte, error) {
	if len(leaves) == 0 {
		return nil, nil, errors.New("empty APDB Merkle tree")
	}
	level := make([][]byte, len(leaves))
	for i := range leaves {
		if len(leaves[i]) != sha256.Size {
			return nil, nil, errors.New("invalid APDB Merkle leaf")
		}
		level[i] = append([]byte(nil), leaves[i]...)
	}
	proofs := make([][][]byte, len(leaves))
	positions := make([]int, len(leaves))
	for i := range positions {
		positions[i] = i
	}
	for len(level) > 1 {
		for original, position := range positions {
			sibling := position ^ 1
			if sibling >= len(level) {
				sibling = position
			}
			proofs[original] = append(proofs[original], append([]byte(nil), level[sibling]...))
			positions[original] = position / 2
		}
		next := make([][]byte, (len(level)+1)/2)
		for i := range next {
			left := level[2*i]
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}
			h := sha256.New()
			h.Write([]byte("PRACTICAL-APDB-MERKLE-NODE-v1"))
			h.Write(left)
			h.Write(right)
			next[i] = h.Sum(nil)
		}
		level = next
	}
	return level[0], proofs, nil
}

func verifyAPDBMerkleProof(leaf []byte, index, total int, proof [][]byte, root []byte) bool {
	if len(leaf) != sha256.Size || len(root) != sha256.Size || index < 0 || index >= total || total <= 0 {
		return false
	}
	current := append([]byte(nil), leaf...)
	position := index
	width := total
	for _, sibling := range proof {
		if len(sibling) != sha256.Size || width <= 1 {
			return false
		}
		left, right := current, sibling
		if position%2 == 1 {
			left, right = sibling, current
		}
		h := sha256.New()
		h.Write([]byte("PRACTICAL-APDB-MERKLE-NODE-v1"))
		h.Write(left)
		h.Write(right)
		current = h.Sum(nil)
		position /= 2
		width = (width + 1) / 2
	}
	return width == 1 && bytes.Equal(current, root)
}

func runNetworkRSAPDB(
	ctx context.Context,
	cfg Config,
	old []int,
	transcripts map[int]*DXTTranscript,
	nodePub map[int]ed25519.PublicKey,
	service *networkAPDBService,
) (*APDBDispersalResult, error) {
	if service == nil || len(service.listeners) == 0 {
		return nil, errors.New("network APDB persistent service unavailable")
	}
	localOld := make([]int, 0, len(service.listeners))
	for _, id := range old {
		if _, ok := service.listeners[id]; ok {
			localOld = append(localOld, id)
		}
	}
	if err := waitNetworkAPDBReady(ctx, cfg, old, service.addresses, service.listeners); err != nil {
		return nil, err
	}

	localCerts := make(chan apdbDealerResult, len(localOld))
	for _, dealer := range localOld {
		dealer := dealer
		go func() {
			certificate, err := disperseNetworkAPDBDealer(ctx, cfg, old, dealer, transcripts[dealer], service.addresses, nodePub, service.thresholdKeys)
			localCerts <- apdbDealerResult{certificate: certificate, err: err}
		}()
	}
	go func() {
		for range localOld {
			select {
			case <-ctx.Done():
				return
			case result := <-localCerts:
				if result.err != nil {
					continue
				}
				certificate := result.certificate
				if !verifyAPDBCertificateWithThresholdPublic(certificate, nodePub, cfg.F, trustedAPDBThresholdPublic(service.thresholdKeys)) {
					continue
				}
				select {
				case service.certificates <- verifiedAPDBCertificate{certificate: certificate}:
					service.broadcast(certificate)
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	required := apdbFinishedSetThreshold(cfg.F, len(old))
	certs := make(map[int]APDBCertificate, required)
	for len(certs) < required {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("network APDB certificates: have=%d need=%d: %w", len(certs), required, ctx.Err())
		case delivery := <-service.certificates:
			certificate := delivery.certificate
			_, dealerPresent := apdbNodeIndex(old, certificate.Sender)
			if _, duplicate := certs[certificate.Sender]; duplicate || !dealerPresent {
				continue
			}
			certs[certificate.Sender] = certificate
		}
	}
	dealers := make([]int, 0, len(certs))
	for dealer := range certs {
		dealers = append(dealers, dealer)
	}
	sort.Ints(dealers)
	localValid := make(map[int][]int, len(old))
	for _, id := range old {
		localValid[id] = append([]int(nil), dealers...)
	}
	return &APDBDispersalResult{LocalValid: localValid, Certificates: certs}, nil
}

func serveNetworkAPDB(
	ctx context.Context,
	cfg Config,
	old []int,
	localID int,
	listener net.Listener,
	transcripts map[int]*DXTTranscript,
	private ed25519.PrivateKey,
	public map[int]ed25519.PublicKey,
	dxt *DXTBackend,
	thresholdKeys *thresholdCoinKeySet,
	certCh chan<- verifiedAPDBCertificate,
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		go func(connection net.Conn) {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			var wire apdbNetworkWire
			if readAPDBNetworkWire(connection, &wire) != nil || wire.SID != cfg.SID || wire.Epoch != cfg.Epoch {
				return
			}
			switch wire.Kind {
			case "ready":
				_ = writeAPDBNetworkWire(connection, apdbNetworkWire{Kind: "ready-ack", SID: cfg.SID, Epoch: cfg.Epoch, Holder: localID})
			case "shard":
				receipt, err := acceptNetworkAPDBShard(cfg, old, localID, wire, transcripts, private, dxt)
				if err == nil && thresholdKeys != nil {
					metadata := APDBCertificate{Sender: wire.Dealer, Root: wire.Root, ValueDigest: wire.ValueDigest, MerkleRoot: wire.MerkleRoot, DataShards: wire.DataShards, TotalShards: wire.TotalShards}
					receipt.ThresholdShare, err = apdbThresholdShare(thresholdKeys, localID, metadata)
				}
				if err == nil {
					_ = writeAPDBNetworkWire(connection, apdbNetworkWire{Kind: "receipt", SID: cfg.SID, Epoch: cfg.Epoch, Dealer: wire.Dealer, Holder: localID, Receipt: receipt})
				}
			case "cert":
				if verifyAPDBCertificateWithThresholdPublic(wire.Certificate, public, cfg.F, trustedAPDBThresholdPublic(thresholdKeys)) {
					select {
					case certCh <- verifiedAPDBCertificate{certificate: wire.Certificate}:
					case <-ctx.Done():
						return
					}
					_ = writeAPDBNetworkWire(connection, apdbNetworkWire{Kind: "cert-ack", SID: cfg.SID, Epoch: cfg.Epoch, Dealer: wire.Certificate.Sender, Holder: localID})
				}
			}
		}(conn)
	}
}

func acceptNetworkAPDBShard(cfg Config, old []int, localID int, wire apdbNetworkWire, _ map[int]*DXTTranscript, private ed25519.PrivateKey, _ *DXTBackend) (APDBReceipt, error) {
	_, dealerPresent := apdbNodeIndex(old, wire.Dealer)
	expectedDataShards := len(old) - 2*cfg.F
	if wire.Holder != localID || wire.TotalShards != len(old) || wire.ShardIndex < 0 || wire.ShardIndex >= len(old) ||
		old[wire.ShardIndex] != localID || !dealerPresent ||
		expectedDataShards <= 0 || wire.DataShards != expectedDataShards {
		return APDBReceipt{}, errors.New("invalid network APDB shard metadata")
	}
	root := apdbCommitmentRoot(wire.Dealer, wire.ValueDigest, wire.MerkleRoot, wire.DataShards, wire.TotalShards)
	leaf := apdbShardLeaf(wire.Dealer, wire.ShardIndex, wire.Shard)
	if !bytes.Equal(root, wire.Root) || !verifyAPDBMerkleProof(leaf, wire.ShardIndex, wire.TotalShards, wire.Proof, wire.MerkleRoot) {
		return APDBReceipt{}, errors.New("invalid network APDB commitment/proof")
	}
	if err := persistNetworkAPDBShard(cfg, old, localID, wire); err != nil {
		return APDBReceipt{}, err
	}
	receipt := APDBReceipt{NodeID: localID, Sender: wire.Dealer, ChunkHash: leaf}
	receipt.Signature = ed25519.Sign(private, hashReceiptMsg(wire.Dealer, localID, wire.Root, leaf))
	return receipt, nil
}

func disperseNetworkAPDBDealer(ctx context.Context, cfg Config, old []int, dealer int, transcript *DXTTranscript, addrMap map[int]string, nodePub map[int]ed25519.PublicKey, thresholdKeys ...*thresholdCoinKeySet) (APDBCertificate, error) {
	if transcript == nil {
		return APDBCertificate{}, errors.New("nil network APDB transcript")
	}
	raw, err := json.Marshal(transcript)
	if err != nil {
		return APDBCertificate{}, err
	}
	dataShards := len(old) - 2*cfg.F
	if dataShards <= 0 {
		return APDBCertificate{}, errors.New("invalid network APDB erasure threshold")
	}
	shards, err := recoverEncodeValue(raw, dataShards, len(old))
	if err != nil {
		return APDBCertificate{}, err
	}
	leaves := make([][]byte, len(shards))
	for i := range shards {
		leaves[i] = apdbShardLeaf(dealer, i, shards[i])
	}
	merkleRoot, proofs, err := apdbMerkleTree(leaves)
	if err != nil {
		return APDBCertificate{}, err
	}
	valueDigest := sha256.Sum256(raw)
	root := apdbCommitmentRoot(dealer, valueDigest[:], merkleRoot, dataShards, len(old))
	receiptCh := make(chan APDBReceipt, len(old))
	for index, holder := range old {
		index, holder := index, holder
		wire := apdbNetworkWire{
			Kind: "shard", SID: cfg.SID, Epoch: cfg.Epoch, Dealer: dealer, Holder: holder,
			Root: root, ValueDigest: valueDigest[:], MerkleRoot: merkleRoot,
			DataShards: dataShards, TotalShards: len(old), ShardIndex: index,
			Shard: shards[index], Proof: proofs[index],
		}
		go func() {
			if receipt, err := sendNetworkAPDBShard(ctx, cfg, dealer, holder, addrMap[holder], wire); err == nil {
				receiptCh <- receipt
			}
		}()
	}
	threshold := apdbCertificateThreshold(cfg.F, len(old))
	receipts := make([]APDBReceipt, 0, threshold)
	seen := make(map[int]struct{}, threshold)
	for len(receipts) < threshold {
		select {
		case <-ctx.Done():
			return APDBCertificate{}, ctx.Err()
		case receipt := <-receiptCh:
			holderIndex, holderPresent := apdbNodeIndex(old, receipt.NodeID)
			if _, duplicate := seen[receipt.NodeID]; duplicate || !holderPresent ||
				!bytes.Equal(receipt.ChunkHash, leaves[holderIndex]) {
				continue
			}
			if !ed25519.Verify(nodePub[receipt.NodeID], hashReceiptMsg(dealer, receipt.NodeID, root, receipt.ChunkHash), receipt.Signature) {
				continue
			}
			seen[receipt.NodeID] = struct{}{}
			receipts = append(receipts, receipt)
		}
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].NodeID < receipts[j].NodeID })
	certificate := APDBCertificate{
		Sender: dealer, Root: root, ValueDigest: valueDigest[:], MerkleRoot: merkleRoot,
		DataShards: dataShards, TotalShards: len(old), Receipts: receipts,
	}
	if len(thresholdKeys) > 0 && thresholdKeys[0] != nil {
		certificate.ThresholdSignature, err = recoverAPDBThresholdSignature(thresholdKeys[0], certificate, receipts)
		if err != nil {
			return APDBCertificate{}, err
		}
		// The trusted group public key is setup material and is intentionally not
		// repeated in every certificate wire. Keep receipt shares only in the
		// local collection scope; MVBA carries just the constant-size proof.
		certificate.Receipts = nil
	}
	return certificate, nil
}

func apdbNodeIndex(nodes []int, target int) (int, bool) {
	for index, nodeID := range nodes {
		if nodeID == target {
			return index, true
		}
	}
	return 0, false
}

func sendNetworkAPDBShard(ctx context.Context, cfg Config, from, to int, addr string, wire apdbNetworkWire) (APDBReceipt, error) {
	frame, err := marshalPracticalJSONFrame(apdbFrameMagic, wire)
	if err != nil {
		return APDBReceipt{}, err
	}
	for {
		conn, err := dialWithBandwidth("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			if writeAPDBNetworkFrame(conn, frame) == nil {
				var response apdbNetworkWire
				if readAPDBNetworkWire(conn, &response) == nil && response.Kind == "receipt" && response.Dealer == wire.Dealer && response.Holder == to {
					_ = conn.Close()
					return response.Receipt, nil
				}
			}
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return APDBReceipt{}, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func sendNetworkAPDBCertificate(ctx context.Context, cfg Config, from, to int, addr string, certificate APDBCertificate) {
	wire := apdbNetworkWire{Kind: "cert", SID: cfg.SID, Epoch: cfg.Epoch, Dealer: certificate.Sender, Holder: to, Certificate: certificate}
	frame, err := marshalPracticalJSONFrame(apdbFrameMagic, wire)
	if err != nil {
		return
	}
	for {
		conn, err := dialWithBandwidth("tcp", addr, 500*time.Millisecond)
		if err == nil {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if writeAPDBNetworkFrame(conn, frame) == nil {
				var ack apdbNetworkWire
				if readAPDBNetworkWire(conn, &ack) == nil && ack.Kind == "cert-ack" && ack.Dealer == certificate.Sender && ack.Holder == to {
					_ = conn.Close()
					return
				}
			}
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func waitNetworkAPDBReady(ctx context.Context, cfg Config, old []int, addrMap map[int]string, local map[int]net.Listener) error {
	dialTimeout := durationFromEnvMsOr("PRACTICAL_APDB_READY_DIAL_TIMEOUT_MS", time.Second)
	ioTimeout := durationFromEnvMsOr("PRACTICAL_APDB_READY_IO_TIMEOUT_MS", 2*time.Second)
	need := len(old) - cfg.F
	lastReachable := 0
	for {
		reachable := 0
		remote := make([]int, 0, len(old))
		for _, id := range old {
			if _, ok := local[id]; ok {
				reachable++
				continue
			}
			remote = append(remote, id)
		}
		if reachable >= need {
			return nil
		}

		results := make(chan bool, len(remote))
		for _, id := range remote {
			id := id
			go func() {
				conn, err := net.DialTimeout("tcp", addrMap[id], dialTimeout)
				if err != nil {
					results <- false
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(ioTimeout))
				if writeAPDBNetworkWire(conn, apdbNetworkWire{Kind: "ready", SID: cfg.SID, Epoch: cfg.Epoch, Holder: id}) != nil {
					results <- false
					return
				}
				var ack apdbNetworkWire
				results <- readAPDBNetworkWire(conn, &ack) == nil && ack.Kind == "ready-ack" && ack.Holder == id
			}()
		}
		for range remote {
			select {
			case ok := <-results:
				if ok {
					reachable++
					if reachable >= need {
						return nil
					}
				}
			case <-ctx.Done():
				return fmt.Errorf("network APDB readiness: reachable=%d need=%d: %w", reachable, need, ctx.Err())
			}
		}
		lastReachable = reachable
		select {
		case <-ctx.Done():
			return fmt.Errorf("network APDB readiness: reachable=%d need=%d: %w", lastReachable, need, ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func persistNetworkAPDBShard(cfg Config, old []int, holder int, wire apdbNetworkWire) error {
	base := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if base == "" {
		return errors.New("network APDB shard store requires PRACTICAL_ARTIFACT_CACHE_DIR")
	}
	path := networkAPDBShardStorePath(base, cfg, old, holder, wire.Dealer, wire.Root)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".apdb-shard-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func networkAPDBShardStorePath(base string, cfg Config, old []int, holder, dealer int, root []byte) string {
	return filepath.Join(base, "apdb-network-shards", practicalRunID(cfg, old, cfg.NewCommittee),
		fmt.Sprintf("node-%06d", holder), fmt.Sprintf("dealer-%06d-%x.shard", dealer, root))
}

// loadNetworkAPDBShard is the RC-side read of the exact shard persisted by PD.
// It never regenerates a codeword from a process-local full transcript.
func loadNetworkAPDBShard(cfg Config, old []int, holder int, cert APDBCertificate) (apdbNetworkWire, error) {
	base := strings.TrimSpace(os.Getenv("PRACTICAL_ARTIFACT_CACHE_DIR"))
	if base == "" {
		return apdbNetworkWire{}, errors.New("network APDB shard load requires PRACTICAL_ARTIFACT_CACHE_DIR")
	}
	if len(cert.Root) != sha256.Size || len(cert.ValueDigest) != sha256.Size ||
		len(cert.MerkleRoot) != sha256.Size || cert.TotalShards != len(old) ||
		cert.DataShards != len(old)-2*cfg.F {
		return apdbNetworkWire{}, errors.New("RC requires a complete RS/Merkle APDB certificate")
	}
	holderIndex, ok := apdbNodeIndex(old, holder)
	if !ok {
		return apdbNetworkWire{}, fmt.Errorf("holder %d is outside the old committee", holder)
	}
	path := networkAPDBShardStorePath(base, cfg, old, holder, cert.Sender, cert.Root)
	info, err := os.Stat(path)
	if err != nil {
		return apdbNetworkWire{}, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 64<<20 {
		return apdbNetworkWire{}, errors.New("invalid persisted network APDB shard file")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return apdbNetworkWire{}, err
	}
	var wire apdbNetworkWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return apdbNetworkWire{}, err
	}
	if wire.Kind != "shard" || wire.SID != cfg.SID || wire.Epoch != cfg.Epoch ||
		wire.Dealer != cert.Sender || wire.Holder != holder || wire.ShardIndex != holderIndex ||
		wire.DataShards != cert.DataShards || wire.TotalShards != cert.TotalShards ||
		!bytes.Equal(wire.Root, cert.Root) || !bytes.Equal(wire.ValueDigest, cert.ValueDigest) ||
		!bytes.Equal(wire.MerkleRoot, cert.MerkleRoot) {
		return apdbNetworkWire{}, errors.New("persisted APDB shard does not match its certificate")
	}
	leaf := apdbShardLeaf(wire.Dealer, wire.ShardIndex, wire.Shard)
	if !verifyAPDBMerkleProof(leaf, wire.ShardIndex, wire.TotalShards, wire.Proof, wire.MerkleRoot) {
		return apdbNetworkWire{}, errors.New("persisted APDB shard has an invalid Merkle proof")
	}
	return wire, nil
}
