// Package core — TCP-based MVBA transport for arladkr AgreeAgg.
//
// Replaces the in-process Go-channel MVBA with per-node TCP listeners so
// each physical machine only runs its assigned subset of logical MVBA nodes.
// Design mirrors dxt24's pkg/adkg/mvba_adapter.go.
package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	dmvba "dumbomvba_go/core"
)

var arlListenConfig = net.ListenConfig{
	Control: func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			ctrlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		if err != nil {
			return err
		}
		return ctrlErr
	},
}

func init() {
	gob.Register(dmvba.ProtocolMessage{})
	gob.Register(arladkrMVBAWire{})
}

type arladkrMVBAWire struct {
	From int
	Msg  dmvba.ProtocolMessage
}

// ── TCP hub (per-node listener) ────────────────────────────────────────────

type arladkrTCPHub struct {
	sid       string
	addrByID  map[int]string
	recv      []chan dmvba.ReceivedMessage
	lnByID    map[int]net.Listener
	lockPaths map[int]string
	closed    chan struct{}
	wg        sync.WaitGroup
	dialTO    time.Duration
	writeTO   time.Duration
	readTO    time.Duration
	retries   int
	backoff   time.Duration
	enqueueTO time.Duration
	runtime   *runtimeCrypto
	poolMu    sync.Mutex
	conns     map[string]*arlPoolConn
	poolLanes int
}

var (
	arlMVBAListenMu     sync.Mutex
	arlMVBAListenOwners = map[string]string{}
)

func arlProcessListenOwner() string {
	return fmt.Sprintf("pid=%d sid=%s local=%s", os.Getpid(), os.Getenv("RLADKR_SID"), os.Getenv("RLADKR_LOCAL_NODE_IDS"))
}

func arlRegisterListenAddr(addr string) error {
	arlMVBAListenMu.Lock()
	defer arlMVBAListenMu.Unlock()
	owner := arlProcessListenOwner()
	if prev, ok := arlMVBAListenOwners[addr]; ok {
		return fmt.Errorf("arladkr mvba tcp: duplicate in-process listen addr=%s owner=%s existing=%s", addr, owner, prev)
	}
	arlMVBAListenOwners[addr] = owner
	return nil
}

func arlUnregisterListenAddr(addr string) {
	arlMVBAListenMu.Lock()
	defer arlMVBAListenMu.Unlock()
	delete(arlMVBAListenOwners, addr)
}

func arlLockFilePath(cfg Config, id int, port string) string {
	base := strings.TrimSpace(cfg.ArtifactCacheDir)
	if base == "" {
		base = filepath.Join(os.TempDir(), "rladkr-mvba-locks")
	}
	return filepath.Join(base, fmt.Sprintf("mvba-port-%s-node-%d.lock", port, id))
}

func arlAcquireListenLock(cfg Config, id int, port string) (string, error) {
	lockPath := arlLockFilePath(cfg, id, port)
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return "", err
	}
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			ownerBytes, _ := os.ReadFile(lockPath)
			owner := strings.TrimSpace(string(ownerBytes))
			if owner == "" {
				owner = "unknown"
			}
			return "", fmt.Errorf("arladkr mvba tcp: lock exists for port=%s node=%d path=%s owner=%s", port, id, lockPath, owner)
		}
		return "", err
	}
	owner := arlProcessListenOwner()
	_, _ = syscall.Write(fd, []byte(owner+"\n"))
	_ = syscall.Close(fd)
	return lockPath, nil
}

func arlReleaseListenLock(lockPath string) {
	if strings.TrimSpace(lockPath) == "" {
		return
	}
	_ = os.Remove(lockPath)
}

func arlListenWithRetry(network string, addr string, timeout time.Duration, backoff time.Duration) (net.Listener, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if backoff <= 0 {
		backoff = 100 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for {
		ln, err := arlListenConfig.Listen(context.Background(), network, addr)
		if err == nil {
			return ln, nil
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) {
			return nil, err
		}
		var sysErr *os.SyscallError
		if !errors.As(opErr.Err, &sysErr) {
			return nil, err
		}
		if sysErr.Err != syscall.EADDRINUSE || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(backoff)
	}
}

func newArladkrTCPHub(cfg Config, recv []chan dmvba.ReceivedMessage) (*arladkrTCPHub, error) {
	n := len(recv)
	addrMap := parseArlAddrMap(firstNonEmptyArl(
		os.Getenv("RLADKR_MVBA_NODE_ADDRS"),
		os.Getenv("RLADKR_NODE_ADDRS"),
	))
	localIDs := parseArlNodeIDs(os.Getenv("RLADKR_LOCAL_NODE_IDS"))
	if len(localIDs) == 0 {
		localIDs = arlNodeIDSet(sortedUnique(cfg.LocalNodeIDs))
	}
	if len(localIDs) == 0 {
		localIDs = arlNodeIDSet(sortedUnique(cfg.OldCommittee))
	}

	h := &arladkrTCPHub{
		sid:       cfg.SID,
		addrByID:  addrMap,
		recv:      recv,
		lnByID:    make(map[int]net.Listener, len(localIDs)),
		lockPaths: make(map[int]string, len(localIDs)),
		closed:    make(chan struct{}),
		dialTO:    arlDurationFromEnv("RLADKR_MVBA_DIAL_TIMEOUT_MS", 3000*time.Millisecond),
		writeTO:   arlDurationFromEnv("RLADKR_MVBA_WRITE_TIMEOUT_MS", 3000*time.Millisecond),
		readTO:    arlDurationFromEnv("RLADKR_MVBA_READ_TIMEOUT_MS", defaultArlMVBAReadTimeout(n)),
		retries:   arlIntFromEnv("RLADKR_MVBA_SEND_RETRIES", 15),
		backoff:   arlDurationFromEnv("RLADKR_MVBA_RETRY_BACKOFF_MS", 120*time.Millisecond),
		enqueueTO: arlDurationFromEnv("RLADKR_MVBA_ENQUEUE_TIMEOUT_MS", 500*time.Millisecond),
		runtime:   cfg.runtime,
		conns:     make(map[string]*arlPoolConn),
		poolLanes: arlMVBAPoolLanes(n),
	}

	dialHost := resolveDialHost(cfg.AgreementBindHost)
	if cfg.AgreementBasePort > 0 {
		mvbaBase := cfg.AgreementBasePort + 500
		for id := 0; id < n; id++ {
			if _, ok := addrMap[id]; !ok {
				addrMap[id] = net.JoinHostPort(dialHost, strconv.Itoa(mvbaBase+id))
			}
		}
	}
	allLocal := len(localIDs) == n
	if len(addrMap) < n && !allLocal {
		return nil, fmt.Errorf("arladkr mvba tcp: incomplete addresses have=%d need=%d", len(addrMap), n)
	}

	for id := range localIDs {
		listenAddr := net.JoinHostPort(cfg.AgreementBindHost, "0")
		lockPort := "0"
		if addr, ok := addrMap[id]; ok {
			_, port, _ := net.SplitHostPort(addr)
			lockPort = port
			listenAddr = net.JoinHostPort(cfg.AgreementBindHost, port)
		}
		lockPath, err := arlAcquireListenLock(cfg, id, lockPort)
		if err != nil {
			h.close()
			return nil, err
		}
		ln, err := arlListenWithRetry(
			"tcp",
			listenAddr,
			arlDurationFromEnv("RLADKR_MVBA_LISTEN_RETRY_TIMEOUT_MS", 5*time.Second),
			arlDurationFromEnv("RLADKR_MVBA_LISTEN_RETRY_BACKOFF_MS", 100*time.Millisecond),
		)
		if err != nil {
			arlReleaseListenLock(lockPath)
			h.close()
			return nil, fmt.Errorf("arladkr mvba tcp: listen %s: %w", listenAddr, err)
		}
		actualAddr := ln.Addr().String()
		if err := arlRegisterListenAddr(actualAddr); err != nil {
			_ = ln.Close()
			arlReleaseListenLock(lockPath)
			h.close()
			return nil, err
		}
		if _, ok := addrMap[id]; !ok {
			_, port, splitErr := net.SplitHostPort(ln.Addr().String())
			if splitErr != nil {
				arlUnregisterListenAddr(actualAddr)
				_ = ln.Close()
				h.close()
				return nil, splitErr
			}
			addrMap[id] = net.JoinHostPort(dialHost, port)
		}
		h.lnByID[id] = ln
		h.lockPaths[id] = lockPath
		h.wg.Add(1)
		go h.acceptLoop(id, ln)
	}
	if len(addrMap) < n {
		h.close()
		return nil, fmt.Errorf("arladkr mvba tcp: incomplete addresses have=%d need=%d", len(addrMap), n)
	}
	h.addrByID = addrMap
	return h, nil
}

func (h *arladkrTCPHub) acceptLoop(id int, ln net.Listener) {
	defer h.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-h.closed:
				return
			default:
				continue
			}
		}
		go h.readConn(id, conn)
	}
}

func (h *arladkrTCPHub) readConn(id int, conn net.Conn) {
	defer conn.Close()
	for {
		select {
		case <-h.closed:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(h.readTO))
		var lenBuf [4]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		bodyLen := binary.BigEndian.Uint32(lenBuf[:])
		if bodyLen > 16*1024*1024 {
			return
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		h.recordRecvBytes(4 + len(body))
		var wire arladkrMVBAWire
		if err := gob.NewDecoder(bytes.NewReader(body)).Decode(&wire); err != nil {
			continue
		}
		h.recordEquivalentRecv(wire.Msg, 4+len(body))
		msg := dmvba.ReceivedMessage{From: wire.From, Msg: wire.Msg}
		select {
		case h.recv[id] <- msg:
		default:
			select {
			case h.recv[id] <- msg:
			case <-time.After(h.enqueueTO):
			case <-h.closed:
				return
			}
		}
	}
}

func (h *arladkrTCPHub) close() {
	select {
	case <-h.closed:
		return
	default:
		close(h.closed)
	}
	for _, ln := range h.lnByID {
		arlUnregisterListenAddr(ln.Addr().String())
		_ = ln.Close()
	}
	for _, lockPath := range h.lockPaths {
		arlReleaseListenLock(lockPath)
	}
	h.wg.Wait()
	h.closeConns()
}

func (h *arladkrTCPHub) waitForPeers(ctx context.Context, timeout time.Duration) int {
	var wg sync.WaitGroup
	reachableCh := make(chan struct{}, len(h.addrByID))
	for id, addr := range h.addrByID {
		if _, isLocal := h.lnByID[id]; isLocal {
			reachableCh <- struct{}{}
			continue
		}
		id, addr := id, addr
		_ = id
		wg.Add(1)
		go func() {
			defer wg.Done()
			deadline := time.Now().Add(timeout)
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				conn, err := net.DialTimeout("tcp", addr, h.dialTO)
				if err == nil {
					_ = conn.Close()
					reachableCh <- struct{}{}
					return
				}
				time.Sleep(50 * time.Millisecond)
			}
		}()
	}
	wg.Wait()
	close(reachableCh)
	reachable := 0
	for range reachableCh {
		reachable++
	}
	return reachable
}

// ── TCP Network ────────────────────────────────────────────────────────────

type arladkrTCPNet struct {
	id  int
	hub *arladkrTCPHub
}

type arlPoolConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func (n *arladkrTCPNet) Broadcast(msg dmvba.ProtocolMessage) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(n.hub.addrByID))
	for to := range n.hub.addrByID {
		to := to
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := n.Send(to, msg); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		return err
	}
	return nil
}

func (n *arladkrTCPNet) Send(to int, msg dmvba.ProtocolMessage) error {
	sendStart := time.Now()
	if to == n.id {
		if to < 0 || to >= len(n.hub.recv) {
			err := fmt.Errorf("arladkr mvba tcp: local recv missing for node %d", to)
			n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, err)
			return err
		}
		localMsg := dmvba.ReceivedMessage{From: n.id, Msg: msg}
		select {
		case n.hub.recv[to] <- localMsg:
			frameBytes := lenBufAndBodySize(msg, n.id)
			n.hub.recordSendRecvBytes(frameBytes)
			n.hub.recordEquivalentSend(msg, frameBytes)
			n.hub.recordEquivalentRecv(msg, frameBytes)
			n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, nil)
			return nil
		case <-time.After(n.hub.enqueueTO):
			err := fmt.Errorf("arladkr mvba tcp: local enqueue timeout %d->%d", n.id, to)
			n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, true, false, 0, err)
			return err
		}
	}
	wire := arladkrMVBAWire{From: n.id, Msg: msg}
	addr, ok := n.hub.addrByID[to]
	if !ok || addr == "" {
		err := fmt.Errorf("arladkr mvba tcp: addr missing for node %d", to)
		n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, false, false, 0, err)
		return err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(wire); err != nil {
		n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, false, false, 0, err)
		return err
	}
	body := buf.Bytes()
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	frameBytes := 4 + len(body)

	writeFrame := func(c net.Conn) error {
		_ = c.SetWriteDeadline(time.Now().Add(n.hub.writeTO))
		written, err := c.Write(frame)
		if err != nil {
			return err
		}
		if written != len(frame) {
			return io.ErrShortWrite
		}
		n.hub.recordSentBytes(frameBytes)
		n.hub.recordEquivalentSend(msg, frameBytes)
		return nil
	}

	if arlIntFromEnv("RLADKR_MVBA_CONN_REUSE", 1) != 0 {
		lockWait, poolHit, reconnects, err := n.sendWithConnReuse(to, addr, msg, writeFrame)
		n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), lockWait, false, poolHit, reconnects, err)
		return err
	}

	// Dial new connection with retry.
	reconnects := 0
	for attempt := 0; attempt < n.hub.retries; attempt++ {
		conn, err := arlDialWithBandwidth("tcp", addr, n.hub.dialTO)
		if err != nil {
			time.Sleep(time.Duration(attempt+1) * n.hub.backoff)
			continue
		}
		reconnects++
		err = writeFrame(conn)
		_ = conn.Close()
		if err == nil {
			n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, false, false, reconnects, nil)
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * n.hub.backoff)
	}
	err := fmt.Errorf("arladkr mvba tcp send failed %d->%d", n.id, to)
	n.hub.recordMVBANetSend(n.id, arlMVBANetTag(msg), time.Since(sendStart), 0, false, false, reconnects, err)
	return err
}

func (h *arladkrTCPHub) recordSentBytes(n int) {
	if h == nil || h.runtime == nil {
		return
	}
	h.runtime.recordSentBytes(n)
}

func (h *arladkrTCPHub) recordRecvBytes(n int) {
	if h == nil || h.runtime == nil {
		return
	}
	h.runtime.recordRecvBytes(n)
}

func (h *arladkrTCPHub) recordSendRecvBytes(n int) {
	h.recordSentBytes(n)
	h.recordRecvBytes(n)
}

func (h *arladkrTCPHub) recordEquivalentSend(msg dmvba.ProtocolMessage, n int) {
	h.recordEquivalentBytes(msg, n, true)
}

func (h *arladkrTCPHub) recordEquivalentRecv(msg dmvba.ProtocolMessage, n int) {
	h.recordEquivalentBytes(msg, n, false)
}

func (h *arladkrTCPHub) recordEquivalentBytes(msg dmvba.ProtocolMessage, n int, sent bool) {
	if h == nil || h.runtime == nil || n <= 0 {
		return
	}
	class := dmvba.ClassifyEquivalentMessage(msg)
	if class == dmvba.EquivalentMessageOther {
		if sent {
			h.runtime.recordNamedSentBytes("mvba_other", n)
		} else {
			h.runtime.recordNamedRecvBytes("mvba_other", n)
		}
		return
	}
	name := "mvba_" + string(class)
	if sent {
		h.runtime.recordNamedSentBytes(name, n)
	} else {
		h.runtime.recordNamedRecvBytes(name, n)
	}
}

func lenBufAndBodySize(msg dmvba.ProtocolMessage, from int) int {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(arladkrMVBAWire{From: from, Msg: msg}); err != nil {
		return 0
	}
	return 4 + buf.Len()
}

func arlMVBANetTag(msg dmvba.ProtocolMessage) string {
	if msg.Tag == dmvba.TagACSMVBA {
		if inner, ok := msg.Body.(dmvba.ProtocolMessage); ok {
			return string(msg.Tag) + "/" + string(inner.Tag)
		}
	}
	return string(msg.Tag)
}

func (h *arladkrTCPHub) recordMVBANetSend(
	id int,
	tag string,
	sendDur time.Duration,
	lockWait time.Duration,
	local bool,
	poolHit bool,
	reconnects int,
	err error,
) {
}

func arlMVBAPoolLanes(n int) int {
	if raw := strings.TrimSpace(os.Getenv("RLADKR_MVBA_CONN_LANES")); raw != "" {
		lanes := arlIntFromEnv("RLADKR_MVBA_CONN_LANES", 1)
		if lanes < 1 {
			return 1
		}
		if lanes > 8 {
			return 8
		}
		return lanes
	}
	switch {
	case n >= 128:
		return 8
	case n >= 64:
		return 4
	case n >= 16:
		return 2
	default:
		return 1
	}
}

func defaultArlMVBAReadTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 180 * time.Second
	case n >= 128:
		return 90 * time.Second
	default:
		return 45 * time.Second
	}
}

func arlMVBAPoolKey(to int, addr string, msg dmvba.ProtocolMessage, lanes int) string {
	if lanes <= 1 {
		return fmt.Sprintf("%d|%s", to, addr)
	}
	return fmt.Sprintf("%d|%s#lane=%d", to, addr, arlMVBALane(msg, lanes))
}

func arlMVBALane(msg dmvba.ProtocolMessage, lanes int) int {
	if lanes <= 1 {
		return 0
	}
	tag := msg.Tag
	leader := msg.Leader
	round := msg.Round
	if msg.Tag == dmvba.TagACSMVBA {
		if inner, ok := msg.Body.(dmvba.ProtocolMessage); ok {
			tag = inner.Tag
			leader = inner.Leader
			round = inner.Round
		}
	}
	h := uint32(2166136261)
	for _, b := range []byte(tag) {
		h ^= uint32(b)
		h *= 16777619
	}
	h ^= uint32(leader + 0x9e3779b9)
	h *= 16777619
	h ^= uint32(round + 0x85ebca6b)
	h *= 16777619
	return int(h % uint32(lanes))
}

func (n *arladkrTCPNet) sendWithConnReuse(to int, addr string, msg dmvba.ProtocolMessage, writeFrame func(net.Conn) error) (time.Duration, bool, int, error) {
	var lockWait time.Duration
	poolHit := false
	reconnects := 0
	poolKey := arlMVBAPoolKey(to, addr, msg, n.hub.poolLanes)
	n.hub.poolMu.Lock()
	if n.hub.conns == nil {
		n.hub.conns = make(map[string]*arlPoolConn)
	}
	pc, ok := n.hub.conns[poolKey]
	if ok {
		poolHit = true
		lockStart := time.Now()
		pc.mu.Lock()
		lockWait += time.Since(lockStart)
		n.hub.poolMu.Unlock()
		if err := writeFrame(pc.conn); err == nil {
			pc.mu.Unlock()
			return lockWait, poolHit, reconnects, nil
		}
		_ = pc.conn.Close()
		pc.mu.Unlock()
		n.hub.poolMu.Lock()
		delete(n.hub.conns, poolKey)
	}
	n.hub.poolMu.Unlock()
	for attempt := 0; attempt < n.hub.retries; attempt++ {
		conn, err := arlDialWithBandwidth("tcp", addr, n.hub.dialTO)
		if err != nil {
			time.Sleep(time.Duration(attempt+1) * n.hub.backoff)
			continue
		}
		reconnects++
		if err := writeFrame(conn); err == nil {
			n.hub.poolMu.Lock()
			if n.hub.conns == nil {
				n.hub.conns = make(map[string]*arlPoolConn)
			}
			if _, exists := n.hub.conns[poolKey]; !exists {
				n.hub.conns[poolKey] = &arlPoolConn{conn: conn}
				n.hub.poolMu.Unlock()
			} else {
				n.hub.poolMu.Unlock()
				_ = conn.Close()
			}
			return lockWait, poolHit, reconnects, nil
		}
		_ = conn.Close()
		time.Sleep(time.Duration(attempt+1) * n.hub.backoff)
	}
	return lockWait, poolHit, reconnects, fmt.Errorf("arladkr mvba tcp send failed %d->%d", n.id, to)
}

func (h *arladkrTCPHub) closeConns() {
	h.poolMu.Lock()
	defer h.poolMu.Unlock()
	for key, pc := range h.conns {
		pc.mu.Lock()
		_ = pc.conn.Close()
		pc.mu.Unlock()
		delete(h.conns, key)
	}
}

// ── MVBA runner ────────────────────────────────────────────────────────────

type arladkrMVBAPredicate func(proposer int, payload []byte) bool

type arladkrMVBATCPSession struct {
	n, f, maxRounds               int
	sid, hint                     string
	localIDs                      []int
	recv                          []chan dmvba.ReceivedMessage
	hub                           *arladkrTCPHub
	highSigner, lowSigner         *tblsThresholdSigner
	spbcTimeout, routeSendTimeout time.Duration
	peerWaitLatency               time.Duration
}

func runArladkrMVBACCommonSubsetTCPInstance(
	ctx context.Context,
	cfg Config,
	instance string,
	payload []byte,
	predicate arladkrMVBAPredicate,
) ([][]byte, time.Duration, error) {
	return runArladkrMVBACCommonSubsetTCPInstanceWithSigners(ctx, cfg, instance, payload, predicate, nil, nil)
}

func runArladkrMVBACCommonSubsetTCPInstanceWithSigners(
	ctx context.Context,
	cfg Config,
	instance string,
	payload []byte,
	predicate arladkrMVBAPredicate,
	highSigner, lowSigner *tblsThresholdSigner,
) ([][]byte, time.Duration, error) {
	session, err := newArladkrMVBATCPSession(ctx, cfg, instance, predicate != nil, highSigner, lowSigner)
	if err != nil {
		return nil, 0, err
	}
	defer session.hub.close()

	outs := make([][][]byte, session.n)
	errs := make([]error, session.n)
	var wg sync.WaitGroup
	for _, i := range session.localIDs {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			signer := &mvbaDomainSigner{member: i, high: session.highSigner, low: session.lowSigner}
			neti := &arladkrTCPNet{id: i, hub: session.hub}
			var mvbaPredicate func(int, dmvba.ProposalValue) bool
			if predicate != nil {
				mvbaPredicate = func(proposer int, value dmvba.ProposalValue) bool {
					return value.Round == 1 && value.Hint == session.hint && predicate(proposer, value.Payload)
				}
			}
			vec, runErr := dmvba.RunMVBACCommonSubset(ctx,
				dmvba.Config{SID: session.sid, ID: i, N: session.n, F: session.f,
					MaxRounds: session.maxRounds, WaitSPBCTimeout: session.spbcTimeout,
					RouteSendTimeout: session.routeSendTimeout, UseEquivalentPath: true},
				neti, signer, session.recv[i],
				dmvba.ProposalValue{Payload: payload, Round: 1, Hint: session.hint}, mvbaPredicate,
			)
			if runErr == nil {
				selected := selectAgreedPayloads(vec, 1, session.hint, predicate)
				if predicate != nil && len(selected) < session.n-session.f {
					runErr = fmt.Errorf("common-subset output has too few valid proposals: have=%d need=%d",
						len(selected), session.n-session.f)
				} else {
					outs[i] = selected
				}
			}
			errs[i] = runErr
		}()
	}
	wg.Wait()
	for _, i := range session.localIDs {
		if errs[i] != nil {
			return nil, session.peerWaitLatency, fmt.Errorf("arladkr MVBA common-subset node %d: %w", i, errs[i])
		}
		if len(outs[i]) > 0 {
			return outs[i], session.peerWaitLatency, nil
		}
	}
	return nil, session.peerWaitLatency, fmt.Errorf("arladkr MVBA common-subset: no output")
}

func runArladkrMVBADirectTCPInstance(
	ctx context.Context, cfg Config, instance string, payload []byte, predicate arladkrMVBAPredicate,
	highSigner, lowSigner *tblsThresholdSigner,
) ([]byte, time.Duration, error) {
	localIDs := sortedUnique(cfg.LocalNodeIDs)
	if len(localIDs) == 0 {
		localIDs = sortedUnique(cfg.OldCommittee)
	}
	if predicate == nil || len(localIDs) != 1 || !predicate(localIDs[0], payload) {
		return nil, 0, fmt.Errorf("arladkr direct MVBA rejected local payload")
	}
	session, err := newArladkrMVBATCPSession(ctx, cfg, instance, true, highSigner, lowSigner)
	if err != nil {
		return nil, 0, err
	}
	defer session.hub.close()

	i := session.localIDs[0]
	signer := &mvbaDomainSigner{member: i, high: session.highSigner, low: session.lowSigner}
	node, err := dmvba.NewDumboMVBA(
		dmvba.Config{SID: session.sid, ID: i, N: session.n, F: session.f,
			MaxRounds: session.maxRounds, WaitSPBCTimeout: session.spbcTimeout,
			RouteSendTimeout: session.routeSendTimeout, UseEquivalentPath: true,
			ValidatePayload: func(candidate []byte) bool { return predicate(i, candidate) }},
		&arladkrTCPNet{id: i, hub: session.hub}, signer, nil, session.recv[i], nil,
	)
	if err != nil {
		return nil, session.peerWaitLatency, err
	}
	decided, err := node.Run(ctx, dmvba.ProposalValue{Payload: payload, Round: 1, Hint: session.hint})
	if err != nil {
		return nil, session.peerWaitLatency, fmt.Errorf("arladkr direct MVBA node %d: %w", i, err)
	}
	if !predicate(i, decided.Payload) {
		return nil, session.peerWaitLatency, fmt.Errorf("arladkr direct MVBA returned invalid payload")
	}
	return append([]byte(nil), decided.Payload...), session.peerWaitLatency, nil
}

func newArladkrMVBATCPSession(
	ctx context.Context, cfg Config, instance string, requireSingleLocal bool,
	highSigner, lowSigner *tblsThresholdSigner,
) (*arladkrMVBATCPSession, error) {
	n := len(cfg.OldCommittee)
	f := cfg.FOld
	mvbaSID, err := arlMVBAInstanceSID(fmt.Sprintf("%s|epoch=%d", cfg.SID, cfg.Epoch), instance)
	if err != nil {
		return nil, err
	}
	hint := "arladkr-mvba-tcp-cs"
	if instance != "" {
		hint = instance
	}
	localIDs := sortedUnique(cfg.LocalNodeIDs)
	if len(localIDs) == 0 {
		localIDs = sortedUnique(cfg.OldCommittee)
	}
	for _, id := range localIDs {
		if id < 0 || id >= n {
			return nil, fmt.Errorf("arladkr mvba tcp requires old node IDs 0..n-1: %d", id)
		}
	}
	if requireSingleLocal && len(localIDs) != 1 {
		return nil, fmt.Errorf(
			"predicate-bearing MVBA requires exactly one local old node, got %d",
			len(localIDs),
		)
	}

	if highSigner == nil && cfg.runtime != nil {
		highSigner = cfg.runtime.lockSigner
	}
	if lowSigner == nil && cfg.runtime != nil {
		lowSigner = cfg.runtime.coinSigner
	}
	if highSigner == nil || lowSigner == nil || highSigner.Threshold() != n-f || lowSigner.Threshold() != f+1 {
		return nil, fmt.Errorf("arladkr MVBA domain-routed threshold runtime is unavailable")
	}

	recv := make([]chan dmvba.ReceivedMessage, n)
	for i := range recv {
		recv[i] = make(chan dmvba.ReceivedMessage, 65536)
	}

	hub, err := newArladkrTCPHub(cfg, recv)
	if err != nil {
		return nil, fmt.Errorf("arladkr mvba tcp hub: %w", err)
	}

	// Wait for peers — longer timeout at larger n.
	peerStart := time.Now()
	peerTimeout := 60 * time.Second
	if n > 30 {
		peerTimeout = 120 * time.Second
	}
	peerWaitDefault := 100 * time.Millisecond
	switch {
	case n >= 127:
		peerWaitDefault = 12 * time.Second
	case n >= 96:
		peerWaitDefault = 10 * time.Second
	case n >= 64:
		peerWaitDefault = 8 * time.Second
	case n >= 32:
		peerWaitDefault = 1 * time.Second
	}
	peerTimeout = arlDurationFromEnv("RLADKR_MVBA_PEER_WAIT_MS", peerWaitDefault)
	peerProbeTimeout := arlDurationFromEnv("RLADKR_MVBA_PEER_PROBE_TIMEOUT_MS", 1500*time.Millisecond)
	peerTarget := n - f
	switch strings.ToLower(strings.TrimSpace(os.Getenv("RLADKR_MVBA_PEER_WAIT_TARGET"))) {
	case "all", "full":
		peerTarget = n
	case "", "quorum":
		peerTarget = n - f
	}
	deadline := time.Now().Add(peerTimeout)
	for time.Now().Before(deadline) {
		if reachable := hub.waitForPeers(ctx, peerProbeTimeout); reachable >= peerTarget {
			break
		}
		select {
		case <-ctx.Done():
			hub.close()
			return nil, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	peerWaitLatency := time.Since(peerStart)

	maxR := f + 4
	if maxR < 4 {
		maxR = 4
	}
	spbcTimeout := cfg.WaitSPBCTimeout
	if spbcTimeout <= 0 {
		switch {
		case n >= 64:
			spbcTimeout = 20 * time.Second
		case n >= 32:
			spbcTimeout = 6 * time.Second
		default:
			spbcTimeout = 2 * time.Second
		}
	}
	routeSendTimeout := cfg.RouteSendTimeout
	if routeSendTimeout <= 0 {
		switch {
		case n >= 64:
			routeSendTimeout = 5 * time.Second
		case n >= 32:
			routeSendTimeout = 1500 * time.Millisecond
		default:
			routeSendTimeout = 500 * time.Millisecond
		}
	}

	return &arladkrMVBATCPSession{n: n, f: f, maxRounds: maxR, sid: mvbaSID, hint: hint,
		localIDs: localIDs, recv: recv, hub: hub, highSigner: highSigner, lowSigner: lowSigner,
		spbcTimeout: spbcTimeout, routeSendTimeout: routeSendTimeout, peerWaitLatency: peerWaitLatency}, nil
}

func arlMVBAInstanceSID(base, instance string) (string, error) {
	if strings.TrimSpace(base) == "" {
		return "", fmt.Errorf("empty ARL MVBA SID")
	}
	suffix := "-arl-mvba-tcp-cs"
	if instance == "" {
		return base + suffix, nil
	}
	for _, r := range instance {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return "", fmt.Errorf("invalid ARL MVBA instance label")
		}
	}
	return base + "|instance=" + instance + suffix, nil
}

func selectAgreedPayloads(
	vec []*dmvba.ProposalValue,
	expectedRound int,
	expectedHint string,
	predicate arladkrMVBAPredicate,
) [][]byte {
	out := make([][]byte, 0, len(vec))
	for proposer, pv := range vec {
		if pv == nil || len(pv.Payload) == 0 || pv.Round != expectedRound || pv.Hint != expectedHint ||
			(predicate != nil && !predicate(proposer, pv.Payload)) {
			continue
		}
		out = append(out, append([]byte(nil), pv.Payload...))
	}
	return out
}

// ── Key derivation ─────────────────────────────────────────────────────────

// ── Helpers ────────────────────────────────────────────────────────────────

func parseArlAddrMap(raw string) map[int]string {
	out := make(map[int]string)
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		kv := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(kv) != 2 {
			continue
		}
		id, err := strconv.Atoi(strings.TrimSpace(kv[0]))
		if err != nil {
			continue
		}
		addr := strings.TrimSpace(kv[1])
		if addr == "" {
			continue
		}
		out[id] = addr
	}
	return out
}

func parseArlNodeIDs(raw string) map[int]struct{} {
	out := make(map[int]struct{})
	for _, item := range strings.Split(strings.TrimSpace(raw), ",") {
		id, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil {
			continue
		}
		out[id] = struct{}{}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func arlNodeIDSet(ids []int) map[int]struct{} {
	if len(ids) == 0 {
		return nil
	}
	out := make(map[int]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}

func arlDurationFromEnv(name string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

func firstNonEmptyArl(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func arlIntFromEnv(name string, def int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
