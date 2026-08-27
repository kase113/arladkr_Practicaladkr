package core

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tcpMessageFrameVersion    = byte(1)
	tcpMessageFrameFixedBytes = 1 + 4 + 4 + 4 + 4
	tcpMessageMaxTagBytes     = 1 << 12
)

func listenerReadyMarkerPath(dir string, nodeID int) string {
	return filepath.Join(dir, fmt.Sprintf("node-%04d.ready", nodeID))
}

func writeListenerReadyMarker(dir string, nodeID int, addr string) error {
	if strings.TrimSpace(dir) == "" {
		return nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	payload := []byte(strings.TrimSpace(addr) + "\n")
	return os.WriteFile(listenerReadyMarkerPath(dir, nodeID), payload, 0o644)
}

func waitForListenerReadyMarkers(dir string, nodeCount int, timeout time.Duration) error {
	if strings.TrimSpace(dir) == "" || nodeCount <= 0 {
		return nil
	}
	deadline := time.Now().Add(timeout)
	for {
		ready, err := countListenerReadyMarkers(dir)
		if err != nil {
			return fmt.Errorf("read listener-ready barrier: %w", err)
		}
		if ready >= nodeCount {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("listener-ready barrier timeout: ready=%d/%d dir=%s", ready, nodeCount, dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func countListenerReadyMarkers(dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	ready := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "node-") || !strings.HasSuffix(name, ".ready") {
			continue
		}
		idText := strings.TrimSuffix(strings.TrimPrefix(name, "node-"), ".ready")
		id, parseErr := strconv.Atoi(idText)
		if parseErr != nil || id < 0 {
			continue
		}
		ready++
	}
	return ready, nil
}

type tcpLoopbackTransport struct {
	mu        sync.RWMutex
	inbox     map[int]chan Message
	addrByID  map[int]string
	listeners map[int]net.Listener
	poolMu    sync.Mutex
	conns     map[string]*tcpLoopbackPoolConn
	closed    chan struct{}
	wg        sync.WaitGroup
	dialTO    time.Duration
	writeTO   time.Duration
	acceptTO  time.Duration
	enqueueTO time.Duration
	runtime   *runtimeCrypto
	reuseConn bool
	bulkLanes int
}

type tcpLoopbackPoolConn struct {
	conn net.Conn
	mu   sync.Mutex
}

func waitForRemoteNodeReadiness(cfg Config, t *tcpLoopbackTransport, nodes []int) error {
	readinessNodes := sortedUnique(cfg.OldCommittee)
	if len(readinessNodes) == 0 {
		readinessNodes = sortedUnique(nodes)
	}
	localSet := nodeSet(filterNodeIDs(cfg.LocalNodeIDs, readinessNodes))
	if len(localSet) == 0 {
		return nil
	}
	ordered := readinessNodes
	faults := cfg.FOld
	if faults <= 0 && cfg.OldFaults > 0 {
		faults = cfg.OldFaults
	}
	required := len(ordered) - faults
	if required <= 0 {
		required = 1
	}
	deadline := time.Now().Add(3 * cfg.WaitSPBCTimeout)
	ready := make(map[int]struct{}, len(localSet))
	for id := range localSet {
		ready[id] = struct{}{}
	}
	configuredRemote := false
	for _, id := range ordered {
		if _, ok := ready[id]; ok {
			continue
		}
		t.mu.RLock()
		addr := t.addrByID[id]
		t.mu.RUnlock()
		if strings.TrimSpace(addr) != "" {
			configuredRemote = true
			break
		}
	}
	if !configuredRemote {
		return nil
	}
	var lastErr error
	for {
		for _, id := range ordered {
			if _, ok := ready[id]; ok {
				continue
			}
			t.mu.RLock()
			addr := t.addrByID[id]
			t.mu.RUnlock()
			if strings.TrimSpace(addr) == "" {
				continue
			}
			conn, err := net.DialTimeout("tcp", addr, t.dialTO)
			if err == nil {
				_ = conn.Close()
				ready[id] = struct{}{}
				continue
			}
			lastErr = fmt.Errorf("remote node %d listener not ready at %s: %w", id, addr, err)
		}
		if len(ready) >= required {
			return nil
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("remote readiness timeout: ready=%d/%d: %w", len(ready), required, lastErr)
			}
			return fmt.Errorf("remote readiness timeout: ready=%d/%d", len(ready), required)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func NewTCPLoopbackTransportWithOptions(
	cfg Config,
	nodes []int,
	localNodes []int,
	buffer int,
	bindHost string,
	basePort int,
) (agreementTransport, error) {
	if buffer <= 0 {
		buffer = 1024
	}
	t := &tcpLoopbackTransport{
		inbox:     make(map[int]chan Message, len(nodes)),
		addrByID:  make(map[int]string, len(nodes)),
		listeners: make(map[int]net.Listener, len(nodes)),
		conns:     make(map[string]*tcpLoopbackPoolConn),
		closed:    make(chan struct{}),
		dialTO:    durationEnvMs("RLADKR_TCP_DIAL_TIMEOUT_MS", defaultTransportDialTimeout(len(nodes))),
		writeTO:   durationEnvMs("RLADKR_TCP_WRITE_TIMEOUT_MS", defaultTransportWriteTimeout(len(nodes))),
		acceptTO:  durationEnvMs("RLADKR_TCP_ACCEPT_READ_TIMEOUT_MS", defaultTransportAcceptTimeout(len(nodes))),
		enqueueTO: durationEnvMs("RLADKR_TCP_ENQUEUE_TIMEOUT_MS", defaultTransportEnqueueTimeout(len(nodes))),
		runtime:   cfg.runtime,
		reuseConn: !strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_TCP_CONN_REUSE")), "0") &&
			!strings.EqualFold(strings.TrimSpace(os.Getenv("RLADKR_TCP_CONN_REUSE")), "false"),
		bulkLanes: tcpBulkPoolLaneCount(),
	}
	addrOverrides := parseAddrOverrideMap(os.Getenv("RLADKR_NODE_ADDRS"))
	ordered := append([]int(nil), nodes...)
	sort.Ints(ordered)
	localSet := make(map[int]struct{}, len(localNodes))
	for _, id := range filterNodeIDs(localNodes, nodes) {
		localSet[id] = struct{}{}
	}
	if len(localSet) == 0 {
		for _, id := range ordered {
			localSet[id] = struct{}{}
		}
	}
	dialHost := resolveDialHost(bindHost)
	listenerReadyDir := strings.TrimSpace(os.Getenv("RLADKR_LISTENER_READY_DIR"))
	listenerReadyNodeCount, _ := strconv.Atoi(strings.TrimSpace(os.Getenv("RLADKR_LISTENER_READY_NODE_COUNT")))
	listenerReadyTimeout := durationEnvMs("RLADKR_LISTENER_READY_TIMEOUT_MS", 120000*time.Millisecond)
	// The shared marker barrier counts old committee nodes. Receiver
	// listeners are colocated with their old node and do not add quorum votes.
	oldNodeSet := nodeSet(cfg.OldCommittee)
	for _, id := range ordered {
		if _, isLocal := localSet[id]; isLocal {
			addr := fmt.Sprintf("%s:0", bindHost)
			if ov, ok := addrOverrides[id]; ok {
				// Extract port from the override (which carries the
				// public IP), but listen on bindHost so the socket
				// actually binds on EC2 instances whose interfaces
				// don't own the public IP.
				if _, ovPort, e := net.SplitHostPort(ov); e == nil {
					addr = net.JoinHostPort(bindHost, ovPort)
				}
			}
			if basePort > 0 {
				port := basePort + id
				addr = fmt.Sprintf("%s:%d", bindHost, port)
			}
			ln, err := arlListenWithRetry(
				"tcp",
				addr,
				durationEnvMs("RLADKR_TCP_LISTEN_RETRY_TIMEOUT_MS", 5*time.Second),
				durationEnvMs("RLADKR_TCP_LISTEN_RETRY_BACKOFF_MS", 100*time.Millisecond),
			)
			if err != nil {
				_ = t.Close()
				return nil, err
			}
			t.listeners[id] = ln
			_, port, splitErr := net.SplitHostPort(ln.Addr().String())
			if splitErr != nil {
				_ = t.Close()
				return nil, splitErr
			}
			if ov, ok := addrOverrides[id]; ok {
				t.addrByID[id] = ov
			} else {
				t.addrByID[id] = net.JoinHostPort(dialHost, port)
			}
			t.inbox[id] = make(chan Message, buffer)
			t.wg.Add(1)
			go t.acceptLoop(id, ln)
			if len(cfg.OldCommittee) == 0 {
				if err := writeListenerReadyMarker(listenerReadyDir, id, t.addrByID[id]); err != nil {
					_ = t.Close()
					return nil, err
				}
			} else if _, isOld := oldNodeSet[id]; isOld {
				if err := writeListenerReadyMarker(listenerReadyDir, id, t.addrByID[id]); err != nil {
					_ = t.Close()
					return nil, err
				}
			}
			continue
		}
		if ov, ok := addrOverrides[id]; ok {
			t.addrByID[id] = ov
			continue
		}
		if basePort > 0 {
			t.addrByID[id] = net.JoinHostPort(dialHost, strconv.Itoa(basePort+id))
		}
	}
	if err := waitForListenerReadyMarkers(listenerReadyDir, listenerReadyNodeCount, listenerReadyTimeout); err != nil {
		_ = t.Close()
		return nil, err
	}
	if err := waitForRemoteNodeReadiness(Config{
		OldCommittee:      append([]int(nil), cfg.OldCommittee...),
		FOld:              cfg.FOld,
		OldFaults:         cfg.OldFaults,
		LocalNodeIDs:      append([]int(nil), localNodes...),
		WaitSPBCTimeout:   10 * time.Second,
		SendRetryMax:      3,
		SendRetryBackoff:  30 * time.Millisecond,
		AgreementBindHost: bindHost,
	}, t, ordered); err != nil {
		_ = t.Close()
		return nil, err
	}
	return t, nil
}

func resolveDialHost(bindHost string) string {
	override := os.Getenv("RLADKR_DIAL_HOST")
	if override != "" {
		return override
	}
	switch bindHost {
	case "", "0.0.0.0", "::":
		return "127.0.0.1"
	default:
		return bindHost
	}
}

func (t *tcpLoopbackTransport) RecvChan(id int) (<-chan Message, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	ch, ok := t.inbox[id]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", id)
	}
	return ch, nil
}

func (t *tcpLoopbackTransport) Send(msg Message) error {
	frame, err := tcpMessageFrame(msg)
	if err != nil {
		return err
	}
	wireBytes := len(frame)
	t.mu.RLock()
	addr, ok := t.addrByID[msg.To]
	ch, local := t.inbox[msg.To]
	t.mu.RUnlock()
	if !ok {
		return fmt.Errorf("node %d not registered", msg.To)
	}
	if local {
		select {
		case ch <- msg:
			t.recordSendRecvBytes(wireBytes)
			return nil
		case <-time.After(t.enqueueTO):
			return fmt.Errorf("local enqueue timeout for node %d", msg.To)
		}
	}
	if t.reuseConn {
		return t.sendRemotePooled(addr, msg, frame, wireBytes)
	}
	return t.sendRemoteShortConn(addr, msg, frame, wireBytes)
}

func (t *tcpLoopbackTransport) sendRemoteShortConn(addr string, msg Message, frame []byte, wireBytes int) error {
	conn, err := arlDialWithBandwidth("tcp", addr, t.dialTO)
	if err != nil {
		return err
	}
	defer conn.Close()
	return t.sendRemoteOnConn(conn, msg, frame, wireBytes)
}

func (t *tcpLoopbackTransport) sendRemotePooled(addr string, msg Message, frame []byte, wireBytes int) error {
	key := tcpLoopbackPoolKeyForPayload(msg.From, msg.To, addr, msg.Tag, msg.Body, t.bulkLanes)
	t.poolMu.Lock()
	if t.conns == nil {
		t.conns = make(map[string]*tcpLoopbackPoolConn)
	}
	pc, ok := t.conns[key]
	if ok {
		pc.mu.Lock()
		t.poolMu.Unlock()
		if err := t.sendRemoteOnConn(pc.conn, msg, frame, wireBytes); err == nil {
			pc.mu.Unlock()
			return nil
		}
		_ = pc.conn.Close()
		pc.mu.Unlock()
		t.poolMu.Lock()
		if t.conns[key] == pc {
			delete(t.conns, key)
		}
		t.poolMu.Unlock()
	} else {
		t.poolMu.Unlock()
	}

	conn, err := arlDialWithBandwidth("tcp", addr, t.dialTO)
	if err != nil {
		return err
	}
	pc = &tcpLoopbackPoolConn{conn: conn}
	pc.mu.Lock()
	if err := t.sendRemoteOnConn(pc.conn, msg, frame, wireBytes); err != nil {
		pc.mu.Unlock()
		_ = conn.Close()
		return err
	}
	pc.mu.Unlock()

	t.poolMu.Lock()
	if _, exists := t.conns[key]; exists {
		t.poolMu.Unlock()
		_ = conn.Close()
		return nil
	}
	t.conns[key] = pc
	t.poolMu.Unlock()
	return nil
}

func (t *tcpLoopbackTransport) sendRemoteOnConn(conn net.Conn, _ Message, frame []byte, wireBytes int) error {
	_ = conn.SetWriteDeadline(time.Now().Add(t.writeTO))
	if err := writeTCPFrame(conn, frame); err != nil {
		return err
	}
	t.recordSentBytes(wireBytes)
	return nil
}

func tcpLoopbackPoolKey(from int, to int, addr string) string {
	return tcpLoopbackPoolKeyForTag(from, to, addr, "")
}

func tcpLoopbackPoolKeyForTag(from int, to int, addr, tag string) string {
	return tcpLoopbackPoolKeyForLane(from, to, addr, tcpLoopbackLaneForTag(tag))
}

func tcpLoopbackPoolKeyForPayload(from, to int, addr, tag string, payload []byte, bulkLanes int) string {
	lane := tcpLoopbackLaneForTag(tag)
	if lane != 0 && bulkLanes > 1 {
		h := fnv.New32a()
		_, _ = h.Write(payload)
		lane += int(h.Sum32() % uint32(bulkLanes))
	}
	return tcpLoopbackPoolKeyForLane(from, to, addr, lane)
}

func tcpLoopbackPoolKeyForLane(from, to int, addr string, lane int) string {
	return fmt.Sprintf("%d->%d@%s#lane=%d", from, to, addr, lane)
}

func tcpBulkPoolLaneCount() int {
	const defaultLanes = 3
	raw := strings.TrimSpace(os.Getenv("RLADKR_TCP_BULK_LANES"))
	if raw == "" {
		return defaultLanes
	}
	lanes, err := strconv.Atoi(raw)
	if err != nil || lanes < 1 {
		return defaultLanes
	}
	if lanes > 8 {
		return 8
	}
	return lanes
}

func tcpLoopbackLaneForTag(tag string) int {
	switch tag {
	case cvTagComponentInit, cvTagComponentLeaf, cvTagComponentGet, cvTagRecoverGet,
		cvTagRecoverShard, cvTagAPDBStoreV2, cvTagAPDBRecoverGetV2,
		cvTagAPDBRecoverStoreV2, cvTagAggregateRecoverGetV2, cvTagAggregateRecoverCancelV2, cvTagAggregateRecoverStoreV2,
		cvTagAggregatePayloadGetV2, cvTagAggregatePayloadV2,
		cvTagAggregateShareV2, cvTagCertifiedCandidateV2:
		return 1
	default:
		return 0
	}
}

func (t *tcpLoopbackTransport) Broadcast(from int, to []int, tag string, body []byte) {
	var wg sync.WaitGroup
	for _, id := range to {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = t.Send(Message{
				From: from,
				To:   id,
				Tag:  tag,
				Body: append([]byte(nil), body...),
			})
		}()
	}
	wg.Wait()
}

func (t *tcpLoopbackTransport) Close() error {
	select {
	case <-t.closed:
		return nil
	default:
		close(t.closed)
	}
	t.mu.Lock()
	for _, ln := range t.listeners {
		_ = ln.Close()
	}
	t.mu.Unlock()
	t.closePooledConns()
	t.wg.Wait()
	return nil
}

func (t *tcpLoopbackTransport) closePooledConns() {
	t.poolMu.Lock()
	defer t.poolMu.Unlock()
	for key, pc := range t.conns {
		pc.mu.Lock()
		_ = pc.conn.Close()
		pc.mu.Unlock()
		delete(t.conns, key)
	}
}

func (t *tcpLoopbackTransport) recordSentBytes(n int) {
	if t == nil || t.runtime == nil {
		return
	}
	t.runtime.recordSentBytes(n)
}

func (t *tcpLoopbackTransport) recordRecvBytes(n int) {
	if t == nil || t.runtime == nil {
		return
	}
	t.runtime.recordRecvBytes(n)
}

func (t *tcpLoopbackTransport) recordSendRecvBytes(n int) {
	t.recordSentBytes(n)
	t.recordRecvBytes(n)
}

func tcpMessageFrame(msg Message) ([]byte, error) {
	if msg.From < 0 || msg.To < 0 || uint64(msg.From) > uint64(^uint32(0)) ||
		uint64(msg.To) > uint64(^uint32(0)) || len(msg.Tag) == 0 ||
		len(msg.Tag) > tcpMessageMaxTagBytes || len(msg.Body) > cvMaxNetworkPayloadBytes+cvNetworkEnvelopeFixedBytes+cvMaxNetworkEnvelopeSIDBytes+cvNetworkAuthBytes {
		return nil, fmt.Errorf("invalid TCP message frame")
	}
	frame := make([]byte, tcpMessageFrameFixedBytes+len(msg.Tag)+len(msg.Body))
	frame[0] = tcpMessageFrameVersion
	binary.BigEndian.PutUint32(frame[1:5], uint32(msg.From))
	binary.BigEndian.PutUint32(frame[5:9], uint32(msg.To))
	binary.BigEndian.PutUint32(frame[9:13], uint32(len(msg.Tag)))
	binary.BigEndian.PutUint32(frame[13:17], uint32(len(msg.Body)))
	copy(frame[tcpMessageFrameFixedBytes:], msg.Tag)
	copy(frame[tcpMessageFrameFixedBytes+len(msg.Tag):], msg.Body)
	return frame, nil
}

func readTCPMessageFrame(reader io.Reader) (Message, int, error) {
	var header [tcpMessageFrameFixedBytes]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Message{}, 0, err
	}
	if header[0] != tcpMessageFrameVersion {
		return Message{}, 0, fmt.Errorf("invalid TCP message frame version")
	}
	tagBytes := int(binary.BigEndian.Uint32(header[9:13]))
	bodyBytes := int(binary.BigEndian.Uint32(header[13:17]))
	maximumBody := cvMaxNetworkPayloadBytes + cvNetworkEnvelopeFixedBytes + cvMaxNetworkEnvelopeSIDBytes + cvNetworkAuthBytes
	if tagBytes <= 0 || tagBytes > tcpMessageMaxTagBytes || bodyBytes < 0 || bodyBytes > maximumBody {
		return Message{}, 0, fmt.Errorf("invalid TCP message frame lengths")
	}
	payload := make([]byte, tagBytes+bodyBytes)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Message{}, 0, err
	}
	return Message{
		From: int(binary.BigEndian.Uint32(header[1:5])),
		To:   int(binary.BigEndian.Uint32(header[5:9])),
		Tag:  string(payload[:tagBytes]),
		Body: payload[tagBytes:],
	}, len(header) + len(payload), nil
}

func writeTCPFrame(writer io.Writer, frame []byte) error {
	for len(frame) > 0 {
		written, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[written:]
	}
	return nil
}

func (t *tcpLoopbackTransport) acceptLoop(id int, ln net.Listener) {
	defer t.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-t.closed:
				return
			default:
				continue
			}
		}
		t.wg.Add(1)
		go t.handleAcceptedConn(id, conn)
	}
}

func (t *tcpLoopbackTransport) handleAcceptedConn(id int, conn net.Conn) {
	defer t.wg.Done()
	defer conn.Close()
	for {
		select {
		case <-t.closed:
			return
		default:
		}
		_ = conn.SetReadDeadline(time.Now().Add(t.acceptTO))
		msg, wireBytes, err := readTCPMessageFrame(conn)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		t.recordRecvBytes(wireBytes)
		t.mu.RLock()
		ch := t.inbox[id]
		t.mu.RUnlock()
		select {
		case ch <- msg:
		case <-t.closed:
			return
		}
	}
}

func parseAddrOverrideMap(raw string) map[int]string {
	out := make(map[int]string)
	if strings.TrimSpace(raw) == "" {
		return out
	}
	items := strings.Split(raw, ",")
	for _, item := range items {
		part := strings.TrimSpace(item)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
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

func durationEnvMs(name string, def time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return def
	}
	return time.Duration(n) * time.Millisecond
}

func defaultTransportDialTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 5 * time.Second
	case n >= 128:
		return 3 * time.Second
	default:
		return 1200 * time.Millisecond
	}
}

func defaultTransportWriteTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 5 * time.Second
	case n >= 128:
		return 3 * time.Second
	default:
		return 1200 * time.Millisecond
	}
}

func defaultTransportAcceptTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 10 * time.Second
	case n >= 128:
		return 5 * time.Second
	default:
		return 2500 * time.Millisecond
	}
}

func defaultTransportEnqueueTimeout(n int) time.Duration {
	switch {
	case n >= 192:
		return 3 * time.Second
	case n >= 128:
		return 1500 * time.Millisecond
	default:
		return 400 * time.Millisecond
	}
}
