package core

import (
	"bytes"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTCPMessageFrameRoundTrip(t *testing.T) {
	want := Message{From: 7, To: 11, Tag: apvssTagLaneOffer, Body: []byte{0, 1, 2, 255}}
	frame, err := tcpMessageFrame(want)
	if err != nil {
		t.Fatal(err)
	}
	got, wireBytes, err := readTCPMessageFrame(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if wireBytes != len(frame) || got.From != want.From || got.To != want.To ||
		got.Tag != want.Tag || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("TCP frame round trip changed message: got=%+v", got)
	}
	bad := append([]byte(nil), frame...)
	bad[0]++
	if _, _, err := readTCPMessageFrame(bytes.NewReader(bad)); err == nil {
		t.Fatal("accepted unknown TCP frame version")
	}
}

func TestTCPPoolLaneClassificationSeparatesBulkAndControl(t *testing.T) {
	if got, want := tcpLoopbackLaneForTag(cvTagAPDBStoreV2), 1; got != want {
		t.Fatalf("APDB store lane=%d want bulk lane %d", got, want)
	}
	if got, want := tcpLoopbackLaneForTag(cvTagPoolCertShareV2), 0; got != want {
		t.Fatalf("pool certificate share lane=%d want control lane %d", got, want)
	}
	control := tcpLoopbackPoolKeyForTag(1, 2, "127.0.0.1:1", cvTagPoolCertShareV2)
	bulk := tcpLoopbackPoolKeyForTag(1, 2, "127.0.0.1:1", cvTagAPDBRecoverStoreV2)
	if control == bulk {
		t.Fatal("control and bulk messages share one TCP pool key")
	}
	if tcpLoopbackPoolKeyForTag(1, 2, "127.0.0.1:1", cvTagPoolCertV2) != control {
		t.Fatal("related control messages do not share deterministic lane")
	}
}

func TestTCPBulkPoolPayloadLaneIsStableAndBounded(t *testing.T) {
	left := tcpLoopbackPoolKeyForPayload(1, 2, "127.0.0.1:1", cvTagAPDBRecoverGetV2, []byte("request-a"), 3)
	if got := tcpLoopbackPoolKeyForPayload(1, 2, "127.0.0.1:1", cvTagAPDBRecoverGetV2, []byte("request-a"), 3); got != left {
		t.Fatalf("same recovery payload selected different pool lanes: %q != %q", left, got)
	}
	for _, payload := range [][]byte{[]byte("request-a"), []byte("request-b"), []byte("request-c"), []byte("request-d")} {
		key := tcpLoopbackPoolKeyForPayload(1, 2, "127.0.0.1:1", cvTagAPDBRecoverGetV2, payload, 3)
		if !strings.Contains(key, "#lane=") {
			t.Fatalf("bulk recovery key missing lane: %q", key)
		}
	}
	control := tcpLoopbackPoolKeyForPayload(1, 2, "127.0.0.1:1", cvTagPoolCertShareV2, []byte("request-a"), 3)
	if control != tcpLoopbackPoolKeyForTag(1, 2, "127.0.0.1:1", cvTagPoolCertShareV2) {
		t.Fatalf("control payload unexpectedly changed its lane: %q", control)
	}
}

func TestTCPPooledSendReconnectsAfterBrokenConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer conn.Close()
		if _, _, readErr := readTCPMessageFrame(conn); readErr != nil {
			serverDone <- readErr
			return
		}
		serverDone <- nil
	}()
	transport := &tcpLoopbackTransport{
		conns:  make(map[string]*tcpLoopbackPoolConn),
		dialTO: time.Second, writeTO: time.Second,
	}
	msg := Message{From: 1, To: 2, Tag: "reconnect", Body: []byte("payload")}
	frame, err := tcpMessageFrame(msg)
	if err != nil {
		t.Fatal(err)
	}
	key := tcpLoopbackPoolKeyForTag(msg.From, msg.To, listener.Addr().String(), msg.Tag)
	brokenClient, brokenServer := net.Pipe()
	_ = brokenClient.Close()
	_ = brokenServer.Close()
	transport.conns[key] = &tcpLoopbackPoolConn{conn: brokenClient}
	done := make(chan error, 1)
	go func() {
		done <- transport.sendRemotePooled(listener.Addr().String(), msg, frame, len(frame))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("pooled reconnect failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pooled reconnect deadlocked")
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
	transport.closePooledConns()
}

func TestTCPRemoteSendDoesNotWaitForReceiverRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	transport := &tcpLoopbackTransport{writeTO: time.Second}
	msg := Message{From: 1, To: 2, Tag: "write-only", Body: []byte("payload")}
	frame, err := tcpMessageFrame(msg)
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan error, 1)
	go func() {
		_, _, readErr := readTCPMessageFrame(server)
		received <- readErr
	}()
	done := make(chan error, 1)
	go func() {
		done <- transport.sendRemoteOnConn(client, msg, frame, len(frame))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("remote send failed: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("remote send waited for a receiver round trip")
	}
	if err := <-received; err != nil {
		t.Fatal(err)
	}
}

func TestTCPAcceptedConnectionSurvivesIdleReadTimeout(t *testing.T) {
	client, server := net.Pipe()
	transport := &tcpLoopbackTransport{
		inbox:     map[int]chan Message{2: make(chan Message, 2)},
		closed:    make(chan struct{}),
		acceptTO:  20 * time.Millisecond,
		enqueueTO: time.Second,
	}
	transport.wg.Add(1)
	go transport.handleAcceptedConn(2, server)
	defer func() {
		close(transport.closed)
		_ = client.Close()
		transport.wg.Wait()
	}()
	send := func(body string) {
		t.Helper()
		frame, err := tcpMessageFrame(Message{From: 1, To: 2, Tag: "idle", Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeTCPFrame(client, frame); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-transport.inbox[2]:
			if string(got.Body) != body {
				t.Fatalf("received body=%q want=%q", got.Body, body)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out receiving %q", body)
		}
	}
	send("first")
	time.Sleep(3 * transport.acceptTO)
	send("second")
}

func TestTCPAcceptedConnectionAppliesInboxBackpressure(t *testing.T) {
	client, server := net.Pipe()
	inbox := make(chan Message, 1)
	transport := &tcpLoopbackTransport{
		inbox:     map[int]chan Message{2: inbox},
		closed:    make(chan struct{}),
		acceptTO:  time.Second,
		enqueueTO: 20 * time.Millisecond,
	}
	transport.wg.Add(1)
	go transport.handleAcceptedConn(2, server)
	defer func() {
		close(transport.closed)
		_ = client.Close()
		transport.wg.Wait()
	}()
	for _, body := range []string{"first", "second"} {
		frame, err := tcpMessageFrame(Message{From: 1, To: 2, Tag: "backpressure", Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		if err := writeTCPFrame(client, frame); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(3 * transport.enqueueTO)
	for _, want := range []string{"first", "second"} {
		select {
		case got := <-inbox:
			if string(got.Body) != want {
				t.Fatalf("received body=%q want=%q", got.Body, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out receiving %q", want)
		}
	}
}

func TestNormalizeConfig_FiltersAndSortsLocalNodeIDs(t *testing.T) {
	cfg := NormalizeConfig(Config{
		SID:          "local-node-normalize",
		Epoch:        1,
		OldCommittee: []int{0, 1, 2, 3},
		NewCommittee: []int{0, 1, 2, 3},
		FOld:         1,
		FNew:         1,
		LocalNodeIDs: []int{3, 99, 1, 3},
	})
	if got, want := cfg.LocalNodeIDs, []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected normalized local node ids: got=%v want=%v", got, want)
	}
}

func TestNewTCPLoopbackTransportWithOptions_RegistersOnlyLocalNodes(t *testing.T) {
	transport, err := NewTCPLoopbackTransportWithOptions(Config{}, []int{0, 1, 2, 3}, []int{1, 3}, 8, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("NewTCPLoopbackTransportWithOptions failed: %v", err)
	}
	defer transport.Close()
	if _, err := transport.RecvChan(1); err != nil {
		t.Fatalf("expected local node 1 to be registered: %v", err)
	}
	if _, err := transport.RecvChan(3); err != nil {
		t.Fatalf("expected local node 3 to be registered: %v", err)
	}
	if _, err := transport.RecvChan(0); err == nil {
		t.Fatalf("expected non-local node 0 to be absent")
	}
}

func TestParseLocalNodeIDsEnv(t *testing.T) {
	prev := os.Getenv("RLADKR_LOCAL_NODE_IDS")
	defer os.Setenv("RLADKR_LOCAL_NODE_IDS", prev)
	if err := os.Setenv("RLADKR_LOCAL_NODE_IDS", "3,1,3,9"); err != nil {
		t.Fatalf("Setenv failed: %v", err)
	}
	got := parseLocalNodeIDsEnv([]int{0, 1, 2, 3})
	if want := []int{1, 3}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed local ids: got=%v want=%v", got, want)
	}
}

func TestWaitForRemoteNodeReadiness_SucceedsOnceRemoteListenerAppears(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	done := make(chan struct{})
	go func() {
		time.Sleep(40 * time.Millisecond)
		lateLn, lateErr := net.Listen("tcp", addr)
		if lateErr != nil {
			close(done)
			return
		}
		defer lateLn.Close()
		go func() {
			for {
				conn, acceptErr := lateLn.Accept()
				if acceptErr != nil {
					return
				}
				_ = conn.Close()
			}
		}()
		<-done
	}()

	cfg := NormalizeConfig(Config{
		SID:              "remote-ready",
		Epoch:            1,
		OldCommittee:     []int{0, 1},
		NewCommittee:     []int{0, 1},
		FOld:             0,
		FNew:             0,
		LocalNodeIDs:     []int{0},
		SendRetryMax:     2,
		SendRetryBackoff: 5 * time.Millisecond,
	})
	transport, err := NewTCPLoopbackTransportWithOptions(cfg, []int{0, 1}, []int{0}, 8, "127.0.0.1", 0)
	if err != nil {
		t.Fatalf("NewTCPLoopbackTransportWithOptions failed: %v", err)
	}
	defer func() {
		close(done)
		_ = transport.Close()
	}()
	impl, ok := transport.(*tcpLoopbackTransport)
	if !ok {
		t.Fatalf("unexpected transport type: %T", transport)
	}
	impl.mu.Lock()
	impl.addrByID[1] = addr
	impl.mu.Unlock()
	if err := waitForRemoteNodeReadiness(cfg, impl, []int{0, 1}); err != nil {
		t.Fatalf("waitForRemoteNodeReadiness failed: %v", err)
	}
}

func TestWaitForRemoteNodeReadiness_UsesAnyQuorum(t *testing.T) {
	listeners := make([]net.Listener, 0, 2)
	addresses := make(map[int]string, 2)
	for _, id := range []int{1, 3} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		addresses[id] = ln.Addr().String()
		go func(listener net.Listener) {
			for {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}
	defer func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}()

	cfg := Config{FOld: 1, OldFaults: 1, LocalNodeIDs: []int{0}, WaitSPBCTimeout: 100 * time.Millisecond}
	transport := &tcpLoopbackTransport{
		addrByID: make(map[int]string), dialTO: 20 * time.Millisecond,
	}
	for id, addr := range addresses {
		transport.addrByID[id] = addr
	}
	if err := waitForRemoteNodeReadiness(cfg, transport, []int{0, 1, 2, 3}); err != nil {
		t.Fatalf("quorum readiness failed: %v", err)
	}
}

func TestWaitForListenerReadyMarkersCountsAnyNodeIDs(t *testing.T) {
	dir := t.TempDir()
	if err := writeListenerReadyMarker(dir, 2, "127.0.0.1:20002"); err != nil {
		t.Fatal(err)
	}
	if err := writeListenerReadyMarker(dir, 5, "127.0.0.1:20005"); err != nil {
		t.Fatal(err)
	}
	if err := waitForListenerReadyMarkers(dir, 2, time.Second); err != nil {
		t.Fatalf("listener marker quorum failed: %v", err)
	}
}
