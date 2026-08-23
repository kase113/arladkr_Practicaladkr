package core

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"
)

type cvRouterTestTransport struct {
	mu        sync.Mutex
	inbox     map[int]chan Message
	recvCalls map[int]int
	sent      []Message
	closes    int
	drops     map[cvRouterDropKey]int
}

type cvRouterDropKey struct {
	from, to int
	tag      string
}

func newCVRouterTestTransport(nodes []int, buffer int) *cvRouterTestTransport {
	inbox := make(map[int]chan Message, len(nodes))
	for _, node := range nodes {
		inbox[node] = make(chan Message, buffer)
	}
	return &cvRouterTestTransport{inbox: inbox, recvCalls: make(map[int]int), drops: make(map[cvRouterDropKey]int)}
}

func (t *cvRouterTestTransport) dropNext(from, to int, tag string) {
	t.mu.Lock()
	t.drops[cvRouterDropKey{from: from, to: to, tag: tag}]++
	t.mu.Unlock()
}

func (t *cvRouterTestTransport) RecvChan(id int) (<-chan Message, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recvCalls[id]++
	ch, ok := t.inbox[id]
	if !ok {
		return nil, fmt.Errorf("node %d not registered", id)
	}
	return ch, nil
}

func (t *cvRouterTestTransport) Send(msg Message) error {
	t.mu.Lock()
	key := cvRouterDropKey{from: msg.From, to: msg.To, tag: msg.Tag}
	if t.drops[key] > 0 {
		t.drops[key]--
		t.mu.Unlock()
		return nil
	}
	ch, ok := t.inbox[msg.To]
	t.sent = append(t.sent, Message{From: msg.From, To: msg.To, Tag: msg.Tag, Body: append([]byte(nil), msg.Body...)})
	t.mu.Unlock()
	if !ok {
		return fmt.Errorf("node %d not registered", msg.To)
	}
	ch <- msg
	return nil
}

func (t *cvRouterTestTransport) sentCount(tag string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, msg := range t.sent {
		if msg.Tag == tag {
			count++
		}
	}
	return count
}

func (t *cvRouterTestTransport) sentCountFromTo(tag string, from, to int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, msg := range t.sent {
		if msg.Tag == tag && msg.From == from && msg.To == to {
			count++
		}
	}
	return count
}

func (t *cvRouterTestTransport) sentFromByTag(tag string) []int {
	t.mu.Lock()
	defer t.mu.Unlock()
	senders := make(map[int]struct{})
	for _, msg := range t.sent {
		if msg.Tag == tag {
			senders[msg.From] = struct{}{}
		}
	}
	result := make([]int, 0, len(senders))
	for sender := range senders {
		result = append(result, sender)
	}
	return sortedUnique(result)
}

func (t *cvRouterTestTransport) Broadcast(from int, to []int, tag string, body []byte) {
	for _, node := range to {
		_ = t.Send(Message{From: from, To: node, Tag: tag, Body: body})
	}
}

func (t *cvRouterTestTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closes++
	return nil
}

func (t *cvRouterTestTransport) inject(inbox int, msg Message) {
	t.inbox[inbox] <- msg
}

func (t *cvRouterTestTransport) closeInbox(node int) {
	close(t.inbox[node])
}

func (t *cvRouterTestTransport) recvCount(node int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recvCalls[node]
}

func (t *cvRouterTestTransport) closeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closes
}

func TestCVRouterTestTransportDropsOnlyConfiguredMessage(t *testing.T) {
	transport := newCVRouterTestTransport([]int{1, 2}, 4)
	transport.dropNext(1, 2, "DROP_ME")
	if err := transport.Send(Message{From: 1, To: 2, Tag: "DROP_ME"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-transport.inbox[2]:
		t.Fatal("configured message was delivered")
	default:
	}
	if err := transport.Send(Message{From: 1, To: 2, Tag: "KEEP_ME"}); err != nil {
		t.Fatal(err)
	}
	select {
	case msg := <-transport.inbox[2]:
		if msg.Tag != "KEEP_ME" {
			t.Fatalf("tag=%s", msg.Tag)
		}
	case <-time.After(time.Second):
		t.Fatal("non-dropped message was not delivered")
	}
}

func TestCVNetworkEnvelopeRoundTripAndCanonicalValidation(t *testing.T) {
	const sid = "cv-router-session"
	const epoch = 17
	payload := []byte("component payload")
	wire, err := cvEncodeNetworkEnvelope(sid, epoch, payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := cvDecodeNetworkEnvelope(wire, sid, epoch)
	if err != nil {
		t.Fatalf("decode canonical envelope: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload = %q, want %q", decoded, payload)
	}
	decoded[0] ^= 0xff
	if bytes.Equal(decoded, payload) {
		t.Fatal("decoded payload aliases the input payload")
	}
	if cvMaxNetworkPayloadBytes < cvMaxLeafWireBytes {
		t.Fatalf("network payload cap %d is below legal Leaf cap %d", cvMaxNetworkPayloadBytes, cvMaxLeafWireBytes)
	}

	tests := []struct {
		name  string
		wire  []byte
		sid   string
		epoch int
	}{
		{name: "version", wire: func() []byte {
			bad := append([]byte(nil), wire...)
			bad[0]++
			return bad
		}(), sid: sid, epoch: epoch},
		{name: "sid", wire: wire, sid: sid + "-other", epoch: epoch},
		{name: "epoch", wire: wire, sid: sid, epoch: epoch + 1},
		{name: "trailing", wire: append(append([]byte(nil), wire...), 0), sid: sid, epoch: epoch},
		{name: "oversized payload declaration", wire: func() []byte {
			bad := append([]byte(nil), wire...)
			payloadLengthOffset := 1 + 4 + len(sid) + 8
			binary.BigEndian.PutUint32(bad[payloadLengthOffset:payloadLengthOffset+4], uint32(cvMaxNetworkPayloadBytes+1))
			return bad
		}(), sid: sid, epoch: epoch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := cvDecodeNetworkEnvelope(test.wire, test.sid, test.epoch); err == nil {
				t.Fatal("accepted non-canonical or mismatched CV network envelope")
			}
		})
	}
}

func TestCVSAPVSSRouterConsumesEachLocalInboxOnce(t *testing.T) {
	transport := newCVRouterTestTransport([]int{2, 4, 6}, 8)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, "router-once", 3,
		[]int{2, 4, 6}, []int{2, 6}, 4,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	for _, node := range []int{2, 6} {
		if got := transport.recvCount(node); got != 1 {
			t.Fatalf("RecvChan(%d) calls = %d, want 1", node, got)
		}
		if _, err := router.Receive(node); err != nil {
			t.Fatalf("receive local node %d: %v", node, err)
		}
	}
	if got := transport.recvCount(4); got != 0 {
		t.Fatalf("RecvChan(nonlocal) calls = %d, want 0", got)
	}
	if _, err := router.Receive(4); err == nil {
		t.Fatal("router exposed a nonlocal receive queue")
	}
}

func TestCVSAPVSSRouterRoutesOnlyValidAllowedMessages(t *testing.T) {
	const sid = "router-filter"
	const epoch = 9
	transport := newCVRouterTestTransport([]int{1, 2}, 16)
	router, err := newCVSAPVSSRouter(
		context.Background(), transport, sid, epoch,
		[]int{1, 2}, []int{2}, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	out, err := router.Receive(2)
	if err != nil {
		t.Fatal(err)
	}

	validEnvelope, err := cvEncodeNetworkEnvelope(sid, epoch, []byte("accepted"))
	if err != nil {
		t.Fatal(err)
	}
	wrongSID, err := cvEncodeNetworkEnvelope("other-session", epoch, []byte("wrong sid"))
	if err != nil {
		t.Fatal(err)
	}
	wrongEpoch, err := cvEncodeNetworkEnvelope(sid, epoch+1, []byte("wrong epoch"))
	if err != nil {
		t.Fatal(err)
	}
	malformed := append([]byte(nil), validEnvelope...)
	malformed[0]++

	transport.inject(2, Message{From: 1, To: 2, Tag: "NOT_CV", Body: validEnvelope})
	transport.inject(2, Message{From: 99, To: 2, Tag: cvTagComponentInit, Body: validEnvelope})
	transport.inject(2, Message{From: 1, To: 1, Tag: cvTagComponentInit, Body: validEnvelope})
	transport.inject(2, Message{From: 1, To: 99, Tag: cvTagComponentInit, Body: validEnvelope})
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentInit, Body: wrongSID})
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentInit, Body: wrongEpoch})
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentInit, Body: malformed})
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentLeaf, Body: validEnvelope})

	select {
	case got := <-out:
		if got.From != 1 || got.To != 2 || got.Tag != cvTagComponentLeaf || !bytes.Equal(got.Body, []byte("accepted")) {
			t.Fatalf("unexpected routed message: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for valid routed message")
	}
	select {
	case extra := <-out:
		t.Fatalf("invalid message reached protocol service: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestCVSAPVSSRouterSeparatesOldDealerAndNewReceiverTags(t *testing.T) {
	const sid = "router-apvss-actors"
	const epoch = 4
	transport := newCVRouterTestTransport([]int{1, 2, 10, 11}, 16)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, sid, epoch,
		[]int{1, 2}, []int{10, 11}, []int{1, 10}, 8,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	oldInbox, _ := router.Receive(1)
	newInbox, _ := router.Receive(10)
	envelope, err := cvEncodeNetworkEnvelope(sid, epoch, []byte("actor payload"))
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(10, Message{From: 1, To: 10, Tag: apvssTagLaneOffer, Body: envelope})
	transport.inject(1, Message{From: 10, To: 1, Tag: apvssTagLaneACK, Body: envelope})
	transport.inject(10, Message{From: 11, To: 10, Tag: apvssTagLaneOffer, Body: envelope})
	transport.inject(1, Message{From: 2, To: 1, Tag: apvssTagLaneACK, Body: envelope})
	transport.inject(1, Message{From: 10, To: 1, Tag: cvTagComponentInit, Body: envelope})

	for name, inbox := range map[string]<-chan Message{"old": oldInbox, "new": newInbox} {
		select {
		case msg := <-inbox:
			if (name == "old" && msg.Tag != apvssTagLaneACK) ||
				(name == "new" && msg.Tag != apvssTagLaneOffer) {
				t.Fatalf("unexpected %s actor message: %+v", name, msg)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for %s actor message", name)
		}
	}
	select {
	case extra := <-oldInbox:
		t.Fatalf("unauthorized message reached old actor: %+v", extra)
	case extra := <-newInbox:
		t.Fatalf("unauthorized message reached new actor: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestCVSAPVSSRouterEnforcesV2HandoffRecoveryDirections(t *testing.T) {
	const sid = "router-v2-handoff"
	const epoch = 6
	transport := newCVRouterTestTransport([]int{1, 2, 10, 11}, 16)
	router, err := newCVSAPVSSRouterWithReceivers(
		context.Background(), transport, sid, epoch,
		[]int{1, 2}, []int{10, 11}, []int{1, 10}, 8,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	oldInbox, _ := router.Receive(1)
	newInbox, _ := router.Receive(10)
	envelope, err := cvEncodeNetworkEnvelope(sid, epoch, []byte("V2 recovery payload"))
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(10, Message{From: 1, To: 10, Tag: cvTagHandoffV2, Body: envelope})
	transport.inject(10, Message{From: 2, To: 10, Tag: cvTagAggregateRecoverStoreV2, Body: envelope})
	transport.inject(10, Message{From: 11, To: 10, Tag: cvTagAggregateShareV2, Body: envelope})
	transport.inject(1, Message{From: 2, To: 1, Tag: cvTagHandoffV2, Body: envelope})
	transport.inject(1, Message{From: 10, To: 1, Tag: cvTagAggregateRecoverGetV2, Body: envelope})
	transport.inject(10, Message{From: 11, To: 10, Tag: cvTagHandoffV2, Body: envelope})
	transport.inject(1, Message{From: 2, To: 1, Tag: cvTagAggregateRecoverGetV2, Body: envelope})
	transport.inject(1, Message{From: 10, To: 1, Tag: cvTagAggregateRecoverStoreV2, Body: envelope})

	for _, expected := range []string{cvTagHandoffV2, cvTagAggregateRecoverStoreV2, cvTagAggregateShareV2} {
		select {
		case msg := <-newInbox:
			if msg.Tag != expected {
				t.Fatalf("new node received %s, want %s", msg.Tag, expected)
			}
		case <-time.After(time.Second):
			t.Fatalf("new node did not receive %s", expected)
		}
	}
	for _, expected := range []string{cvTagHandoffV2, cvTagAggregateRecoverGetV2} {
		select {
		case msg := <-oldInbox:
			if msg.Tag != expected {
				t.Fatalf("old node received %s, want %s", msg.Tag, expected)
			}
		case <-time.After(time.Second):
			t.Fatalf("old node did not receive V2 tag %s", expected)
		}
	}
	select {
	case extra := <-oldInbox:
		t.Fatalf("unauthorized V2 message reached old node: %+v", extra)
	case extra := <-newInbox:
		t.Fatalf("unauthorized V2 message reached new node: %+v", extra)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestCVSAPVSSRouterHasBoundedQueueAndStopsWithoutClosingTransport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := newCVRouterTestTransport([]int{5}, 4)
	router, err := newCVSAPVSSRouter(ctx, transport, "router-close", 1, []int{5}, []int{5}, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := router.Receive(5)
	if err != nil {
		t.Fatal(err)
	}
	if cap(out) != 1 {
		t.Fatalf("delivery queue capacity = %d, want 1", cap(out))
	}

	cancel()
	select {
	case _, ok := <-out:
		if ok {
			t.Fatal("delivery queue remained open after context cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("router did not stop after context cancellation")
	}
	if err := router.Close(); err != nil {
		t.Fatal(err)
	}
	if err := router.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if got := transport.closeCount(); got != 0 {
		t.Fatalf("router closed shared transport %d times", got)
	}
	if err, ok := <-router.Errors(); ok {
		t.Fatalf("normal cancellation reported router error: %v", err)
	}
}

func TestCVSAPVSSRouterQueueOverflowIsFatal(t *testing.T) {
	const sid = "router-overflow"
	transport := newCVRouterTestTransport([]int{1, 2}, 4)
	router, err := newCVSAPVSSRouter(context.Background(), transport, sid, 2, []int{1, 2}, []int{2}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	wire, err := cvEncodeNetworkEnvelope(sid, 2, []byte("valid"))
	if err != nil {
		t.Fatal(err)
	}
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentInit, Body: wire})
	transport.inject(2, Message{From: 1, To: 2, Tag: cvTagComponentAck, Body: wire})

	select {
	case err, ok := <-router.Errors():
		if !ok || err == nil {
			t.Fatal("queue overflow closed error channel without an error")
		}
	case <-time.After(time.Second):
		t.Fatal("queue overflow did not terminate router")
	}
}

func TestCVSAPVSSRouterClosedInboxIsFatal(t *testing.T) {
	transport := newCVRouterTestTransport([]int{7}, 1)
	router, err := newCVSAPVSSRouter(context.Background(), transport, "router-reader", 2, []int{7}, []int{7}, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer router.Close()
	transport.closeInbox(7)
	select {
	case err, ok := <-router.Errors():
		if !ok || err == nil {
			t.Fatal("closed transport inbox did not report an error")
		}
	case <-time.After(time.Second):
		t.Fatal("closed transport inbox did not terminate router")
	}
}
