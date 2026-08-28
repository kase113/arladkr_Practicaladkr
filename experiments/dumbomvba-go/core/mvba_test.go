package core

import (
	"context"
	"testing"
	"time"
)

type noopNetwork struct{}

func (n *noopNetwork) Broadcast(msg ProtocolMessage) error { return nil }
func (n *noopNetwork) Send(to int, msg ProtocolMessage) error {
	return nil
}

type fakeSPBCDriver struct {
	expectedSID    string
	expectedLeader int
	waitInbound    bool
	noFinal        bool
	value          ProposalValue

	starts int
	seen   chan RoutedSPBCMessage
}

func (d *fakeSPBCDriver) Start(
	ctx context.Context,
	sid string,
	id, n, f, round, leader int,
	input *ProposalValue,
) (*SPBCHandle, error) {
	d.starts++
	if sid != d.expectedSID {
		return nil, ErrInvalidConfig
	}
	if leader != d.expectedLeader {
		return nil, ErrInvalidConfig
	}
	inbound := make(chan RoutedSPBCMessage, 16)
	s1 := make(chan SPBCS1Result, 1)
	final := make(chan SPBCFinalResult, 1)

	go func() {
		defer close(s1)
		defer close(final)
		if d.noFinal {
			<-ctx.Done()
			return
		}
		if d.waitInbound {
			select {
			case msg := <-inbound:
				select {
				case d.seen <- msg:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
		final <- SPBCFinalResult{
			Leader: leader,
			Value:  d.value,
			OK:     true,
		}
	}()

	return &SPBCHandle{
		Inbound:  inbound,
		S1Out:    s1,
		FinalOut: final,
		Close:    func() {},
	}, nil
}

func TestDumboMVBA_RunRoutesSPBCMessagesAndDecides(t *testing.T) {
	order := leaderOrder("mvba-test", 4, 0)
	leader := order[0]
	driver := &fakeSPBCDriver{
		expectedSID:    "mvba-test",
		expectedLeader: leader,
		waitInbound:    true,
		value: ProposalValue{
			Payload: []byte("decide-me"),
			Round:   0,
			Hint:    "test",
		},
		seen: make(chan RoutedSPBCMessage, 1),
	}

	recv := make(chan ReceivedMessage, 8)
	node, err := NewDumboMVBA(
		Config{
			SID:              "mvba-test",
			ID:               1,
			N:                4,
			F:                1,
			MaxRounds:        1,
			WaitSPBCTimeout:  2 * time.Second,
			RouteSendTimeout: 300 * time.Millisecond,
		},
		&noopNetwork{},
		nil,
		driver,
		recv,
		nil,
	)
	if err != nil {
		t.Fatalf("NewDumboMVBA failed: %v", err)
	}

	runDone := make(chan ProposalValue, 1)
	runErr := make(chan error, 1)
	go func() {
		out, rerr := node.Run(context.Background(), ProposalValue{
			Payload: []byte("input"),
			Round:   0,
			Hint:    "input",
		})
		if rerr != nil {
			runErr <- rerr
			return
		}
		runDone <- out
	}()

	recv <- ReceivedMessage{
		From: 2,
		Msg: ProtocolMessage{
			Tag:    TagSPBC,
			Round:  0,
			Leader: leader,
			Body:   "hello-spbc",
		},
	}

	select {
	case routed := <-driver.seen:
		if routed.From != 2 || routed.Body != "hello-spbc" {
			t.Fatalf("unexpected routed message: %+v", routed)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting routed message")
	}

	select {
	case out := <-runDone:
		if string(out.Payload) != "decide-me" {
			t.Fatalf("unexpected decision: %q", string(out.Payload))
		}
	case err := <-runErr:
		t.Fatalf("Run returned error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting Run result")
	}
}

func TestDumboMVBA_RunTimeout(t *testing.T) {
	order := leaderOrder("mvba-timeout", 4, 0)
	driver := &fakeSPBCDriver{
		expectedSID:    "mvba-timeout",
		expectedLeader: order[0],
		noFinal:        true,
		seen:           make(chan RoutedSPBCMessage, 1),
	}
	recv := make(chan ReceivedMessage, 1)
	node, err := NewDumboMVBA(
		Config{
			SID:              "mvba-timeout",
			ID:               0,
			N:                4,
			F:                1,
			MaxRounds:        1,
			WaitSPBCTimeout:  80 * time.Millisecond,
			RouteSendTimeout: 10 * time.Millisecond,
		},
		&noopNetwork{},
		nil,
		driver,
		recv,
		nil,
	)
	if err != nil {
		t.Fatalf("NewDumboMVBA failed: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = node.Run(ctx, ProposalValue{Payload: []byte("x")})
	if err == nil {
		t.Fatalf("expected timeout error")
	}
}

func TestDumboMVBAPayloadValidityRejectsInvalidDecision(t *testing.T) {
	const sid = "mvba-invalid-decision"
	driver := &fakeSPBCDriver{
		expectedSID:    sid,
		expectedLeader: leaderOrder(sid, 4, 0)[0],
		value: ProposalValue{
			Payload: []byte("invalid-decision"),
			Round:   0,
			Hint:    "test",
		},
		seen: make(chan RoutedSPBCMessage, 1),
	}
	node, err := NewDumboMVBA(
		Config{
			SID:              sid,
			ID:               0,
			N:                4,
			F:                1,
			MaxRounds:        1,
			WaitSPBCTimeout:  time.Second,
			RouteSendTimeout: time.Second,
			ValidatePayload: func(payload []byte) bool {
				return string(payload) == "valid-input"
			},
		},
		&noopNetwork{},
		nil,
		driver,
		make(chan ReceivedMessage, 1),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := node.Run(context.Background(), ProposalValue{Payload: []byte("valid-input")}); err == nil {
		t.Fatal("MVBA accepted a decided payload rejected by the application predicate")
	}
}
