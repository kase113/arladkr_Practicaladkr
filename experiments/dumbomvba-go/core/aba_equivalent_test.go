package core

import (
	"context"
	"sync"
	"testing"
	"time"
)

type reliableABANet struct {
	id    int
	peers []chan ReceivedMessage
}

func (n *reliableABANet) Send(to int, msg ProtocolMessage) error {
	n.peers[to] <- ReceivedMessage{From: n.id, Msg: msg}
	return nil
}

func (n *reliableABANet) Broadcast(msg ProtocolMessage) error {
	for peer := range n.peers {
		if err := n.Send(peer, msg); err != nil {
			return err
		}
	}
	return nil
}

func TestRunABAEquivalentAgreesAcrossMixedInputs(t *testing.T) {
	const (
		n = 4
		f = 1
	)
	recv := make([]chan ReceivedMessage, n)
	nets := make([]*reliableABANet, n)
	for i := 0; i < n; i++ {
		recv[i] = make(chan ReceivedMessage, 65536)
	}
	for i := 0; i < n; i++ {
		nets[i] = &reliableABANet{id: i, peers: recv}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	inputs := []int{0, 1, 0, 1}
	outputs := make([]int, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			m := &DumboMVBA{cfg: Config{SID: "aba-equivalent", ID: id, N: n, F: f}, net: nets[id]}
			coinRound := 0
			outputs[id], errs[id] = m.runABA(ctx, "aba-sid", 0, inputs[id], recv[id], func(string) (int, error) {
				// A constant coin is not guaranteed to terminate for every
				// valid estimate. Alternate values to exercise both branches
				// while keeping this focused test bounded.
				value := 1 - coinRound%2
				coinRound++
				return value, nil
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("node %d ABA failed: %v", i, err)
		}
		if outputs[i] != outputs[0] {
			t.Fatalf("ABA disagreement: node 0=%d node %d=%d", outputs[0], i, outputs[i])
		}
	}
}

func TestNormalizeABAValuesRejectsMalformedSets(t *testing.T) {
	for _, values := range [][]int{{}, {0, 0}, {1, 2}, {-1}, {0, 1, 1}} {
		if got := normalizeABAValues(values); got != nil {
			t.Fatalf("normalizeABAValues(%v) = %v, want nil", values, got)
		}
	}
	if got := normalizeABAValues([]int{1, 0}); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("normalizeABAValues([1 0]) = %v, want [0 1]", got)
	}
}
