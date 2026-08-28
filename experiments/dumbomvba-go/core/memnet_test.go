package core

import "time"

// memNet is the bounded in-memory transport used by the deterministic ACS
// smoke tests. Fault-injection transports live outside the retained test set.
type memNet struct {
	id    int
	peers []chan ReceivedMessage
}

func (n *memNet) Broadcast(msg ProtocolMessage) error {
	for i := range n.peers {
		_ = n.Send(i, msg)
	}
	return nil
}

func (n *memNet) Send(to int, msg ProtocolMessage) error {
	if to < 0 || to >= len(n.peers) {
		return nil
	}
	rm := ReceivedMessage{From: n.id, Msg: msg}
	select {
	case n.peers[to] <- rm:
	default:
		select {
		case n.peers[to] <- rm:
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil
}
