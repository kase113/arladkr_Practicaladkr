package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
)

type acsMVBANet struct {
	net Network
}

func (n *acsMVBANet) Broadcast(msg ProtocolMessage) error {
	return n.net.Broadcast(ProtocolMessage{
		Tag:    TagACSMVBA,
		Round:  msg.Round,
		Leader: msg.Leader,
		Body:   msg,
	})
}

func (n *acsMVBANet) Send(to int, msg ProtocolMessage) error {
	return n.net.Send(to, ProtocolMessage{
		Tag:    TagACSMVBA,
		Round:  msg.Round,
		Leader: msg.Leader,
		Body:   msg,
	})
}

func RunMVBACCommonSubset(
	ctx context.Context,
	cfg Config,
	net Network,
	signer Signer,
	recv <-chan ReceivedMessage,
	input ProposalValue,
	predicate func(i int, v ProposalValue) bool,
) ([]*ProposalValue, error) {
	if predicate == nil {
		predicate = func(_ int, _ ProposalValue) bool { return true }
	}
	if !predicate(cfg.ID, input) {
		return nil, fmt.Errorf("local input rejected by predicate")
	}
	n := cfg.N
	f := cfg.F
	sid := cfg.SID + "VACS"

	diffuseRecv := make(chan ReceivedMessage, 4096)
	mvbaRecv := make(chan ReceivedMessage, 4096)

	routerCtx, cancelRouter := context.WithCancel(ctx)
	defer cancelRouter()
	go func() {
		for {
			select {
			case <-routerCtx.Done():
				return
			case in, ok := <-recv:
				if !ok {
					return
				}
				switch in.Msg.Tag {
				case TagACSDiffuse:
					trySend(routerCtx, diffuseRecv, in)
				case TagACSMVBA:
					body, ok := in.Msg.Body.(ProtocolMessage)
					if !ok {
						continue
					}
					trySend(routerCtx, mvbaRecv, ReceivedMessage{From: in.From, Msg: body})
				}
			}
		}
	}()

	diffuseDigest := hashACSValue(sid, input)
	sig, err := signer.Sign("ACS_DIFFUSE", diffuseDigest)
	if err != nil {
		return nil, err
	}
	bcast := acsDiffuseMsg{
		SID:   sid,
		Value: cloneProposal(input),
		Sig:   append([]byte(nil), sig...),
	}
	for i := 0; i < n; i++ {
		_ = net.Send(i, ProtocolMessage{
			Tag:    TagACSDiffuse,
			Round:  0,
			Leader: 0,
			Body:   bcast,
		})
	}

	seenSenders := make(map[int]struct{}, n)
	values := make([]*acsVectorEntry, n)
	for len(seenSenders) < n-f {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case in := <-diffuseRecv:
			msg, ok := in.Msg.Body.(acsDiffuseMsg)
			if !ok || msg.SID != sid {
				continue
			}
			if _, seen := seenSenders[in.From]; seen {
				continue
			}
			if !predicate(in.From, msg.Value) {
				continue
			}
			dig := hashACSValue(sid, msg.Value)
			if !signer.Verify(in.From, "ACS_DIFFUSE", dig, msg.Sig) {
				continue
			}
			seenSenders[in.From] = struct{}{}
			values[in.From] = &acsVectorEntry{
				From:  in.From,
				Value: cloneProposal(msg.Value),
				Sig:   append([]byte(nil), msg.Sig...),
			}
		}
	}

	vecBytes, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}

	mvbaCfg := cfg
	mvbaCfg.SID = sid + "MVBA"
	mvbaCfg.UseEquivalentPath = true
	mvbaCfg.ValidatePayload = func(payload []byte) bool {
		_, validateErr := validateACSVectorPayload(payload, cfg, signer, predicate)
		return validateErr == nil
	}
	mvbaNode, err := NewDumboMVBA(mvbaCfg, &acsMVBANet{net: net}, signer, nil, mvbaRecv, nil)
	if err != nil {
		return nil, err
	}

	dec, err := mvbaNode.Run(ctx, ProposalValue{
		Payload: vecBytes,
		Round:   0,
		Hint:    "acs-vacs",
	})
	if err != nil {
		return nil, err
	}
	out, err := validateACSVectorPayload(dec.Payload, cfg, signer, predicate)
	if err != nil {
		return nil, err
	}
	result := make([]*ProposalValue, n)
	for i := 0; i < n && i < len(out); i++ {
		if out[i] == nil {
			continue
		}
		v := cloneProposal(out[i].Value)
		result[i] = &v
	}
	return result, nil
}

func validateACSVectorPayload(
	payload []byte,
	cfg Config,
	signer Signer,
	predicate func(int, ProposalValue) bool,
) ([]*acsVectorEntry, error) {
	if cfg.N <= 0 || cfg.F < 0 || cfg.N < 3*cfg.F+1 || signer == nil {
		return nil, fmt.Errorf("invalid ACS vector validation config")
	}
	if predicate == nil {
		predicate = func(_ int, _ ProposalValue) bool { return true }
	}

	var entries []*acsVectorEntry
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("decode ACS vector: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return nil, err
	}
	if len(entries) != cfg.N {
		return nil, fmt.Errorf("ACS vector length=%d want=%d", len(entries), cfg.N)
	}

	sid := cfg.SID + "VACS"
	count := 0
	for slot, entry := range entries {
		if entry == nil {
			continue
		}
		if entry.From != slot {
			return nil, fmt.Errorf("ACS vector slot=%d has proposer=%d", slot, entry.From)
		}
		if !predicate(entry.From, entry.Value) {
			return nil, fmt.Errorf("ACS vector proposer=%d rejected by predicate", entry.From)
		}
		digest := hashACSValue(sid, entry.Value)
		if !signer.Verify(entry.From, "ACS_DIFFUSE", digest, entry.Sig) {
			return nil, fmt.Errorf("ACS vector proposer=%d has invalid diffuse signature", entry.From)
		}
		count++
	}
	if count < cfg.N-cfg.F {
		return nil, fmt.Errorf("ACS vector entries=%d need=%d", count, cfg.N-cfg.F)
	}
	return entries, nil
}

func ensureJSONEOF(dec *json.Decoder) error {
	var extra interface{}
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode ACS vector: trailing JSON value")
		}
		return fmt.Errorf("decode ACS vector trailing data: %w", err)
	}
	return nil
}

func hashACSValue(sid string, v ProposalValue) []byte {
	payload := v.Payload
	return hashBytes(
		[]byte("ACS_DIFFUSE"),
		[]byte(sid),
		[]byte(v.Hint),
		payload,
		[]byte(fmt.Sprintf("%d", v.Round)),
	)
}
