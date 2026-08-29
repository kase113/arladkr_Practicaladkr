package core

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

const cvScalarStateScalarVersion = 2

type cvScalarStateScalar struct {
	Version         int    `json:"version"`
	SID             string `json:"sid"`
	Epoch           uint64 `json:"epoch"`
	ReceiverID      int    `json:"receiver_id"`
	AggregateDigest []byte `json:"aggregate_digest"`
	Scalar          []byte `json:"scalar"`
	Output          []byte `json:"output"`
}

type cvScalarStoreScalar struct{ root string }

func newCVScalarStoreScalar(root string) (*cvScalarStoreScalar, error) {
	if strings.TrimSpace(root) == "" {
		return nil, fmt.Errorf("empty CV V2 scalar store root")
	}
	store := &cvScalarStoreScalar{root: filepath.Join(root, "scalar-state-v2")}
	if err := cvEnsurePrivateStoreDir(store.root); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *cvScalarStoreScalar) PersistOnce(
	sid string, epoch uint64, receiverID int, aggregateDigest []byte,
	scalar fr.Element, output *cvScalarShareOutputScalar,
) error {
	if s == nil || sid == "" || epoch == 0 || receiverID < 0 || len(aggregateDigest) != 32 || output == nil ||
		output.ReceiverID != receiverID || !bytes.Equal(output.AggregateDigest, aggregateDigest) {
		return fmt.Errorf("invalid CV V2 scalar state input")
	}
	if public := cvPointTimes(&genG1, &scalar); !public.Equal(&output.Y) {
		return fmt.Errorf("CV V2 scalar state does not match public output")
	}
	outputWire, err := cvScalarShareOutputScalarCanonicalBytes(output)
	if err != nil {
		return err
	}
	encodedScalar := scalar.Bytes()
	state := cvScalarStateScalar{
		Version: cvScalarStateScalarVersion, SID: sid, Epoch: epoch, ReceiverID: receiverID,
		AggregateDigest: append([]byte(nil), aggregateDigest...), Scalar: append([]byte(nil), encodedScalar[:]...),
		Output: outputWire,
	}
	raw, err := json.Marshal(&state)
	if err != nil {
		return err
	}
	return cvPutImmutableFile(s.path(sid, epoch, receiverID), raw)
}

func (s *cvScalarStoreScalar) Read(sid string, epoch uint64, receiverID int) (*cvScalarStateScalar, error) {
	raw, err := cvReadImmutableFile(s.path(sid, epoch, receiverID))
	if err != nil {
		return nil, err
	}
	var state cvScalarStateScalar
	if err := cvDecodeStrictJSONScalar(raw, &state); err != nil || state.Version != cvScalarStateScalarVersion ||
		state.SID != sid || state.Epoch != epoch || state.ReceiverID != receiverID ||
		len(state.AggregateDigest) != 32 || len(state.Scalar) != fr.Bytes || len(state.Output) == 0 {
		return nil, fmt.Errorf("invalid CV V2 scalar state")
	}
	return &state, nil
}

func cvDecodeStrictJSONScalar(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON state")
		}
		return err
	}
	return nil
}

func (s *cvScalarStoreScalar) path(sid string, epoch uint64, receiverID int) string {
	digest := hashBytes([]byte("ARL-CV-sAPVSS/v2-scalar-group/scalar-store-key"), []byte(sid))
	return filepath.Join(s.root, hex.EncodeToString(digest[:8]), fmt.Sprintf("epoch-%020d", epoch),
		fmt.Sprintf("receiver-%06d.private.json", receiverID))
}
