package core

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type EquivalentMessageClass string

const (
	EquivalentMessageOther       EquivalentMessageClass = ""
	EquivalentMessagePDData      EquivalentMessageClass = "pd_data"
	EquivalentMessageRCData      EquivalentMessageClass = "rc_data"
	EquivalentMessageCertificate EquivalentMessageClass = "certificate"
)

// ClassifyEquivalentMessage exposes only the wire-cost category needed by
// experiment instrumentation; equivalent protocol body types remain private.
func ClassifyEquivalentMessage(msg ProtocolMessage) EquivalentMessageClass {
	switch body := msg.Body.(type) {
	case pdStoreMsg:
		return EquivalentMessagePDData
	case rcStoreMsg:
		return EquivalentMessageRCData
	case pdLockMsg, pdDoneMsg, quitFinishMsg, rcLockMsg:
		return EquivalentMessageCertificate
	case rcPrepareMsg:
		if body.Lock != nil {
			return EquivalentMessageCertificate
		}
	}
	return EquivalentMessageOther
}

type merkleBranch struct {
	Index    int
	Siblings [][]byte
}

type pdStoreMsg struct {
	SID    string
	Root   []byte
	Stripe []byte
	Branch merkleBranch
}

type pdPullRequest struct {
	SID       string
	Root      []byte
	Requester int
	Index     int
}

func appendWireBytes(dst []byte, value []byte) ([]byte, error) {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("wire field too large: %d", len(value))
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	dst = append(dst, length[:]...)
	dst = append(dst, value...)
	return dst, nil
}

func readWireBytes(r *bytes.Reader, max int) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(length[:]))
	if n < 0 || n > max || n > r.Len() {
		return nil, fmt.Errorf("invalid wire field length %d", n)
	}
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func encodeMerkleBranch(dst []byte, branch merkleBranch) ([]byte, error) {
	var index [4]byte
	binary.BigEndian.PutUint32(index[:], uint32(branch.Index))
	dst = append(dst, index[:]...)
	if len(branch.Siblings) > 1024 {
		return nil, fmt.Errorf("too many merkle siblings: %d", len(branch.Siblings))
	}
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(branch.Siblings)))
	dst = append(dst, count[:]...)
	for _, sibling := range branch.Siblings {
		var err error
		dst, err = appendWireBytes(dst, sibling)
		if err != nil {
			return nil, err
		}
	}
	return dst, nil
}

func decodeMerkleBranch(r *bytes.Reader) (merkleBranch, error) {
	var branch merkleBranch
	var field [4]byte
	if _, err := io.ReadFull(r, field[:]); err != nil {
		return branch, err
	}
	branch.Index = int(binary.BigEndian.Uint32(field[:]))
	if _, err := io.ReadFull(r, field[:]); err != nil {
		return branch, err
	}
	count := int(binary.BigEndian.Uint32(field[:]))
	if count < 0 || count > 1024 {
		return branch, fmt.Errorf("invalid merkle sibling count %d", count)
	}
	branch.Siblings = make([][]byte, count)
	for i := range branch.Siblings {
		sibling, err := readWireBytes(r, 1<<20)
		if err != nil {
			return branch, err
		}
		branch.Siblings[i] = sibling
	}
	return branch, nil
}

func (m pdStoreMsg) GobEncode() ([]byte, error) {
	out := make([]byte, 0, len(m.SID)+len(m.Root)+len(m.Stripe)+256)
	var err error
	if out, err = appendWireBytes(out, []byte(m.SID)); err != nil {
		return nil, err
	}
	if out, err = appendWireBytes(out, m.Root); err != nil {
		return nil, err
	}
	if out, err = appendWireBytes(out, m.Stripe); err != nil {
		return nil, err
	}
	return encodeMerkleBranch(out, m.Branch)
}

func (m *pdStoreMsg) GobDecode(data []byte) error {
	if m == nil {
		return fmt.Errorf("nil pd store message")
	}
	r := bytes.NewReader(data)
	sid, err := readWireBytes(r, 1<<20)
	if err != nil {
		return err
	}
	root, err := readWireBytes(r, 1<<20)
	if err != nil {
		return err
	}
	stripe, err := readWireBytes(r, 64<<20)
	if err != nil {
		return err
	}
	branch, err := decodeMerkleBranch(r)
	if err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing pd store bytes: %d", r.Len())
	}
	m.SID, m.Root, m.Stripe, m.Branch = string(sid), root, stripe, branch
	return nil
}

type pdStoredMsg struct {
	SID   string
	Root  []byte
	Share []byte
}

type pdLockMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type pdLockedMsg struct {
	SID   string
	Root  []byte
	Share []byte
}

type pdDoneMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type quitReadyMsg struct {
	SID   string
	Share []byte
}

type quitFinishMsg struct {
	SID         string
	Certificate []byte
}

type rcStoreMsg struct {
	SID    string
	Root   []byte
	From   int
	Stripe []byte
	Branch merkleBranch
}

func (m rcStoreMsg) GobEncode() ([]byte, error) {
	out := make([]byte, 0, len(m.SID)+len(m.Root)+len(m.Stripe)+256)
	var err error
	if out, err = appendWireBytes(out, []byte(m.SID)); err != nil {
		return nil, err
	}
	if out, err = appendWireBytes(out, m.Root); err != nil {
		return nil, err
	}
	var from [4]byte
	binary.BigEndian.PutUint32(from[:], uint32(m.From))
	out = append(out, from[:]...)
	if out, err = appendWireBytes(out, m.Stripe); err != nil {
		return nil, err
	}
	return encodeMerkleBranch(out, m.Branch)
}

func (m *rcStoreMsg) GobDecode(data []byte) error {
	if m == nil {
		return fmt.Errorf("nil rc store message")
	}
	r := bytes.NewReader(data)
	sid, err := readWireBytes(r, 1<<20)
	if err != nil {
		return err
	}
	root, err := readWireBytes(r, 1<<20)
	if err != nil {
		return err
	}
	var from [4]byte
	if _, err := io.ReadFull(r, from[:]); err != nil {
		return err
	}
	stripe, err := readWireBytes(r, 64<<20)
	if err != nil {
		return err
	}
	branch, err := decodeMerkleBranch(r)
	if err != nil {
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("trailing rc store bytes: %d", r.Len())
	}
	m.SID, m.Root, m.From, m.Stripe, m.Branch = string(sid), root, int(binary.BigEndian.Uint32(from[:])), stripe, branch
	return nil
}

type rcPullRequest struct {
	SID       string
	Root      []byte
	Requester int
}

type rcLockMsg struct {
	SID         string
	Leader      int
	Root        []byte
	Certificate []byte
}

type rcPrepareMsg struct {
	SID    string
	Leader int
	Lock   *pdLockMsg
}

type coinShareMsg struct {
	SID   string
	Nonce string
	Share []byte
}

type abaEstMsg struct {
	SID   string
	Iter  int
	Value int
}

type abaDecisionMsg struct {
	SID   string
	Iter  int
	Value int
}

type acsDiffuseMsg struct {
	SID   string
	Value ProposalValue
	Sig   []byte
}

type acsVectorEntry struct {
	From  int
	Value ProposalValue
	Sig   []byte
}
