package core

import "encoding/gob"

func init() {
	gob.Register(ProtocolMessage{}) // required for ACS_MVBA wrapping
	gob.Register(ProposalValue{})
	gob.Register(SigShare{})
	gob.Register([]SigShare{})

	gob.Register(pdStoreMsg{})
	gob.Register(pdPullRequest{})
	gob.Register(pdStoredMsg{})
	gob.Register(pdLockMsg{})
	gob.Register(pdLockedMsg{})
	gob.Register(pdDoneMsg{})
	gob.Register(quitReadyMsg{})
	gob.Register(quitFinishMsg{})
	gob.Register(rcStoreMsg{})
	gob.Register(rcPullRequest{})
	gob.Register(rcLockMsg{})
	gob.Register(rcPrepareMsg{})
	gob.Register(coinShareMsg{})
	gob.Register(abaEstMsg{})
	gob.Register(abaDecisionMsg{})
	gob.Register(acsDiffuseMsg{})
	gob.Register(acsVectorEntry{})
	gob.Register(mvbaABAVoteMsg{})
	gob.Register(mvbaABACoinMsg{})
}
