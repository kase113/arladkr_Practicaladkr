package core

import (
	"fmt"
)

func newAgreementTransport(cfg Config, nodes []int, buffer int) (agreementTransport, error) {
	localNodes := append([]int(nil), cfg.LocalNodeIDs...)
	localNodes = sortedUnique(append(localNodes, cfg.CVLocalReceiverIDs...))
	if cfg.AgreementTransport == "" || cfg.AgreementTransport == "tcp" || cfg.AgreementTransport == "tcp-distributed" || cfg.AgreementTransport == "tcp-loopback" {
		return NewTCPLoopbackTransportWithOptions(cfg, nodes, localNodes, buffer, cfg.AgreementBindHost, cfg.AgreementBasePort)
	}
	return nil, fmt.Errorf("unsupported agreement transport: %s", cfg.AgreementTransport)
}
