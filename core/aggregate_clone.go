package core

func cloneAPVSSAggregate(in *APVSSAggregate) *APVSSAggregate {
	if in == nil {
		return nil
	}
	return &APVSSAggregate{
		Provider:        in.Provider,
		Dealers:         append([]int(nil), in.Dealers...),
		AggregateDigest: append([]byte(nil), in.AggregateDigest...),
	}
}

func cloneAggRLO(in *AggRLO) *AggRLO {
	if in == nil {
		return nil
	}
	return &AggRLO{
		Header: AggHeader{
			SID: in.Header.SID, Epoch: in.Header.Epoch,
			Dealers:         append([]int(nil), in.Header.Dealers...),
			AggregateDigest: append([]byte(nil), in.Header.AggregateDigest...),
			PayloadDigest:   append([]byte(nil), in.Header.PayloadDigest...),
			FreshShardRoot:  append([]byte(nil), in.Header.FreshShardRoot...),
			MetadataHash:    append([]byte(nil), in.Header.MetadataHash...),
		},
		Lock: AggLock{
			Threshold:   in.Lock.Threshold,
			Certificate: append([]byte(nil), in.Lock.Certificate...),
		},
		Aggregate: *cloneAPVSSAggregate(&in.Aggregate),
		Digest:    append([]byte(nil), in.Digest...),
	}
}
