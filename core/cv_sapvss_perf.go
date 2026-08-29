package core

import (
	"os"
	"strings"
	"sync/atomic"
)

// These counters are an opt-in diagnostic aid used by the legacy service's
// internal instrumentation. They are deliberately kept separate from the
// benchmark result schema and do not participate in protocol decisions.
var cvPerfCountersEnabled = strings.TrimSpace(os.Getenv("RLADKR_CV_PERF_COUNTERS")) != ""

var cvPerfCounters struct {
	leafVerifyCalls          atomic.Uint64
	leafVerifySuccesses      atomic.Uint64
	sharingVerifyCalls       atomic.Uint64
	chunkingVerifyCalls      atomic.Uint64
	exactRangeVerifyCalls    atomic.Uint64
	aggCalls                 atomic.Uint64
	aggVerifiedCalls         atomic.Uint64
	averCalls                atomic.Uint64
	averVerifiedCalls        atomic.Uint64
	averSuccesses            atomic.Uint64
	aggregateOffers          atomic.Uint64
	verifiedLeafCacheHits    atomic.Uint64
	verifiedLeafCacheMiss    atomic.Uint64
	componentRetrievalStarts atomic.Uint64
	componentRetrievalJoins  atomic.Uint64
	receiptPrewarmStarts     atomic.Uint64
	receiptPrewarmHits       atomic.Uint64
	freshArtifactWrites      atomic.Uint64
	freshArtifactSkips       atomic.Uint64
	reconstructedCacheQueued atomic.Uint64
	reconstructedCacheWrites atomic.Uint64
	reconstructedCacheDrops  atomic.Uint64
	reconstructedCacheErrors atomic.Uint64
	envelopeReuseSends       atomic.Uint64
}
