package storage

import (
	"strconv"
	"time"

	"github.com/dgraph-io/ristretto"
	mdns "github.com/miekg/dns"
)

const (
	defaultCacheCounters = 1 << 20
	defaultCacheMaxCost  = 1 << 30
	defaultCacheBuffer   = 64
)

type cacheEntry struct {
	msg      *mdns.Msg
	storedAt time.Time
	minTTL   uint32
}

// IsNegativeResponse reports whether resp is an NXDOMAIN or NODATA answer per RFC 2308.
func IsNegativeResponse(resp *mdns.Msg) bool {
	if resp == nil {
		return false
	}
	if resp.Rcode == mdns.RcodeNameError {
		return true
	}
	return resp.Rcode == mdns.RcodeSuccess && len(resp.Answer) == 0
}

// ResponseCache stores forwarded upstream DNS responses with TTL-aware eviction.
type ResponseCache struct {
	cache *ristretto.Cache
}

// NewResponseCache creates a Ristretto cache tuned for high read throughput.
func NewResponseCache() (*ResponseCache, error) {
	c, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: defaultCacheCounters,
		MaxCost:     defaultCacheMaxCost,
		BufferItems: defaultCacheBuffer,
	})
	if err != nil {
		return nil, err
	}
	return &ResponseCache{cache: c}, nil
}

// QuestionKey returns a deterministic base cache key from a DNS question.
func QuestionKey(q mdns.Question) string {
	return NormalizeName(q.Name) + "|" +
		strconv.FormatUint(uint64(q.Qtype), 10) + "|" +
		strconv.FormatUint(uint64(q.Qclass), 10)
}

// CacheKey returns a deterministic cache key including ECS scope when present
// in the query or synthesized from ecs when ECS forwarding is enabled.
func CacheKey(q mdns.Question, req *mdns.Msg, ecs ECSContext) string {
	key := QuestionKey(q)
	if suffix := ECSCacheSuffix(req, ecs); suffix != "" {
		key += "|ecs:" + suffix
	}
	return key
}

// Get returns a cached upstream response with TTLs adjusted for elapsed time.
// The second return value is false on miss or when the entry has expired.
func (c *ResponseCache) Get(key string) (*mdns.Msg, bool) {
	if c == nil || c.cache == nil {
		return nil, false
	}

	raw, ok := c.cache.Get(key)
	if !ok {
		return nil, false
	}

	entry, ok := raw.(*cacheEntry)
	if !ok || entry == nil || entry.msg == nil {
		return nil, false
	}

	elapsed := uint32(time.Since(entry.storedAt).Seconds())
	if elapsed >= entry.minTTL {
		c.cache.Del(key)
		return nil, false
	}

	resp := entry.msg.Copy()
	if !adjustRecordTTLs(resp, elapsed) {
		c.cache.Del(key)
		return nil, false
	}

	return resp, true
}

// Set stores a forwarded upstream response using TTL-aware eviction.
// Positive answers use the minimum TTL across Answer and Authority records.
// Negative answers (NXDOMAIN / NODATA) use min(SOA TTL, SOA MINIMUM) from Authority.
func (c *ResponseCache) Set(key string, resp *mdns.Msg) {
	if c == nil || c.cache == nil || resp == nil {
		return
	}

	negative := IsNegativeResponse(resp)
	minTTL := minResponseTTL(resp)
	if negative {
		minTTL = negativeCacheTTL(resp)
	}
	if minTTL == 0 {
		return
	}

	entry := &cacheEntry{
		msg:      cloneForwardResponse(resp),
		storedAt: time.Now(),
		minTTL:   minTTL,
	}

	cost := int64(1)
	if packed, err := entry.msg.Pack(); err == nil {
		cost = int64(len(packed))
	}

	c.cache.SetWithTTL(key, entry, cost, time.Duration(minTTL)*time.Second)
}

// Wait blocks until pending cache writes are applied.
func (c *ResponseCache) Wait() {
	if c == nil || c.cache == nil {
		return
	}
	c.cache.Wait()
}

func cloneForwardResponse(resp *mdns.Msg) *mdns.Msg {
	copy := &mdns.Msg{
		MsgHdr: resp.MsgHdr,
		Answer: cloneRecords(resp.Answer),
		Ns:     cloneRecords(resp.Ns),
		Extra:  cloneRecords(resp.Extra),
	}
	copy.Question = nil
	return copy
}

func cloneRecords(rrs []mdns.RR) []mdns.RR {
	if len(rrs) == 0 {
		return nil
	}
	out := make([]mdns.RR, len(rrs))
	for i, rr := range rrs {
		out[i] = mdns.Copy(rr)
	}
	return out
}

func minResponseTTL(resp *mdns.Msg) uint32 {
	minTTL := sectionMinTTL(resp.Answer)
	if nsMin := sectionMinTTL(resp.Ns); nsMin > 0 && (minTTL == 0 || nsMin < minTTL) {
		minTTL = nsMin
	}
	return minTTL
}

func negativeCacheTTL(resp *mdns.Msg) uint32 {
	for _, rr := range resp.Ns {
		soa, ok := rr.(*mdns.SOA)
		if !ok {
			continue
		}
		ttl := soa.Hdr.Ttl
		if soa.Minttl < ttl {
			ttl = soa.Minttl
		}
		return ttl
	}
	return 0
}

func sectionMinTTL(rrs []mdns.RR) uint32 {
	if len(rrs) == 0 {
		return 0
	}

	minTTL := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if ttl := rr.Header().Ttl; ttl < minTTL {
			minTTL = ttl
		}
	}
	return minTTL
}

func adjustRecordTTLs(msg *mdns.Msg, elapsed uint32) bool {
	for _, section := range [][]mdns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			hdr := rr.Header()
			if hdr.Ttl <= elapsed {
				return false
			}
			hdr.Ttl -= elapsed
		}
	}
	return true
}
