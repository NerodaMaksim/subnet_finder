package scanner

import (
	"sync"
	"time"
)

// Hostname lookups are cached across scans so a rescan of the same subnet does
// not pay the query cost again. Misses expire sooner than hits: a host that
// was silent once is worth re-asking, and a name that resolved is unlikely to
// change within the window.
type cachedHostname struct {
	hostname
	expires time.Time
}

var (
	hostnameCacheMu sync.Mutex
	hostnameCache   = make(map[string]cachedHostname)
)

func loadCachedHostname(ip string) (hostname, bool) {
	hostnameCacheMu.Lock()
	defer hostnameCacheMu.Unlock()

	entry, ok := hostnameCache[ip]
	if !ok || time.Now().After(entry.expires) {
		return hostname{}, false
	}
	return entry.hostname, true
}

func storeCachedHostname(ip string, name hostname) {
	ttl := hostnameTTL
	if name.name == "" {
		ttl = hostnameMissTTL
	}

	hostnameCacheMu.Lock()
	defer hostnameCacheMu.Unlock()

	now := time.Now()
	for key, entry := range hostnameCache {
		if now.After(entry.expires) {
			delete(hostnameCache, key)
		}
	}
	hostnameCache[ip] = cachedHostname{hostname: name, expires: now.Add(ttl)}
}
