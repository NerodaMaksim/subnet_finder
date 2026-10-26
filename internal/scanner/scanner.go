package scanner

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
)

const (
	defaultWorkers = 96
	// Hostname lookups are slower than a probe and run off the critical path,
	// so they get their own smaller pool.
	hostnameWorkers = 24
	hostnameBacklog = 4096
)

type Host struct {
	IP             string `json:"ip"`
	Hostname       string `json:"hostname,omitempty"`
	HostnameSource string `json:"hostname_source,omitempty"`
	Method         string `json:"method"`
	Ports          []int  `json:"ports,omitempty"`
}

type Progress struct {
	Scanned int `json:"scanned"`
	Total   int `json:"total"`
	Live    int `json:"live"`
}

type Event struct {
	Kind     string    `json:"-"`
	Progress *Progress `json:"progress,omitempty"`
	Host     *Host     `json:"host,omitempty"`
	Message  string    `json:"message,omitempty"`
}

func Scan(ctx context.Context, cidrs []string, emit func(Event)) {
	cidrs = uniqueCIDRs(cidrs)
	if len(cidrs) == 0 {
		emit(Event{Kind: "error", Message: "no subnets selected"})
		return
	}

	var total int
	ranges := make([][2]uint32, 0, len(cidrs))
	for _, cidr := range cidrs {
		first, last, err := hostRange(cidr)
		if err != nil {
			log.Printf("host range for %s: %v", cidr, err)
			emit(Event{Kind: "error", Message: err.Error()})
			return
		}
		if last < first {
			continue
		}
		n := int(last-first) + 1
		total += n
		ranges = append(ranges, [2]uint32{first, last})
	}

	if total == 0 {
		emit(Event{Kind: "done", Progress: &Progress{Total: 0}})
		return
	}

	jobs := make(chan string, defaultWorkers)
	var scanned atomic.Int64
	var live atomic.Int64

	var emitMu sync.Mutex
	safeEmit := func(e Event) {
		emitMu.Lock()
		defer emitMu.Unlock()
		emit(e)
	}

	progress := func() Progress {
		return Progress{
			Scanned: int(scanned.Load()),
			Total:   total,
			Live:    int(live.Load()),
		}
	}

	// Hosts are reported the moment they answer a probe and the name is filled
	// in by a follow-up event, so a slow resolver never holds up the scan.
	resolver := newHostnameResolver()
	names := make(chan Host, hostnameBacklog)
	var nameWG sync.WaitGroup
	for i := 0; i < hostnameWorkers; i++ {
		nameWG.Add(1)
		go func() {
			defer nameWG.Done()
			for host := range names {
				if ctx.Err() != nil {
					continue
				}
				found := resolver.lookup(ctx, host.IP)
				if found.name == "" || ctx.Err() != nil {
					continue
				}
				host.Hostname = found.name
				host.HostnameSource = found.source
				p := progress()
				safeEmit(Event{Kind: "host", Host: &host, Progress: &p})
			}
		}()
	}

	var wg sync.WaitGroup
	for i := 0; i < defaultWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				if ctx.Err() != nil {
					continue
				}

				result := probeHost(ctx, ip)
				n := int(scanned.Add(1))
				if ctx.Err() != nil {
					continue
				}

				if !result.pingOK && len(result.ports) == 0 {
					if n == total || n%8 == 0 {
						p := progress()
						safeEmit(Event{Kind: "progress", Progress: &p})
					}
					continue
				}

				host := Host{
					IP:     ip,
					Method: detectionMethod(result.pingOK, result.ports),
					Ports:  result.ports,
				}
				live.Add(1)
				p := progress()
				safeEmit(Event{Kind: "host", Host: &host, Progress: &p})
				names <- host
			}
		}()
	}

produce:
	for _, r := range ranges {
		first, last := r[0], r[1]
		for n := first; ; n++ {
			if ctx.Err() != nil {
				break produce
			}
			select {
			case <-ctx.Done():
				break produce
			case jobs <- ipString(n):
			}
			if n == last {
				break
			}
		}
	}
	close(jobs)
	wg.Wait()

	p := progress()
	if ctx.Err() == nil && live.Load() > 0 {
		safeEmit(Event{Kind: "resolving", Progress: &p, Message: "resolving hostnames…"})
	}

	close(names)
	nameWG.Wait()

	p = progress()
	if ctx.Err() != nil {
		safeEmit(Event{Kind: "error", Progress: &p, Message: "scan cancelled"})
		return
	}
	safeEmit(Event{Kind: "done", Progress: &p})
}
