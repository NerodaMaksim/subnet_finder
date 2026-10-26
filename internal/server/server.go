package server

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"

	"github.com/NerodaMaksim/subnet_finder/internal/netinfo"
	"github.com/NerodaMaksim/subnet_finder/internal/scanner"
)

type scanRequest struct {
	CIDRs []string `json:"cidrs"`
}

func New(web fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/subnets", handleSubnets)
	mux.HandleFunc("POST /api/scan", handleScan)
	mux.Handle("/", http.FileServer(http.FS(web)))
	return mux
}

func handleSubnets(w http.ResponseWriter, r *http.Request) {
	subnets, err := netinfo.List()
	if err != nil {
		log.Printf("list subnets: %v", err)
		http.Error(w, "failed to list subnets", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subnets": subnets})
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("decode scan request: %v", err)
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	subnets, err := netinfo.List()
	if err != nil {
		log.Printf("list subnets for scan: %v", err)
		http.Error(w, "failed to list subnets", http.StatusInternalServerError)
		return
	}

	cidrs, err := allowedCIDRs(req.CIDRs, subnets)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	log.Printf("scan started: %v", cidrs)
	scanner.Scan(r.Context(), cidrs, func(ev scanner.Event) {
		payload := map[string]any{}
		if ev.Progress != nil {
			payload["progress"] = ev.Progress
		}
		if ev.Host != nil {
			payload["host"] = ev.Host
		}
		if ev.Message != "" {
			payload["message"] = ev.Message
		}
		if err := writeSSE(w, flusher, ev.Kind, payload); err != nil {
			log.Printf("write sse: %v", err)
		}
	})
}

func allowedCIDRs(requested []string, subnets []netinfo.Subnet) ([]string, error) {
	if len(requested) == 0 {
		return nil, fmt.Errorf("no subnets selected")
	}

	out := make([]string, 0, len(requested))
	seen := make(map[string]struct{})
	for _, cidr := range requested {
		if _, ipnet, err := net.ParseCIDR(cidr); err != nil || ipnet.IP.To4() == nil {
			return nil, fmt.Errorf("invalid ipv4 cidr: %s", cidr)
		}
		if !netinfo.ContainsCIDR(subnets, cidr) {
			return nil, fmt.Errorf("cidr is not an available local subnet: %s", cidr)
		}
		if _, ok := seen[cidr]; ok {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}
