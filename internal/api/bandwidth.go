package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nullbore/nullbore-server/internal/store"
)

// BandwidthReporter periodically aggregates per-client bandwidth from the
// tunnel store and POSTs deltas to the dashboard's /internal/report-bandwidth.
type BandwidthReporter struct {
	store    *store.Store
	target   string // dashboard base URL (e.g. https://nullbore.com)
	secret   string // internal auth secret
	interval time.Duration
	client   *http.Client

	mu       sync.Mutex
	reported map[string]bandwidthSnapshot // client_id → last reported totals
}

type bandwidthSnapshot struct {
	bytesIn  int64
	bytesOut int64
}

// NewBandwidthReporter creates a reporter that flushes every interval.
func NewBandwidthReporter(s *store.Store, dashboardURL, secret string, interval time.Duration) *BandwidthReporter {
	return &BandwidthReporter{
		store:    s,
		target:   dashboardURL,
		secret:   secret,
		interval: interval,
		client:   &http.Client{Timeout: 10 * time.Second},
		reported: make(map[string]bandwidthSnapshot),
	}
}

// Start begins the periodic reporting loop.
func (br *BandwidthReporter) Start() {
	go func() {
		// Initial delay to let things settle
		time.Sleep(10 * time.Second)
		br.flush()

		ticker := time.NewTicker(br.interval)
		defer ticker.Stop()
		for range ticker.C {
			br.flush()
		}
	}()
	slog.Info("bandwidth reporter started", "interval", br.interval, "target", br.target)
}

func (br *BandwidthReporter) flush() {
	// Get per-client totals from the store
	totals, err := br.store.BandwidthByClient()
	if err != nil {
		slog.Error("bandwidth flush: failed to query", "error", err)
		return
	}

	br.mu.Lock()
	defer br.mu.Unlock()

	for clientID, current := range totals {
		prev := br.reported[clientID]
		deltaIn := current.BytesIn - prev.bytesIn
		deltaOut := current.BytesOut - prev.bytesOut

		if deltaIn <= 0 && deltaOut <= 0 {
			continue // no new traffic
		}

		if err := br.report(clientID, deltaIn, deltaOut); err != nil {
			slog.Warn("bandwidth report failed", "client", clientID, "error", err)
			continue // don't update snapshot so we retry next cycle
		}

		br.reported[clientID] = bandwidthSnapshot{
			bytesIn:  current.BytesIn,
			bytesOut: current.BytesOut,
		}
	}
}

func (br *BandwidthReporter) report(userID string, bytesIn, bytesOut int64) error {
	body, _ := json.Marshal(map[string]interface{}{
		"user_id":   userID,
		"bytes_in":  bytesIn,
		"bytes_out": bytesOut,
	})

	req, err := http.NewRequest("POST", br.target+"/internal/report-bandwidth", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Secret", br.secret)

	resp, err := br.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return &httpError{status: resp.StatusCode}
	}
	return nil
}

type httpError struct {
	status int
}

func (e *httpError) Error() string {
	return http.StatusText(e.status)
}
