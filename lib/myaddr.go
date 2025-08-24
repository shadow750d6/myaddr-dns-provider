// Package myaddr implements a DNS provider for managing DNS records at myaddr.
package myaddr

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/libdns/libdns"
)

// Provider implements libdns.Provider for myaddr.
type Provider struct {
	Key string
}

// AppendRecords adds records to a zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.SetRecords(ctx, zone, records)
}

// SetRecords sets the records in a zone, either by updating existing records or creating new ones.
// It returns the records that were set.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	for _, r := range records {
		if r.RR().Type != "TXT" {
			return nil, fmt.Errorf("only TXT records are supported")
		}
		if !strings.HasPrefix(r.RR().Name, "_acme-challenge.") {
			return nil, fmt.Errorf("only ACME challenge records are supported")
		}

		payload := map[string]string{
			"key":            p.Key,
			"acme_challenge": r.RR().Data,
		}
		jsonPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal JSON payload: %w", err)
		}
		httpClient := &http.Client{}
		resp, err := httpClient.Post("https://myaddr.tools/update", "application/json", strings.NewReader(string(jsonPayload)))
		if err != nil {
			return nil, fmt.Errorf("failed to update record: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("failed to update record: %s", resp.Status)
		}
	}
	return records, nil
}

// DeleteRecords deletes records from a zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Automatically expires.
	return nil, nil
}

// Interface guards
var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
