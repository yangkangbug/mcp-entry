package gateway

import (
	"encoding/json"
	"errors"
	"time"
)

// TimeoutConfig is administrator-only, per fixed system. When present all three
// millisecond values are required. Omit the entire object for legacy defaults.
// ResponseHeaderMS is a per-request ceiling, clipped by the operation deadline.
type TimeoutConfig struct {
	DiscoveryMS      int `json:"discovery_ms"`
	CallMS           int `json:"call_ms"`
	ResponseHeaderMS int `json:"response_header_ms"`
}

type timeoutBudgets struct{ discovery, call, responseHeader, client time.Duration }

func resolveTimeouts(c *TimeoutConfig) (timeoutBudgets, error) {
	b := timeoutBudgets{5 * time.Second, 10 * time.Second, 5 * time.Second, 12 * time.Second}
	if c == nil {
		return b, nil
	}
	for _, v := range []int{c.DiscoveryMS, c.CallMS, c.ResponseHeaderMS} {
		if v <= 0 || v > 120000 {
			return timeoutBudgets{}, errors.New("timeouts must contain positive milliseconds no greater than 120000")
		}
	}
	if c.ResponseHeaderMS > max(c.DiscoveryMS, c.CallMS) {
		return timeoutBudgets{}, errors.New("response-header timeout exceeds all operation budgets")
	}
	b.discovery = time.Duration(c.DiscoveryMS) * time.Millisecond
	b.call = time.Duration(c.CallMS) * time.Millisecond
	b.responseHeader = time.Duration(c.ResponseHeaderMS) * time.Millisecond
	b.client = max(b.discovery, b.call) + 2*time.Second
	return b, nil
}

func (s System) timeoutBudgets() timeoutBudgets {
	if s.budgets.call != 0 {
		return s.budgets
	}
	b, _ := resolveTimeouts(s.Timeouts) // Validated by New before any operation.
	return b
}

func (c *TimeoutConfig) UnmarshalJSON(data []byte) error {
	fields, err := uniqueObjectFields(data)
	if err != nil {
		return err
	}
	if len(fields) != 3 {
		return errors.New("timeouts requires all three fields")
	}
	var decoded TimeoutConfig
	for key, value := range fields {
		var destination *int
		switch key {
		case "discovery_ms":
			destination = &decoded.DiscoveryMS
		case "call_ms":
			destination = &decoded.CallMS
		case "response_header_ms":
			destination = &decoded.ResponseHeaderMS
		default:
			return errors.New("unknown timeout field")
		}
		if err := json.Unmarshal(value, destination); err != nil {
			return err
		}
	}
	if _, err := resolveTimeouts(&decoded); err != nil {
		return err
	}
	*c = decoded
	return nil
}
