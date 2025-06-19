package main

// This is lifted from https://github.com/crowdsecurity/crowdsec/blob/master/pkg/models/decisions_stream_response.go
// We cannot use crowdsec as a dependency because it seems it's not compatible with WASI:
// 2025-06-18 17:45:45.658][1][error][wasm] [source/extensions/common/wasm/wasm_vm.cc:38] Failed to load Wasm module due to a missing import: wasi_snapshot_preview1.fd_readdir
// On top of that, the latest logrus release does not support WASI, so we would need to update it in crowdsec/have a replace directive to use the latest commit from master.

type Decision struct {

	// the duration of the decisions
	// Required: true
	Duration *string `json:"duration"`

	// (only relevant for GET ops) the unique id
	// Read Only: true
	ID int64 `json:"id,omitempty"`

	// the origin of the decision : cscli, crowdsec
	// Required: true
	Origin *string `json:"origin"`

	// scenario
	// Required: true
	Scenario *string `json:"scenario"`

	// the scope of decision : does it apply to an IP, a range, a username, etc
	// Required: true
	Scope *string `json:"scope"`

	// true if the decision result from a scenario in simulation mode
	// Read Only: true
	Simulated *bool `json:"simulated,omitempty"`

	// the type of decision, might be 'ban', 'captcha' or something custom. Ignored when watcher (cscli/crowdsec) is pushing to APIL.
	// Required: true
	Type *string `json:"type"`

	// the date until the decisions must be active
	Until string `json:"until,omitempty"`

	// only relevant for LAPI->CAPI, ignored for cscli->LAPI and crowdsec->LAPI
	// Read Only: true
	UUID string `json:"uuid,omitempty"`

	// the value of the decision scope : an IP, a range, a username, etc
	// Required: true
	Value *string `json:"value"`
}

type GetDecisionsResponse []*Decision

type DecisionsStreamResponse struct {

	// deleted
	Deleted GetDecisionsResponse `json:"deleted,omitempty"`

	// new
	New GetDecisionsResponse `json:"new,omitempty"`
}
