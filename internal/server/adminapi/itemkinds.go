package adminapi

import (
	"encoding/json"
	"fmt"

	"retune/internal/protocol"
	"retune/internal/server/compliance"
)

// optionsParsers validates and canonicalises the options of an include
// assignment, by item kind. A kind that is not here is one this server does
// not implement: an assignment naming it could never do anything, so it is
// refused rather than stored.
var optionsParsers = map[string]func(json.RawMessage) ([]byte, error){
	protocol.ItemKindScript: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseDeploymentOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
	protocol.ItemKindProfile: func(raw json.RawMessage) ([]byte, error) {
		var opts protocol.ProfileOptions
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &opts); err != nil {
				return nil, fmt.Errorf("%w: profile options must be an object", protocol.ErrBadOptions)
			}
		}
		return json.Marshal(opts)
	},
	protocol.ItemKindApp: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseAppOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
	protocol.ItemKindAgent: func(raw json.RawMessage) ([]byte, error) {
		opts, err := protocol.ParseAgentOptions(raw)
		if err != nil {
			return nil, err
		}
		return opts.Marshal()
	},
	// A compliance policy has nothing to configure per assignment - unlike a
	// script or profile, the same policy always evaluates the same way - so
	// the only acceptable options are none at all.
	compliance.ItemKindCompliance: func(raw json.RawMessage) ([]byte, error) {
		if len(raw) == 0 {
			return nil, nil
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("%w: compliance takes no options", protocol.ErrBadOptions)
		}
		if v == nil {
			return nil, nil
		}
		if m, ok := v.(map[string]any); !ok || len(m) != 0 {
			return nil, fmt.Errorf("%w: compliance takes no options", protocol.ErrBadOptions)
		}
		return nil, nil
	},
}
