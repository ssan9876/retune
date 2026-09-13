package adminapi

import (
	"encoding/json"
	"fmt"

	"retune/internal/protocol"
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
}
