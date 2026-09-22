package natsapi

import (
	"encoding/json"

	"github.com/gogrlx/grlx/v2/internal/pki"
)

func handlePKIList(_ json.RawMessage) (any, error) {
	return pki.ListNKeysByType(pki.CurrentTenantID()), nil
}

func handlePKIAccept(params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.AcceptNKey(pki.CurrentTenantID(), km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIReject(params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.RejectNKey(pki.CurrentTenantID(), km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDeny(params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.DenyNKey(pki.CurrentTenantID(), km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIUnaccept(params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.UnacceptNKey(pki.CurrentTenantID(), km.SproutID, "")
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}

func handlePKIDelete(params json.RawMessage) (any, error) {
	var km pki.KeyManager
	if err := json.Unmarshal(params, &km); err != nil {
		return nil, err
	}
	err := pki.DeleteNKey(pki.CurrentTenantID(), km.SproutID)
	if err != nil {
		return nil, err
	}
	return map[string]bool{"success": true}, nil
}
