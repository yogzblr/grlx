package handlers

// POST /v1/enroll: design doc §3.2
// (docs/design/cloudxp-machine-manager-api-design.md,
// docs/design/grlx-envoy-enrollment-design.md). FLAG FOR SECURITY REVIEW
// per the task brief — see internal/pki/enroll.go's doc comment for why
// every failure here, at every layer, collapses to the same generic
// response.
//
// Deliberately not wrapped in Auth (see routers.go): an enrolling sprout
// has no JWT yet. It's still served over the same TLS-terminated farmer
// API server as GetCertificate/PutNKey, and is meant to sit behind Envoy's
// own IP-based rate limiting at the DMZ edge (the one route deliberately
// without a JWT gate — see the design doc's "Why this is safe" section).

import (
	"encoding/json"
	"net/http"

	log "github.com/gogrlx/grlx/v2/internal/log"

	"github.com/gogrlx/grlx/v2/internal/config"
	"github.com/gogrlx/grlx/v2/internal/pki"
)

type enrollRequest struct {
	JoinToken string `json:"join_token"`
	NKeyPub   string `json:"nkey_pub"`
	Hostname  string `json:"hostname"`
}

// enrollSuccessResponse is design doc §3.2's success shape, plus
// nkey_identity and tenant_x25519_pub per
// grlx-envoy-enrollment-design.md's "Response, in one round trip" —
// everything the sprout needs for every subsequent interaction, issued
// atomically here rather than across several separate exchanges.
//
// jwt and gateway_jwt are two different tokens for two different
// validators, per the "Gateway JWT Companion Token" brief: jwt is the
// native NATS User JWT nats-server itself validates (alg:ed25519-nkey);
// gateway_jwt is a standard alg:EdDSA JWS (internal/gatewayjwt) for
// Envoy's jwt_authn-gated wss:// and recipe-download routes, since
// Envoy — unlike nats-server — can't be taught NATS's own JWT dialect.
type enrollSuccessResponse struct {
	SproutID        string   `json:"sprout_id"`
	JWT             string   `json:"jwt"`
	GatewayJWT      string   `json:"gateway_jwt"`
	NKeyIdentity    string   `json:"nkey_identity"`
	TenantX25519Pub string   `json:"tenant_x25519_pub"`
	NatsURLs        []string `json:"nats_urls"`
}

// enrollErrorResponse is design doc §3.4's single generic failure shape.
type enrollErrorResponse struct {
	Error string `json:"error"`
}

// Enroll handles POST /v1/enroll. Every failure path — a malformed
// request body, a missing field, or any failure inside pki.Enroll
// (unknown/malformed token, hash mismatch, revoked, expired, exhausted, a
// lost redemption race) — writes the exact same status and body, by
// design (§3.4): distinguishing them would hand an attacker a free oracle
// for enumerating key_ids or timing a race against expiry.
func Enroll(w http.ResponseWriter, r *http.Request) {
	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warnf("enroll: invalid request body: %v", err)
		writeEnrollFailed(w)
		return
	}
	if req.JoinToken == "" || req.NKeyPub == "" || req.Hostname == "" {
		log.Warnf("enroll: request missing a required field")
		writeEnrollFailed(w)
		return
	}

	result, err := pki.Enroll(r.Context(), req.JoinToken, req.NKeyPub, req.Hostname)
	if err != nil {
		// pki.Enroll has already logged the specific reason; nothing more
		// to add here.
		writeEnrollFailed(w)
		return
	}

	resp := enrollSuccessResponse{
		SproutID:        result.SproutID,
		JWT:             result.JWT,
		GatewayJWT:      result.GatewayJWT,
		NKeyIdentity:    req.NKeyPub,
		TenantX25519Pub: result.TenantX25519Pub,
		NatsURLs:        enrollBusURLs(),
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Errorf("enroll: writing success response: %v", err)
	}
}

func writeEnrollFailed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	if err := json.NewEncoder(w).Encode(enrollErrorResponse{Error: "enrollment_failed"}); err != nil {
		log.Errorf("enroll: writing failure response: %v", err)
	}
}

// enrollBusURLs returns the operator-configured externally-reachable
// wss:// bus addresses (config.SproutBusURLs), falling back to a
// single-node URL derived from this farmer's own interface/websocket port
// when none are configured — good enough for local/dev, not a substitute
// for setting SproutBusURLs to the real Envoy-fronted DMZ addresses in
// production.
func enrollBusURLs() []string {
	if len(config.SproutBusURLs) > 0 {
		return config.SproutBusURLs
	}
	return []string{"wss://" + config.FarmerInterface + ":" + config.FarmerWSPort}
}
