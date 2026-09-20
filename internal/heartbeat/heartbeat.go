// Package heartbeat replaces the old app-level sprout heartbeat
// (internal/natsapi's probeSprout, a synchronous NATS request/reply ping
// with a 3s worst-case timeout — see docs/design/grlx-master-plan.md
// Phase 1) with Valkey TTL keys driven directly by NATS's own connection
// lifecycle: farmer subscribes to $SYS.ACCOUNT.*.CONNECT/DISCONNECT on its
// bus (as the SYS account — see internal/pki.ConnectSystemAccount) and
// sets/deletes a Valkey key per sprout as connections come and go. A
// GetSprout/ListSprouts call then answers "is this sprout online" with a
// single Valkey read instead of a live round trip to the sprout itself.
//
// Correlating an event to a sprout: nats-server's ConnectEventMsg/
// DisconnectEventMsg carry ClientInfo.User, which for a JWT-authenticated
// connection is the User JWT's subject — i.e. the sprout's NKey public
// key (see internal/pki/jwtusers.go's mintOrReuseUserJWT, which mints
// each sprout's User JWT with Subject = its NKey pubkey). This package
// reverse-looks that up via pki.SproutIDForNKey, which also acts as the
// filter for events that aren't a sprout at all (farmer's own connection,
// a grlx CLI admin, or the SYS push user itself) — those simply fail the
// lookup and are ignored.
package heartbeat

import (
	"context"
	"encoding/json"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/valkey-io/valkey-go"

	"github.com/gogrlx/grlx/v2/internal/config"
	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/gogrlx/grlx/v2/internal/pki"
)

// TTL bounds how long a heartbeat key survives without a fresh CONNECT.
// DISCONNECT deletes the key immediately, so under normal operation TTL
// expiry never fires — it's a safety net for a missed DISCONNECT (e.g.
// the bus process dying before it can publish one), so a crashed bus
// doesn't leave every sprout looking online forever.
const TTL = 5 * time.Minute

const keyPrefix = "grlx:heartbeat:"

// client is the shared Valkey client. Nil until SetClient is called.
var client valkey.Client

// SetClient installs the Valkey client this package reads and writes
// through. Call once at startup.
func SetClient(c valkey.Client) { client = c }

// tenantID resolves the current tenant scope, matching the identical
// seam in internal/props, internal/pki, and internal/rbac's store.go
// files — see their doc comments for why this isn't yet a per-request
// value. Deliberately not using the CONNECT/DISCONNECT event's own
// Client.Account field: that's the tenant NATS Account's public key
// (nats-server's internal Account.Name), a different identifier space
// than config.FarmerOrganization, which is what every other PXC-backed
// store in this fork scopes by.
func tenantID() string {
	if config.FarmerOrganization != "" {
		return config.FarmerOrganization
	}
	return "default"
}

func keyFor(tenant, sproutID string) string {
	return keyPrefix + tenant + ":" + sproutID
}

// IsOnline reports whether sproutID currently holds a live heartbeat key.
func IsOnline(ctx context.Context, sproutID string) bool {
	if client == nil {
		return false
	}
	n, err := client.Do(ctx, client.B().Exists().Key(keyFor(tenantID(), sproutID)).Build()).ToInt64()
	return err == nil && n > 0
}

// clientInfo mirrors the fields this package needs from nats-server's
// server.ClientInfo (events.go) — only User (the authenticated pubkey) is
// used; Client.Account is deliberately not (see tenantID's doc comment).
type clientInfo struct {
	User string `json:"user"`
}

type connectOrDisconnectEvent struct {
	Client clientInfo `json:"client"`
}

// RegisterListener subscribes nc — a connection authenticated as the SYS
// account (see pki.ConnectSystemAccount) — to
// $SYS.ACCOUNT.*.CONNECT/DISCONNECT and maintains Valkey heartbeat keys
// from them. nc should be a long-lived, dedicated connection: this
// function returns once both subscriptions are registered, not when the
// listener stops.
func RegisterListener(nc *nats.Conn) error {
	if _, err := nc.Subscribe("$SYS.ACCOUNT.*.CONNECT", func(msg *nats.Msg) {
		handleConnect(msg.Data)
	}); err != nil {
		return err
	}
	if _, err := nc.Subscribe("$SYS.ACCOUNT.*.DISCONNECT", func(msg *nats.Msg) {
		handleDisconnect(msg.Data)
	}); err != nil {
		return err
	}
	return nil
}

func handleConnect(data []byte) {
	sproutID, ok := sproutIDFromEvent(data, "CONNECT")
	if !ok || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := client.B().Set().Key(keyFor(tenantID(), sproutID)).Value("1").Ex(TTL).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		log.Errorf("heartbeat: setting key for sprout %s: %v", sproutID, err)
	}
}

func handleDisconnect(data []byte) {
	sproutID, ok := sproutIDFromEvent(data, "DISCONNECT")
	if !ok || client == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := client.B().Del().Key(keyFor(tenantID(), sproutID)).Build()
	if err := client.Do(ctx, cmd).Error(); err != nil {
		log.Errorf("heartbeat: deleting key for sprout %s: %v", sproutID, err)
	}
}

// sproutIDFromEvent decodes a CONNECT/DISCONNECT event and resolves its
// authenticated pubkey to an accepted sprout ID. ok is false for a
// malformed event or a connection that isn't a currently-accepted sprout
// (farmer's own connection, a CLI admin, the SYS push user, or a sprout
// that was denied/deleted between connecting and this lookup) — none of
// those are errors worth logging, just events this package has nothing to
// do with.
func sproutIDFromEvent(data []byte, kind string) (string, bool) {
	var ev connectOrDisconnectEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		log.Errorf("heartbeat: decoding %s event: %v", kind, err)
		return "", false
	}
	sproutID, err := pki.SproutIDForNKey(ev.Client.User)
	if err != nil {
		return "", false
	}
	return sproutID, true
}
