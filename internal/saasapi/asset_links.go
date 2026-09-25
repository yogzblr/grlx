// Security-sensitive: asset linking and asset_id → sprout resolution.
// FLAG FOR SECURITY REVIEW per the task brief — §1.4's `unresolved` list
// is a tenant-isolation property, not just a response shape: it must
// never let a caller tell "this asset_id was never linked" apart from
// "this asset_id is linked, but to another tenant's sprout". Every
// caller-visible outcome in this file is built so those two cases (and
// "this sprout doesn't exist" vs. "this sprout is another tenant's")
// produce byte-identical responses.
package saasapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"gorm.io/gorm"
)

const (
	assetLinkIDPrefix = "al_"

	// maxAssetIDsPerLookup is §1.4's (and §4 "Pagination"'s) cap on
	// caller-supplied asset_ids per GET .../sprouts call.
	maxAssetIDsPerLookup = 100

	// maxAssetIDLen / maxSproutIDLen match AssetLink's column sizes. An
	// ID longer than its column can never have been linked, so it's
	// rejected up front rather than sent to the database.
	maxAssetIDLen  = 191
	maxSproutIDLen = 253

	// farmerSproutsTable is farmer's sprout registry, read (never
	// written) through the saas service account's SELECT grant on
	// farmer.* (§4.1). This package relies on exactly these columns:
	//
	//	id         the sprout_id (the value asset_links.sprout_id holds)
	//	tenant_id  the owning tenant
	//	key_state  e.g. "accepted" (§1.4's response field)
	//	connected  boolean (§1.4's response field)
	farmerSproutsTable = "farmer.sprouts"
)

type linkAssetRequest struct {
	AssetID string `json:"asset_id"`
}

type assetLinkResponse struct {
	SproutID string    `json:"sprout_id"`
	AssetID  string    `json:"asset_id"`
	LinkedAt time.Time `json:"linked_at"`
}

// sproutByAssetItem is one §1.4 result row.
type sproutByAssetItem struct {
	SproutID  string `json:"sprout_id"`
	AssetID   string `json:"asset_id"`
	KeyState  string `json:"key_state"`
	Connected bool   `json:"connected"`
}

type sproutsByAssetResponse struct {
	Results    []sproutByAssetItem `json:"results"`
	Unresolved []string            `json:"unresolved"`
}

// LinkAsset handles POST /tenants/{tenant_id}/sprouts/{sprout_id}/asset-link
// (design doc §1.3).
//
// The sprout must belong to the caller's tenant in farmer.sprouts; a
// sprout that doesn't exist and one that belongs to another tenant are
// both 404 sprout_not_found (§4 "Tenant safety"). Without this check a
// tenant could create a link row pointing at another tenant's sprout_id,
// squatting on it (sprout_id is globally UNIQUE, §4.2) so its real owner
// could never link it.
//
// Re-linking the exact same (sprout, asset) pair is idempotent: 200 with
// the existing link. Any other collision with the global sprout_id /
// asset_id uniqueness is 409 asset_link_conflict, with one fixed body
// regardless of which row it collided with or which tenant owns that
// row. See the PR description for the residual oracle this leaves: a
// 409 on an asset_id the caller can't see via §1.4 implies another
// tenant has linked it — inherent to §4.2 declaring asset_id globally
// UNIQUE.
//
// Not rate-limited: a tenant can create at most one link per sprout it
// owns, so the table can't grow faster than the tenant's own fleet.
func LinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	sproutID := r.PathValue("sprout_id")
	if !tenantExists(w, tenantID) {
		return
	}

	var req linkAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be valid JSON")
		return
	}
	assetID := strings.TrimSpace(req.AssetID)
	if assetID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is required")
		return
	}
	if len(assetID) > maxAssetIDLen {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is too long")
		return
	}

	owned, err := sproutOwnedByTenant(tenantID, sproutID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to look up sprout")
		return
	}
	if !owned {
		writeError(w, http.StatusNotFound, "sprout_not_found", "no such sprout")
		return
	}

	linkID, err := newID(assetLinkIDPrefix)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to generate asset link id")
		return
	}
	link := AssetLink{
		ID:       linkID,
		TenantID: tenantID,
		SproutID: sproutID,
		AssetID:  assetID,
		LinkedAt: time.Now().UTC(),
	}

	// Insert first and let the UNIQUE indexes arbitrate, rather than a
	// check-then-insert that two concurrent requests could both pass.
	// Only if the insert fails do we work out why.
	if createErr := db.Create(&link).Error; createErr != nil {
		var existing AssetLink
		err := db.Where("tenant_id = ? AND sprout_id = ? AND asset_id = ?", tenantID, sproutID, assetID).
			First(&existing).Error
		if err == nil {
			writeJSON(w, http.StatusOK, toAssetLinkResponse(existing))
			return
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to link asset")
			return
		}
		conflict, err := assetLinkConflictExists(sproutID, assetID)
		if err != nil || !conflict {
			// Not a uniqueness collision: a genuine write failure.
			writeError(w, http.StatusInternalServerError, "internal_error", "failed to link asset")
			return
		}
		writeError(w, http.StatusConflict, "asset_link_conflict",
			"this sprout or asset_id is already linked; unlink it first")
		return
	}

	writeJSON(w, http.StatusCreated, toAssetLinkResponse(link))
}

// UnlinkAsset handles DELETE
// /tenants/{tenant_id}/sprouts/{sprout_id}/asset-link (design doc §1.3).
// The delete's WHERE clause carries tenant_id as well as sprout_id, so
// another tenant's link is indistinguishable from no link: both 404
// asset_link_not_found.
func UnlinkAsset(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	sproutID := r.PathValue("sprout_id")
	if !tenantExists(w, tenantID) {
		return
	}

	res := db.Where("tenant_id = ? AND sprout_id = ?", tenantID, sproutID).Delete(&AssetLink{})
	if res.Error != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to unlink asset")
		return
	}
	if res.RowsAffected == 0 {
		writeError(w, http.StatusNotFound, "asset_link_not_found", "no asset link for this sprout")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sprout_id": sproutID, "unlinked": true})
}

// ListSproutsByAssetIDs handles GET
// /tenants/{tenant_id}/sprouts?asset_ids=a1,a2,... (design doc §1.4).
//
// Resolution is the single local SQL join §1.4 specifies — no NATS call.
// An asset_id the join doesn't return lands in `unresolved`, whatever the
// reason: never linked, linked by another tenant, or linked here but its
// sprout is missing from (or owned by another tenant in) farmer.sprouts.
// The handler never looks at *why* an id didn't resolve, so it has no way
// to leak the difference.
func ListSproutsByAssetIDs(w http.ResponseWriter, r *http.Request) {
	tenantID := r.PathValue("tenant_id")
	if !tenantExists(w, tenantID) {
		return
	}

	assetIDs, ok := parseAssetIDs(w, r.URL.Query()["asset_ids"])
	if !ok {
		return
	}

	rows, err := resolveAssetIDs(tenantID, assetIDs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to resolve asset ids")
		return
	}

	byAsset := make(map[string]sproutByAssetItem, len(rows))
	for _, row := range rows {
		byAsset[row.AssetID] = row
	}
	resp := sproutsByAssetResponse{
		Results:    make([]sproutByAssetItem, 0, len(rows)),
		Unresolved: make([]string, 0),
	}
	for _, id := range assetIDs {
		if row, found := byAsset[id]; found {
			resp.Results = append(resp.Results, row)
		} else {
			resp.Unresolved = append(resp.Unresolved, id)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseAssetIDs flattens asset_ids (comma-separated, optionally repeated
// as asset_ids=a1&asset_ids=a2) into a deduplicated, order-preserving
// list. More than maxAssetIDsPerLookup ids is 400 too_many_asset_ids,
// counted before deduplication and checked as ids are scanned, so an
// oversized list is rejected without being fully split.
func parseAssetIDs(w http.ResponseWriter, values []string) ([]string, bool) {
	var ids []string
	seen := make(map[string]bool)
	count := 0
	for _, v := range values {
		for rest, more := v, true; more; {
			var id string
			id, rest, more = strings.Cut(rest, ",")
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			count++
			if count > maxAssetIDsPerLookup {
				writeErrorDetails(w, http.StatusBadRequest, "too_many_asset_ids",
					"at most 100 asset_ids per request", map[string]any{"max": maxAssetIDsPerLookup})
				return nil, false
			}
			if len(id) > maxAssetIDLen {
				writeError(w, http.StatusBadRequest, "invalid_request", "asset_id is too long")
				return nil, false
			}
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "asset_ids is required")
		return nil, false
	}
	return ids, true
}

// resolveAssetIDs is §1.4's single local join of farmer.sprouts against
// saas.asset_links. Beyond the design doc's SQL, the join also requires
// s.tenant_id = a.tenant_id: LinkAsset already refuses to link another
// tenant's sprout, but this keeps the read side from ever returning
// another tenant's key_state/connected even if a bad link row exists.
func resolveAssetIDs(tenantID string, assetIDs []string) ([]sproutByAssetItem, error) {
	var rows []sproutByAssetItem
	err := db.Raw(`SELECT a.asset_id AS asset_id, s.id AS sprout_id, s.key_state AS key_state, s.connected AS connected
FROM `+farmerSproutsTable+` s
JOIN `+AssetLink{}.TableName()+` a ON a.sprout_id = s.id AND a.tenant_id = s.tenant_id
WHERE a.tenant_id = ? AND a.asset_id IN ?`, tenantID, assetIDs).Scan(&rows).Error
	return rows, err
}

// sproutOwnedByTenant reports whether farmer.sprouts has sprout_id under
// tenant_id — false for both a missing sprout and another tenant's.
func sproutOwnedByTenant(tenantID, sproutID string) (bool, error) {
	if sproutID == "" || len(sproutID) > maxSproutIDLen {
		return false, nil
	}
	var count int64
	err := db.Table(farmerSproutsTable).Where("tenant_id = ? AND id = ?", tenantID, sproutID).Count(&count).Error
	return count > 0, err
}

// assetLinkConflictExists reports whether some link row already holds
// sproutID or assetID. Deliberately not tenant-scoped: it's checking the
// global UNIQUE constraints of §4.2, not resolving an id for the caller,
// and its answer only ever surfaces as LinkAsset's fixed 409 body.
func assetLinkConflictExists(sproutID, assetID string) (bool, error) {
	var count int64
	err := db.Model(&AssetLink{}).Where("sprout_id = ? OR asset_id = ?", sproutID, assetID).Count(&count).Error
	return count > 0, err
}

func toAssetLinkResponse(l AssetLink) assetLinkResponse {
	return assetLinkResponse{SproutID: l.SproutID, AssetID: l.AssetID, LinkedAt: l.LinkedAt}
}
