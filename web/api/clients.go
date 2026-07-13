package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/djylb/nps/lib/file"
	webservice "github.com/djylb/nps/web/service"
)

type nodeClientResourcePayload struct {
	ID                     int    `json:"id"`
	OwnerUserID            int    `json:"owner_user_id"`
	ManagerUserIDs         []int  `json:"manager_user_ids,omitempty"`
	VerifyKey              string `json:"verify_key"`
	Mode                   string `json:"mode,omitempty"`
	Addr                   string `json:"addr,omitempty"`
	LocalAddr              string `json:"local_addr,omitempty"`
	Remark                 string `json:"remark"`
	Status                 bool   `json:"status"`
	IsConnect              bool   `json:"is_connect"`
	NoStore                bool   `json:"no_store"`
	ExpireAt               int64  `json:"expire_at"`
	FlowLimitTotalBytes    int64  `json:"flow_limit_total_bytes"`
	RateLimitTotalBps      int    `json:"rate_limit_total_bps"`
	MaxConnections         int    `json:"max_connections"`
	NowConn                int    `json:"now_conn"`
	MaxTunnelNum           int    `json:"max_tunnel_num"`
	ConfigConnAllow        bool   `json:"config_conn_allow"`
	Version                string `json:"version,omitempty"`
	SourceType             string `json:"source_type,omitempty"`
	SourcePlatformID       string `json:"source_platform_id,omitempty"`
	SourceActorID          string `json:"source_actor_id,omitempty"`
	DevicePublicKey        string `json:"device_public_key,omitempty"`
	DeviceKeyID            string `json:"device_key_id,omitempty"`
	DeviceEnrolledAt       int64  `json:"device_enrolled_at,omitempty"`
	Revision               int64  `json:"revision"`
	UpdatedAt              int64  `json:"updated_at"`
	BridgeInBytes          int64  `json:"bridge_in_bytes"`
	BridgeOutBytes         int64  `json:"bridge_out_bytes"`
	BridgeTotalBytes       int64  `json:"bridge_total_bytes"`
	ServiceInBytes         int64  `json:"service_in_bytes"`
	ServiceOutBytes        int64  `json:"service_out_bytes"`
	ServiceTotalBytes      int64  `json:"service_total_bytes"`
	TotalInBytes           int64  `json:"total_in_bytes"`
	TotalOutBytes          int64  `json:"total_out_bytes"`
	TotalBytes             int64  `json:"total_bytes"`
	BridgeNowRateInBps     int64  `json:"bridge_now_rate_in_bps"`
	BridgeNowRateOutBps    int64  `json:"bridge_now_rate_out_bps"`
	BridgeNowRateTotalBps  int64  `json:"bridge_now_rate_total_bps"`
	ServiceNowRateInBps    int64  `json:"service_now_rate_in_bps"`
	ServiceNowRateOutBps   int64  `json:"service_now_rate_out_bps"`
	ServiceNowRateTotalBps int64  `json:"service_now_rate_total_bps"`
	TotalNowRateInBps      int64  `json:"total_now_rate_in_bps"`
	TotalNowRateOutBps     int64  `json:"total_now_rate_out_bps"`
	TotalNowRateTotalBps   int64  `json:"total_now_rate_total_bps"`
	EntryACLMode           int    `json:"entry_acl_mode"`
	EntryACLRules          string `json:"entry_acl_rules,omitempty"`
	CreateTime             string `json:"create_time,omitempty"`
	LastOnlineTime         string `json:"last_online_time,omitempty"`
	ConnectionCount        int    `json:"connection_count"`
	Config                 struct {
		User     string `json:"user,omitempty"`
		Compress bool   `json:"compress"`
		Crypt    bool   `json:"crypt"`
	} `json:"config"`
}

type nodeClientConnectionPayload struct {
	UUID                   string `json:"uuid"`
	Version                string `json:"version,omitempty"`
	BaseVer                int    `json:"base_ver"`
	RemoteAddr             string `json:"remote_addr,omitempty"`
	LocalAddr              string `json:"local_addr,omitempty"`
	HasSignal              bool   `json:"has_signal"`
	HasTunnel              bool   `json:"has_tunnel"`
	IsOnline               bool   `json:"is_online"`
	ConnectedAt            int64  `json:"connected_at"`
	ConnectedAtText        string `json:"connected_at_text,omitempty"`
	NowConn                int    `json:"now_conn"`
	BridgeInBytes          int64  `json:"bridge_in_bytes"`
	BridgeOutBytes         int64  `json:"bridge_out_bytes"`
	BridgeTotalBytes       int64  `json:"bridge_total_bytes"`
	ServiceInBytes         int64  `json:"service_in_bytes"`
	ServiceOutBytes        int64  `json:"service_out_bytes"`
	ServiceTotalBytes      int64  `json:"service_total_bytes"`
	TotalInBytes           int64  `json:"total_in_bytes"`
	TotalOutBytes          int64  `json:"total_out_bytes"`
	TotalBytes             int64  `json:"total_bytes"`
	BridgeNowRateInBps     int64  `json:"bridge_now_rate_in_bps"`
	BridgeNowRateOutBps    int64  `json:"bridge_now_rate_out_bps"`
	BridgeNowRateTotalBps  int64  `json:"bridge_now_rate_total_bps"`
	ServiceNowRateInBps    int64  `json:"service_now_rate_in_bps"`
	ServiceNowRateOutBps   int64  `json:"service_now_rate_out_bps"`
	ServiceNowRateTotalBps int64  `json:"service_now_rate_total_bps"`
	TotalNowRateInBps      int64  `json:"total_now_rate_in_bps"`
	TotalNowRateOutBps     int64  `json:"total_now_rate_out_bps"`
	TotalNowRateTotalBps   int64  `json:"total_now_rate_total_bps"`
}

type nodeClientPingPayload struct {
	ID  int `json:"id"`
	RTT int `json:"rtt"`
}

func (a *App) NodeClients(c Context) {
	access := a.nodeActorAccessFromContext(c)
	offset := requestIntValue(c, "offset")
	limit := requestIntValue(c, "limit")
	items, total, err := a.listNodeClients(c, access)
	if err != nil {
		respondNodeResourceData(c, nodeResourceListPayload{}, err)
		return
	}
	offset, limit, returned, hasMore := nodeListPagination(offset, limit, len(items), total)
	respondNodeResourceData(c, nodeResourceListPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Offset:      offset,
		Limit:       limit,
		Returned:    returned,
		Total:       total,
		HasMore:     hasMore,
		Items:       items,
	}, nil)
}

func (a *App) NodeClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	client, err := a.Services.Clients.Get(requestIntValue(c, "id"))
	if err == nil {
		switch {
		case client == nil:
			err = webservice.ErrClientNotFound
		case !access.scope.AllowsClient(client):
			err = webservice.ErrForbidden
		default:
			client = sanitizeNodeClient(access.scope, client)
		}
	}
	item := a.nodeClientResource(access.actor, client)
	respondNodeResourceData(c, nodeResourceItemPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Item:        item,
	}, err)
}

func (a *App) NodeClientConnections(c Context) {
	access := a.nodeActorAccessFromContext(c)
	client, err := a.Services.Clients.Get(requestIntValue(c, "id"))
	if err == nil {
		switch {
		case client == nil:
			err = webservice.ErrClientNotFound
		case !access.scope.AllowsClient(client):
			err = webservice.ErrForbidden
		}
	}
	items := []nodeClientConnectionPayload{}
	if err == nil {
		items = newNodeClientConnections(a.clientConnections(client.Id))
	}
	respondNodeResourceData(c, nodeResourceListPayload{
		ConfigEpoch: a.runtimeIdentity().ConfigEpoch(),
		GeneratedAt: time.Now().Unix(),
		Offset:      0,
		Limit:       len(items),
		Returned:    len(items),
		Total:       len(items),
		HasMore:     false,
		Items:       items,
	}, err)
}

func (a *App) NodeClientQRCode(c Context) {
	cfg := a.currentConfig()
	png, err := a.Services.Clients.BuildQRCode(webservice.ClientQRCodeInput{
		Text:    requestString(c, "text"),
		Account: requestString(c, "account"),
		Secret:  requestString(c, "secret"),
		AppName: cfg.App.Name,
	})
	if err != nil {
		if errors.Is(err, webservice.ErrClientQRCodeTextRequired) {
			respondManagementErrorMessage(c, http.StatusBadRequest, "qrcode_text_required", "missing text", nil)
			return
		}
		respondManagementErrorMessage(c, http.StatusInternalServerError, "qrcode_encode_failed", "QR encode failed", nil)
		return
	}
	c.SetResponseHeader("Cache-Control", "no-store")
	c.SetResponseHeader("Pragma", "no-cache")
	c.RespondData(http.StatusOK, "image/png", png)
}

func (a *App) NodePingClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	if id <= 0 {
		respondManagementErrorMessage(c, http.StatusBadRequest, "client_id_required", "missing client id", nil)
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionClientsRead,
		Ownership:  "client",
		ResourceID: id,
	}); err != nil {
		respondNodeResourceData(c, nodeResourceItemPayload{}, err)
		return
	}
	rtt, err := a.Services.Clients.Ping(id, c.RemoteAddr())
	if err != nil {
		respondNodeResourceData(c, nodeResourceItemPayload{}, err)
		return
	}
	configEpoch := a.runtimeIdentity().ConfigEpoch()
	generatedAt := time.Now().Unix()
	respondNodeResourceData(c, nodeResourceItemPayload{
		ConfigEpoch: configEpoch,
		GeneratedAt: generatedAt,
		Item: nodeClientPingPayload{
			ID:  id,
			RTT: rtt,
		},
	}, nil)
}

func (a *App) NodeClearClients(c Context) {
	access := a.nodeActorAccessFromContext(c)
	var body nodeClearClientsRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		respondMissingRequestField(c, "mode")
		return
	}
	var clientIDs []int
	if body.ClientIDs != nil {
		clientIDs = append([]int(nil), (*body.ClientIDs)...)
	}
	targetIDs, err := a.nodeClearClientTargetIDs(c, access, orderedUniquePositiveIDs(clientIDs))
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	for _, id := range targetIDs {
		if _, err := a.Services.Clients.Clear(id, mode, true); err != nil {
			respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
			return
		}
	}
	payload := map[string]interface{}{
		"mode":       mode,
		"client_ids": append([]int(nil), targetIDs...),
		"count":      len(targetIDs),
	}
	a.emitNodeResourceMutationEvent(c, "client.cleared", "client", "clear_all", payload)
	a.respondCompletedNodeMutation(c, "client", "clear_all", 0, payload)
}

func (a *App) nodeClearClientTargetIDs(c Context, access nodeActorAccess, requestedClientIDs []int) ([]int, error) {
	if len(requestedClientIDs) > 0 {
		targetIDs := make([]int, 0, len(requestedClientIDs))
		for _, id := range requestedClientIDs {
			if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
				Permission: webservice.PermissionClientsStatus,
				Ownership:  "client",
				ResourceID: id,
			}); err != nil {
				return nil, err
			}
			targetIDs = append(targetIDs, id)
		}
		return targetIDs, nil
	}
	visibility, ok, err := access.visibility(a)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	if !visibility.IsAdmin {
		return append([]int(nil), visibility.ClientIDs...), nil
	}
	result := a.Services.Clients.List(webservice.ListClientsInput{
		Offset:     0,
		Limit:      0,
		Host:       c.Host(),
		Visibility: visibility,
	})
	return nodeClientIDs(result.Rows), nil
}

func nodeClientIDs(clients []*file.Client) []int {
	if len(clients) == 0 {
		return nil
	}
	ids := make([]int, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}
		ids = append(ids, client.Id)
	}
	return orderedUniquePositiveIDs(ids)
}

func (a *App) listNodeClients(c Context, access nodeActorAccess) ([]nodeClientResourcePayload, int, error) {
	visibility, ok, err := access.visibility(a)
	if err != nil {
		return nil, 0, err
	}
	if !ok {
		return nil, 0, nil
	}
	result := a.Services.Clients.List(nodeListQueryFromContext(c).clientsInput(visibility))
	items := a.sanitizeNodeClients(access.actor, access.scope, result.Rows)
	return items, adjustedNodeListTotal(result.Total, len(result.Rows), len(items)), nil
}

func (a *App) sanitizeNodeClients(actor *Actor, scope webservice.NodeAccessScope, clients []*file.Client) []nodeClientResourcePayload {
	if len(clients) == 0 {
		return nil
	}
	items := make([]nodeClientResourcePayload, 0, len(clients))
	for _, client := range clients {
		if client == nil {
			continue
		}
		items = append(items, a.nodeClientResource(actor, sanitizeNodeClient(scope, client)))
	}
	return items
}

func sanitizeNodeClient(scope webservice.NodeAccessScope, client *file.Client) *file.Client {
	if client == nil {
		return nil
	}
	return webservice.CloneClientSnapshot(client)
}

func newNodeClientResource(client *file.Client) nodeClientResourcePayload {
	payload := nodeClientResourcePayload{}
	if client == nil {
		return payload
	}
	payload.ID = client.Id
	payload.OwnerUserID = client.OwnerID()
	payload.ManagerUserIDs = append([]int(nil), client.ManagerUserIDs...)
	payload.VerifyKey = client.VerifyKey
	payload.Mode = client.Mode
	payload.Addr = client.Addr
	payload.LocalAddr = client.LocalAddr
	payload.Remark = client.Remark
	payload.Status = client.Status
	payload.IsConnect = client.IsConnect
	payload.NoStore = client.NoStore
	payload.ExpireAt = client.EffectiveExpireAt()
	payload.FlowLimitTotalBytes = client.EffectiveFlowLimitBytes()
	payload.MaxConnections = client.MaxConn
	payload.NowConn = int(client.NowConn)
	payload.MaxTunnelNum = client.MaxTunnelNum
	payload.ConfigConnAllow = client.ConfigConnAllow
	payload.Version = client.Version
	payload.SourceType = client.SourceType
	payload.SourcePlatformID = client.SourcePlatformID
	payload.SourceActorID = client.SourceActorID
	payload.DevicePublicKey = client.DevicePublicKey
	payload.DeviceKeyID = client.DeviceKeyID
	payload.DeviceEnrolledAt = client.DeviceEnrolledAt
	payload.Revision = client.Revision
	payload.UpdatedAt = client.UpdatedAt
	payload.BridgeInBytes, payload.BridgeOutBytes, payload.BridgeTotalBytes = client.BridgeTrafficTotals()
	payload.ServiceInBytes, payload.ServiceOutBytes, payload.ServiceTotalBytes = client.ServiceTrafficTotals()
	payload.TotalInBytes, payload.TotalOutBytes, payload.TotalBytes = client.TotalTrafficTotals()
	payload.EntryACLMode = client.EntryAclMode
	payload.EntryACLRules = client.EntryAclRules
	payload.CreateTime = client.CreateTime
	payload.LastOnlineTime = client.LastOnlineTime
	payload.ConnectionCount = 0
	payload.RateLimitTotalBps = webservice.ManagementRateLimitToBps(client.RateLimit)
	payload.BridgeNowRateInBps, payload.BridgeNowRateOutBps, payload.BridgeNowRateTotalBps = client.BridgeRateTotals()
	payload.ServiceNowRateInBps, payload.ServiceNowRateOutBps, payload.ServiceNowRateTotalBps = client.ServiceRateTotals()
	payload.TotalNowRateInBps, payload.TotalNowRateOutBps, payload.TotalNowRateTotalBps = client.TotalRateTotals()
	if client.Cnf != nil {
		payload.Config.User = client.Cnf.U
		payload.Config.Compress = client.Cnf.Compress
		payload.Config.Crypt = client.Cnf.Crypt
	}
	return payload
}

func newEmbeddedNodeClientResource(client *file.Client) nodeClientResourcePayload {
	payload := newNodeClientResource(client)
	payload.VerifyKey = ""
	payload.Config.User = ""
	return payload
}

func (a *App) embeddedNodeClientResource(client *file.Client) nodeClientResourcePayload {
	payload := newEmbeddedNodeClientResource(client)
	if client != nil {
		payload.ConnectionCount = a.clientConnectionCount(client.Id)
	}
	return payload
}

func (a *App) nodeClientResourceWithAccess(access nodeActorAccess, client *file.Client) nodeClientResourcePayload {
	payload := newNodeClientResource(client)
	if !access.allows(a, webservice.PermissionClientsUpdate) {
		payload.VerifyKey = ""
	}
	if client != nil {
		payload.ConnectionCount = a.clientConnectionCount(client.Id)
	}
	return payload
}

func (a *App) nodeClientResource(actor *Actor, client *file.Client) nodeClientResourcePayload {
	return a.nodeClientResourceWithAccess(a.nodeActorAccess(actor), client)
}

func (a *App) clientConnectionCount(clientID int) int {
	if a == nil || clientID == 0 {
		return 0
	}
	runtime := a.backend().Runtime
	if isNilAppServiceValue(runtime) {
		return 0
	}
	return runtime.ClientConnectionCount(clientID)
}

func (a *App) clientConnections(clientID int) []webservice.ClientConnection {
	if a == nil || clientID == 0 {
		return nil
	}
	runtime := a.backend().Runtime
	if isNilAppServiceValue(runtime) {
		return nil
	}
	return runtime.ListClientConnections(clientID)
}

func newNodeClientConnections(connections []webservice.ClientConnection) []nodeClientConnectionPayload {
	if len(connections) == 0 {
		return []nodeClientConnectionPayload{}
	}
	items := make([]nodeClientConnectionPayload, 0, len(connections))
	for _, connection := range connections {
		item := nodeClientConnectionPayload{
			UUID:                   connection.UUID,
			Version:                connection.Version,
			BaseVer:                connection.BaseVer,
			RemoteAddr:             connection.RemoteAddr,
			LocalAddr:              connection.LocalAddr,
			HasSignal:              connection.HasSignal,
			HasTunnel:              connection.HasTunnel,
			IsOnline:               connection.Online,
			ConnectedAt:            connection.ConnectedAt,
			NowConn:                int(connection.NowConn),
			BridgeInBytes:          connection.BridgeInBytes,
			BridgeOutBytes:         connection.BridgeOutBytes,
			BridgeTotalBytes:       connection.BridgeTotalBytes,
			ServiceInBytes:         connection.ServiceInBytes,
			ServiceOutBytes:        connection.ServiceOutBytes,
			ServiceTotalBytes:      connection.ServiceTotalBytes,
			TotalInBytes:           connection.TotalInBytes,
			TotalOutBytes:          connection.TotalOutBytes,
			TotalBytes:             connection.TotalBytes,
			BridgeNowRateInBps:     connection.BridgeNowRateInBps,
			BridgeNowRateOutBps:    connection.BridgeNowRateOutBps,
			BridgeNowRateTotalBps:  connection.BridgeNowRateTotalBps,
			ServiceNowRateInBps:    connection.ServiceNowRateInBps,
			ServiceNowRateOutBps:   connection.ServiceNowRateOutBps,
			ServiceNowRateTotalBps: connection.ServiceNowRateTotalBps,
			TotalNowRateInBps:      connection.TotalNowRateInBps,
			TotalNowRateOutBps:     connection.TotalNowRateOutBps,
			TotalNowRateTotalBps:   connection.TotalNowRateTotalBps,
		}
		if connection.ConnectedAt > 0 {
			item.ConnectedAtText = time.Unix(0, connection.ConnectedAt).Format("2006-01-02 15:04:05")
		}
		items = append(items, item)
	}
	return items
}

func (a *App) finishNodeClientMutation(c Context, access nodeActorAccess, action, eventName string, id int, client *file.Client, overrides map[string]interface{}) {
	a.emitNodeResourceMutationEvent(c, eventName, "client", action, nodeResourceMutationFields(id, clientEventFields(client), overrides))
	a.respondCompletedNodeMutation(c, "client", action, id, a.nodeClientResourceWithAccess(access, client))
}

func (a *App) NodeCreateClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	var body nodeClientWriteRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	requestedOwnerUserID := 0
	ownerSpecified := body.OwnerUserID != nil
	if body.OwnerUserID != nil {
		requestedOwnerUserID = *body.OwnerUserID
	}
	var managerUserIDs []int
	if body.ManagerUserIDs != nil {
		managerUserIDs = append([]int(nil), (*body.ManagerUserIDs)...)
	}
	result, err := a.Services.Clients.Add(webservice.BuildAddClientInput(webservice.ClientMutationContext{
		Principal:             access.principal,
		Authz:                 a.authorization(),
		ReservedAdminUsername: a.currentConfig().Web.Username,
	}, webservice.AddClientRequest{
		ClientWriteRequest: webservice.ClientWriteRequest{
			UserID:          requestedOwnerUserID,
			OwnerSpecified:  ownerSpecified,
			ManagerUserIDs:  managerUserIDs,
			VKey:            body.VerifyKey,
			Remark:          body.Remark,
			User:            body.Username,
			Password:        nodeMutationStringValue(body.Password),
			Compress:        body.Compress,
			Crypt:           body.Crypt,
			ConfigConnAllow: body.ConfigConnAllow,
			RateLimit:       webservice.ManagementRateLimitFromBps(body.RateLimitTotalBps),
			MaxConn:         body.MaxConnections,
			MaxTunnelNum:    body.MaxTunnelNum,
			FlowLimit:       body.FlowLimitTotalBytes,
			TimeLimit:       body.ExpireAt,
			EntryACLMode:    body.EntryACLMode,
			EntryACLRules:   body.EntryACLRules,
		},
	}))
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeClientMutation(c, access, "create", "client.created", result.ID, sanitizeNodeClient(access.scope, result.Client), nil)
}

func (a *App) NodeUpdateClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	var body nodeClientWriteRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionClientsUpdate,
		Ownership:  "client",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	requestedOwnerUserID := 0
	ownerSpecified := body.OwnerUserID != nil
	if body.OwnerUserID != nil {
		requestedOwnerUserID = *body.OwnerUserID
	}
	var managerUserIDs []int
	managerSpecified := body.ManagerUserIDs != nil
	if body.ManagerUserIDs != nil {
		managerUserIDs = append([]int(nil), (*body.ManagerUserIDs)...)
	}
	result, err := a.Services.Clients.Edit(webservice.BuildEditClientInput(webservice.ClientMutationContext{
		Principal:               access.principal,
		Authz:                   a.authorization(),
		ReservedAdminUsername:   a.currentConfig().Web.Username,
		AllowUserChangeUsername: a.currentConfig().Feature.AllowUserChangeUsername,
	}, webservice.EditClientRequest{
		ID:               id,
		ExpectedRevision: body.ExpectedRevision,
		ClientWriteRequest: webservice.ClientWriteRequest{
			UserID:                  requestedOwnerUserID,
			OwnerSpecified:          ownerSpecified,
			ManagerUserIDsSpecified: managerSpecified,
			ManagerUserIDs:          managerUserIDs,
			VKey:                    body.VerifyKey,
			Remark:                  body.Remark,
			User:                    body.Username,
			Password:                nodeMutationStringValue(body.Password),
			PasswordProvided:        body.Password != nil,
			Compress:                body.Compress,
			Crypt:                   body.Crypt,
			ConfigConnAllow:         body.ConfigConnAllow,
			RateLimit:               webservice.ManagementRateLimitFromBps(body.RateLimitTotalBps),
			MaxConn:                 body.MaxConnections,
			MaxTunnelNum:            body.MaxTunnelNum,
			FlowLimit:               body.FlowLimitTotalBytes,
			TimeLimit:               body.ExpireAt,
			EntryACLMode:            body.EntryACLMode,
			EntryACLRules:           body.EntryACLRules,
		},
		ResetFlow: body.ResetFlow,
	}))
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeClientMutation(c, access, "update", "client.updated", result.ID, sanitizeNodeClient(access.scope, result.Client), nil)
}

func (a *App) NodeSetClientStatus(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	var body nodeStatusActionRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionClientsStatus,
		Ownership:  "client",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	if body.Status == nil {
		respondMissingRequestField(c, "status")
		return
	}
	status := *body.Status
	result, err := a.Services.Clients.ChangeStatus(id, status)
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	client := sanitizeNodeClient(access.scope, result.Client)
	statusFields := map[string]interface{}{"status": status}
	if client != nil {
		statusFields["status"] = client.Status
	}
	a.finishNodeClientMutation(c, access, "status", "client.status_changed", result.ID, client, statusFields)
}

func (a *App) NodeClearClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	var body nodeModeActionRequest
	if !decodeCanonicalJSONObject(c, &body) {
		return
	}
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionClientsStatus,
		Ownership:  "client",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	mode := strings.TrimSpace(body.Mode)
	if mode == "" {
		respondMissingRequestField(c, "mode")
		return
	}
	result, err := a.Services.Clients.Clear(id, mode, true)
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeClientMutation(c, access, "clear", "client.cleared", result.ID, sanitizeNodeClient(access.scope, result.Client), map[string]interface{}{"mode": mode})
}

func (a *App) NodeDeleteClient(c Context) {
	access := a.nodeActorAccessFromContext(c)
	id := requestIntValue(c, "id")
	if _, err := access.authorize(a, c, webservice.ProtectedActionAccessInput{
		Permission: webservice.PermissionClientsDelete,
		Ownership:  "client",
		ResourceID: id,
	}); err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	result, err := a.Services.Clients.Delete(id)
	if err != nil {
		respondNodeMutationData(c, nodeResourceMutationPayload{}, err)
		return
	}
	a.finishNodeClientMutation(c, access, "delete", "client.deleted", result.ID, sanitizeNodeClient(access.scope, result.Client), nil)
}
