package service

import "github.com/djylb/nps/lib/file"

func CloneClientSnapshot(client *file.Client) *file.Client {
	return cloneClientSnapshotForMutation(client)
}

func snapshotsDetached(source interface{}) bool {
	if source == nil {
		return false
	}
	repo, ok := source.(detachedSnapshotRepository)
	return ok && repo.SupportsDetachedSnapshots()
}

func ensureDetachedClientSnapshot(source interface{}, client *file.Client) *file.Client {
	if client == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return client
	}
	return cloneClientSnapshotForMutation(client)
}

func ensureDetachedUserSnapshot(source interface{}, user *file.User) *file.User {
	if user == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return user
	}
	return cloneUserForMutation(user)
}

func ensureDetachedTunnelSnapshot(source interface{}, tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return tunnel
	}
	return cloneTunnelSnapshot(tunnel)
}

func ensureDetachedTunnelMutation(source interface{}, tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return tunnel
	}
	return cloneTunnelForMutation(tunnel)
}

func ensureDetachedHostSnapshot(source interface{}, host *file.Host) *file.Host {
	if host == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return host
	}
	return cloneHostSnapshot(host)
}

func ensureDetachedHostMutation(source interface{}, host *file.Host) *file.Host {
	if host == nil {
		return nil
	}
	if snapshotsDetached(source) {
		return host
	}
	return cloneHostForMutation(host)
}

func resolveClientOwnerUser(repo interface {
	GetUser(int) (*file.User, error)
}, client *file.Client) (*file.User, error) {
	if client == nil {
		return nil, nil
	}
	ownerID := client.OwnerID()
	if ownerID <= 0 {
		return nil, nil
	}
	if owner := client.OwnerUser(); owner != nil && owner.Id == ownerID {
		return owner, nil
	}
	if repo == nil {
		return nil, nil
	}
	return repo.GetUser(ownerID)
}

func cloneClientForMutation(client *file.Client) *file.Client {
	return cloneClientSnapshotForMutation(client)
}

func cloneClientConfig(cfg *file.Config) *file.Config {
	if cfg == nil {
		return &file.Config{}
	}
	return &file.Config{
		U:        cfg.U,
		P:        cfg.P,
		Compress: cfg.Compress,
		Crypt:    cfg.Crypt,
	}
}

func cloneClientFlow(flow *file.Flow) *file.Flow {
	if flow == nil {
		return &file.Flow{}
	}
	flow.RLock()
	defer flow.RUnlock()
	return &file.Flow{
		ExportFlow: flow.ExportFlow,
		InletFlow:  flow.InletFlow,
		FlowLimit:  flow.FlowLimit,
		TimeLimit:  flow.TimeLimit,
	}
}

func cloneClientSnapshotForMutation(client *file.Client) *file.Client {
	if client == nil {
		return nil
	}
	owner := cloneAttachedOwnerUser(client.OwnerUser())
	client.RLock()
	cloned := &file.Client{
		Cnf:              cloneClientConfig(client.Cnf),
		Id:               client.Id,
		UserId:           client.UserId,
		OwnerUserID:      client.OwnerUserID,
		ManagerUserIDs:   append([]int(nil), client.ManagerUserIDs...),
		SourceType:       client.SourceType,
		SourcePlatformID: client.SourcePlatformID,
		SourceActorID:    client.SourceActorID,
		DevicePublicKey:  client.DevicePublicKey,
		DeviceKeyID:      client.DeviceKeyID,
		DeviceEnrolledAt: client.DeviceEnrolledAt,
		Revision:         client.Revision,
		UpdatedAt:        client.UpdatedAt,
		VerifyKey:        client.VerifyKey,
		Mode:             client.Mode,
		Addr:             client.Addr,
		LocalAddr:        client.LocalAddr,
		Remark:           client.Remark,
		Status:           client.Status,
		IsConnect:        client.IsConnect,
		ExpireAt:         client.ExpireAt,
		FlowLimit:        client.FlowLimit,
		RateLimit:        client.RateLimit,
		Flow:             cloneClientFlow(client.Flow),
		Rate:             client.Rate.Clone(),
		BridgeTraffic:    cloneTrafficStats(client.BridgeTraffic),
		ServiceTraffic:   cloneTrafficStats(client.ServiceTraffic),
		BridgeMeter:      client.BridgeMeter.Clone(),
		ServiceMeter:     client.ServiceMeter.Clone(),
		TotalMeter:       client.TotalMeter.Clone(),
		ExportFlow:       client.ExportFlow,
		InletFlow:        client.InletFlow,
		NoStore:          client.NoStore,
		NoDisplay:        client.NoDisplay,
		MaxConn:          client.MaxConn,
		NowConn:          client.NowConn,
		ConfigConnAllow:  client.ConfigConnAllow,
		MaxTunnelNum:     client.MaxTunnelNum,
		Version:          client.Version,
		EntryAclMode:     client.EntryAclMode,
		EntryAclRules:    client.EntryAclRules,
		CreateTime:       client.CreateTime,
		LastOnlineTime:   client.LastOnlineTime,
	}
	client.RUnlock()
	cloned.NormalizeOwnership()
	cloned.BindOwnerUser(owner)
	cloned.NormalizeLifecycleFields()
	cloned.EnsureRuntimeTraffic()
	return cloned
}

func cloneAttachedOwnerUser(user *file.User) *file.User {
	if user == nil {
		return nil
	}
	user.RLock()
	cloned := &file.User{
		Id:                 user.Id,
		Username:           user.Username,
		Kind:               user.Kind,
		ExternalPlatformID: user.ExternalPlatformID,
		Hidden:             user.Hidden,
		Status:             user.Status,
		ExpireAt:           user.ExpireAt,
		FlowLimit:          user.FlowLimit,
		TotalFlow:          cloneClientFlow(user.TotalFlow),
		TotalTraffic:       cloneTrafficStats(user.TotalTraffic),
		MaxClients:         user.MaxClients,
		MaxTunnels:         user.MaxTunnels,
		MaxHosts:           user.MaxHosts,
		MaxConnections:     user.MaxConnections,
		RateLimit:          user.RateLimit,
		EntryAclMode:       user.EntryAclMode,
		EntryAclRules:      user.EntryAclRules,
		DestAclMode:        user.DestAclMode,
		DestAclRules:       user.DestAclRules,
		Revision:           user.Revision,
		UpdatedAt:          user.UpdatedAt,
		NowConn:            user.NowConn,
		Rate:               user.Rate.Clone(),
		TotalMeter:         user.TotalMeter.Clone(),
	}
	user.RUnlock()
	cloned.NormalizeIdentity()
	cloned.EnsureTotalFlow()
	cloned.EnsureRuntimeTraffic()
	return cloned
}

func cloneUserForMutation(user *file.User) *file.User {
	if user == nil {
		return nil
	}
	user.RLock()
	cloned := &file.User{
		Id:                 user.Id,
		Username:           user.Username,
		Password:           user.Password,
		TOTPSecret:         user.TOTPSecret,
		Kind:               user.Kind,
		ExternalPlatformID: user.ExternalPlatformID,
		Hidden:             user.Hidden,
		Status:             user.Status,
		ExpireAt:           user.ExpireAt,
		FlowLimit:          user.FlowLimit,
		TotalFlow:          cloneClientFlow(user.TotalFlow),
		TotalTraffic:       cloneTrafficStats(user.TotalTraffic),
		MaxClients:         user.MaxClients,
		MaxTunnels:         user.MaxTunnels,
		MaxHosts:           user.MaxHosts,
		MaxConnections:     user.MaxConnections,
		RateLimit:          user.RateLimit,
		EntryAclMode:       user.EntryAclMode,
		EntryAclRules:      user.EntryAclRules,
		DestAclMode:        user.DestAclMode,
		DestAclRules:       user.DestAclRules,
		Revision:           user.Revision,
		UpdatedAt:          user.UpdatedAt,
		NowConn:            user.NowConn,
		Rate:               user.Rate.Clone(),
		TotalMeter:         user.TotalMeter.Clone(),
	}
	user.RUnlock()
	cloned.NormalizeIdentity()
	cloned.EnsureTotalFlow()
	cloned.EnsureRuntimeTraffic()
	return cloned
}

func cloneTunnelForMutation(tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	tunnel.RLock()
	cloned := &file.Tunnel{
		Id:             tunnel.Id,
		Revision:       tunnel.Revision,
		UpdatedAt:      tunnel.UpdatedAt,
		Port:           tunnel.Port,
		ServerIp:       tunnel.ServerIp,
		Mode:           tunnel.Mode,
		Status:         tunnel.Status,
		RunStatus:      tunnel.RunStatus,
		Client:         tunnel.Client,
		Ports:          tunnel.Ports,
		ExpireAt:       tunnel.ExpireAt,
		FlowLimit:      tunnel.FlowLimit,
		RateLimit:      tunnel.RateLimit,
		Flow:           cloneClientFlow(tunnel.Flow),
		Rate:           tunnel.Rate.Clone(),
		ServiceTraffic: cloneTrafficStats(tunnel.ServiceTraffic),
		ServiceMeter:   tunnel.ServiceMeter.Clone(),
		MaxConn:        tunnel.MaxConn,
		NowConn:        tunnel.NowConn,
		Password:       tunnel.Password,
		Remark:         tunnel.Remark,
		TargetAddr:     tunnel.TargetAddr,
		TargetType:     tunnel.TargetType,
		EntryAclMode:   tunnel.EntryAclMode,
		EntryAclRules:  tunnel.EntryAclRules,
		DestAclMode:    tunnel.DestAclMode,
		DestAclRules:   tunnel.DestAclRules,
		DestAclSet:     tunnel.DestAclSet,
		NoStore:        tunnel.NoStore,
		IsHttp:         tunnel.IsHttp,
		HttpProxy:      tunnel.HttpProxy,
		Socks5Proxy:    tunnel.Socks5Proxy,
		LocalPath:      tunnel.LocalPath,
		StripPre:       tunnel.StripPre,
		ReadOnly:       tunnel.ReadOnly,
		Target:         cloneTargetForMutation(tunnel.Target),
		UserAuth:       cloneMultiAccountForMutation(tunnel.UserAuth),
		MultiAccount:   cloneMultiAccountForMutation(tunnel.MultiAccount),
	}
	tunnel.RUnlock()
	cloneHealthForMutation(&cloned.Health, &tunnel.Health)
	return cloned
}

func cloneTunnelSnapshot(tunnel *file.Tunnel) *file.Tunnel {
	if tunnel == nil {
		return nil
	}
	tunnel.RLock()
	client := tunnel.Client
	tunnel.RUnlock()
	cloned := cloneTunnelForMutation(tunnel)
	if cloned == nil {
		return nil
	}
	cloned.Client = cloneClientSnapshotForMutation(client)
	return cloned
}

func CloneTunnelSnapshot(tunnel *file.Tunnel) *file.Tunnel {
	return cloneTunnelSnapshot(tunnel)
}

func cloneHostForMutation(host *file.Host) *file.Host {
	if host == nil {
		return nil
	}
	host.RLock()
	cloned := &file.Host{
		Id:               host.Id,
		Revision:         host.Revision,
		UpdatedAt:        host.UpdatedAt,
		Host:             host.Host,
		HeaderChange:     host.HeaderChange,
		RespHeaderChange: host.RespHeaderChange,
		HostChange:       host.HostChange,
		Location:         host.Location,
		PathRewrite:      host.PathRewrite,
		Remark:           host.Remark,
		Scheme:           host.Scheme,
		RedirectURL:      host.RedirectURL,
		HttpsJustProxy:   host.HttpsJustProxy,
		TlsOffload:       host.TlsOffload,
		AutoSSL:          host.AutoSSL,
		CertType:         host.CertType,
		CertHash:         host.CertHash,
		CertFile:         host.CertFile,
		KeyFile:          host.KeyFile,
		NoStore:          host.NoStore,
		IsClose:          host.IsClose,
		AutoHttps:        host.AutoHttps,
		AutoCORS:         host.AutoCORS,
		CompatMode:       host.CompatMode,
		ExpireAt:         host.ExpireAt,
		FlowLimit:        host.FlowLimit,
		RateLimit:        host.RateLimit,
		Flow:             cloneClientFlow(host.Flow),
		Rate:             host.Rate.Clone(),
		ServiceTraffic:   cloneTrafficStats(host.ServiceTraffic),
		ServiceMeter:     host.ServiceMeter.Clone(),
		MaxConn:          host.MaxConn,
		NowConn:          host.NowConn,
		Client:           host.Client,
		EntryAclMode:     host.EntryAclMode,
		EntryAclRules:    host.EntryAclRules,
		TargetIsHttps:    host.TargetIsHttps,
		Target:           cloneTargetForMutation(host.Target),
		UserAuth:         cloneMultiAccountForMutation(host.UserAuth),
		MultiAccount:     cloneMultiAccountForMutation(host.MultiAccount),
	}
	host.RUnlock()
	cloneHealthForMutation(&cloned.Health, &host.Health)
	return cloned
}

func cloneHostSnapshot(host *file.Host) *file.Host {
	if host == nil {
		return nil
	}
	host.RLock()
	client := host.Client
	host.RUnlock()
	cloned := cloneHostForMutation(host)
	if cloned == nil {
		return nil
	}
	cloned.Client = cloneClientSnapshotForMutation(client)
	return cloned
}

func CloneHostSnapshot(host *file.Host) *file.Host {
	return cloneHostSnapshot(host)
}

func cloneTargetForMutation(target *file.Target) *file.Target {
	return file.CloneTargetSnapshot(target)
}

func cloneMultiAccountForMutation(account *file.MultiAccount) *file.MultiAccount {
	return file.CloneMultiAccountSnapshot(account)
}

func cloneTrafficStats(stats *file.TrafficStats) *file.TrafficStats {
	if stats == nil {
		return nil
	}
	in, out, _ := stats.Snapshot()
	return &file.TrafficStats{
		InletBytes:  in,
		ExportBytes: out,
	}
}

func cloneHealthForMutation(dst *file.Health, src *file.Health) {
	if dst == nil {
		return
	}
	*dst = file.Health{}
	if src == nil {
		return
	}
	src.RLock()
	defer src.RUnlock()
	dst.HealthCheckTimeout = src.HealthCheckTimeout
	dst.HealthMaxFail = src.HealthMaxFail
	dst.HealthCheckInterval = src.HealthCheckInterval
	dst.HealthNextTime = src.HealthNextTime
	dst.HttpHealthUrl = src.HttpHealthUrl
	dst.HealthRemoveArr = append([]string(nil), src.HealthRemoveArr...)
	dst.HealthCheckType = src.HealthCheckType
	dst.HealthCheckTarget = src.HealthCheckTarget
	if len(src.HealthMap) > 0 {
		dst.HealthMap = make(map[string]int, len(src.HealthMap))
		for key, value := range src.HealthMap {
			dst.HealthMap[key] = value
		}
	}
}
