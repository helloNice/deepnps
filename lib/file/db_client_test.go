package file

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/djylb/nps/lib/common"
	"github.com/djylb/nps/lib/crypt"
)

func TestUpdateClientPersistsClientChangesToDisk(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        1,
		VerifyKey: "verify-old",
		Remark:    "before",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	updated := &Client{
		Id:        client.Id,
		VerifyKey: "verify-new",
		Remark:    "after",
		Status:    client.Status,
		Cnf:       client.Cnf,
		Flow:      client.Flow,
	}
	if err := db.UpdateClient(updated); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}

	if _, err := db.GetClientByVerifyKey("verify-old"); err == nil {
		t.Fatal("GetClientByVerifyKey(old) error = nil, want old verify key removed from runtime lookup")
	}
	current, err := db.GetClientByVerifyKey("verify-new")
	if err != nil {
		t.Fatalf("GetClientByVerifyKey(new) error = %v", err)
	}
	if current.Remark != "after" {
		t.Fatalf("runtime client remark = %q, want %q", current.Remark, "after")
	}

	payload, err := common.ReadAllFromFile(db.JsonDb.ClientFilePath)
	if err != nil {
		t.Fatalf("ReadAllFromFile(clients.json) error = %v", err)
	}
	var stored []Client
	if err := json.Unmarshal(payload, &stored); err != nil {
		t.Fatalf("json.Unmarshal(clients.json) error = %v", err)
	}
	if len(stored) != 1 {
		t.Fatalf("len(stored clients) = %d, want 1", len(stored))
	}
	if stored[0].VerifyKey != "verify-new" || stored[0].Remark != "after" {
		t.Fatalf("stored client fields = verify_key:%q remark:%q, want verify key %q and remark %q", stored[0].VerifyKey, stored[0].Remark, "verify-new", "after")
	}
}

func TestUpdateClientRejectsDuplicateVerifyKey(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	first := &Client{
		Id:        1,
		VerifyKey: "verify-a",
		Remark:    "first",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	second := &Client{
		Id:        2,
		VerifyKey: "verify-b",
		Remark:    "second",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(first); err != nil {
		t.Fatalf("NewClient(first) error = %v", err)
	}
	if err := db.NewClient(second); err != nil {
		t.Fatalf("NewClient(second) error = %v", err)
	}

	updated := &Client{
		Id:        second.Id,
		VerifyKey: "verify-a",
		Remark:    second.Remark,
		Status:    second.Status,
		Cnf:       second.Cnf,
		Flow:      second.Flow,
	}
	if err := db.UpdateClient(updated); err == nil {
		t.Fatal("UpdateClient() error = nil, want duplicate verify key rejection")
	}

	currentSecond, err := db.GetClient(second.Id)
	if err != nil {
		t.Fatalf("GetClient(second) error = %v", err)
	}
	if currentSecond.VerifyKey != "verify-b" {
		t.Fatalf("current second verify key = %q, want original %q", currentSecond.VerifyKey, "verify-b")
	}
	if _, err := db.GetClientByVerifyKey("verify-a"); err != nil {
		t.Fatalf("GetClientByVerifyKey(verify-a) error = %v", err)
	}
	if client, err := db.GetClientByVerifyKey("verify-b"); err != nil {
		t.Fatalf("GetClientByVerifyKey(verify-b) error = %v", err)
	} else if client.Id != second.Id {
		t.Fatalf("verify-b now points to client %d, want %d", client.Id, second.Id)
	}
}

func TestGetClientIDsByUserIdTracksOwnerUpdateAndDelete(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	for _, user := range []*User{
		{Id: 7, Username: "owner-a", Status: 1},
		{Id: 8, Username: "owner-b", Status: 1},
	} {
		if err := db.NewUser(user); err != nil {
			t.Fatalf("NewUser(%s) error = %v", user.Username, err)
		}
	}

	client := &Client{
		Id:          11,
		VerifyKey:   "vk-owner",
		OwnerUserID: 7,
		Status:      true,
		Cnf:         &Config{},
		Flow:        &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	if got := db.GetClientIDsByUserId(7); len(got) != 1 || got[0] != client.Id {
		t.Fatalf("GetClientIDsByUserId(7) = %v, want [%d]", got, client.Id)
	}

	updated := *client
	updated.SetOwnerUserID(8)
	if err := db.UpdateClient(&updated); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}

	if got := db.GetClientIDsByUserId(7); len(got) != 0 {
		t.Fatalf("GetClientIDsByUserId(7) after owner move = %v, want empty", got)
	}
	if got := db.GetClientIDsByUserId(8); len(got) != 1 || got[0] != client.Id {
		t.Fatalf("GetClientIDsByUserId(8) after owner move = %v, want [%d]", got, client.Id)
	}

	if err := db.DelClient(client.Id); err != nil {
		t.Fatalf("DelClient() error = %v", err)
	}
	if got := db.GetClientIDsByUserId(8); len(got) != 0 {
		t.Fatalf("GetClientIDsByUserId(8) after delete = %v, want empty", got)
	}
}

func TestGetVisibleManagedClientIDsByUserIdTracksOwnerAndManagerIndexes(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	for _, user := range []*User{
		{Id: 7, Username: "owner-a", Status: 1},
		{Id: 8, Username: "owner-b", Status: 1},
		{Id: 9, Username: "manager-a", Status: 1},
	} {
		if err := db.NewUser(user); err != nil {
			t.Fatalf("NewUser(%s) error = %v", user.Username, err)
		}
	}

	owned := &Client{
		Id:          11,
		VerifyKey:   "owner-visible",
		OwnerUserID: 7,
		Status:      true,
		Cnf:         &Config{},
		Flow:        &Flow{},
	}
	managed := &Client{
		Id:             12,
		VerifyKey:      "manager-visible",
		OwnerUserID:    8,
		ManagerUserIDs: []int{7},
		Status:         true,
		Cnf:            &Config{},
		Flow:           &Flow{},
	}
	hidden := &Client{
		Id:          13,
		VerifyKey:   "owner-hidden",
		OwnerUserID: 7,
		Status:      true,
		NoDisplay:   true,
		Cnf:         &Config{},
		Flow:        &Flow{},
	}
	disabled := &Client{
		Id:             14,
		VerifyKey:      "manager-disabled",
		OwnerUserID:    8,
		ManagerUserIDs: []int{7},
		Status:         false,
		Cnf:            &Config{},
		Flow:           &Flow{},
	}
	for _, client := range []*Client{owned, managed, hidden, disabled} {
		if err := db.NewClient(client); err != nil {
			t.Fatalf("NewClient(%s) error = %v", client.VerifyKey, err)
		}
	}

	db.JsonDb.ownerClientIndex.add(7, 404)
	db.JsonDb.managerClientIndex.add(7, 405)

	if got := db.GetAllManagedClientIDsByUserId(7); !reflect.DeepEqual(got, []int{11, 12, 13, 14}) {
		t.Fatalf("GetAllManagedClientIDsByUserId(7) = %v, want [11 12 13 14]", got)
	}
	if got := db.GetVisibleManagedClientIDsByUserId(7); !reflect.DeepEqual(got, []int{11, 12}) {
		t.Fatalf("GetVisibleManagedClientIDsByUserId(7) = %v, want [11 12]", got)
	}
	if indexed := db.JsonDb.ownerClientIndex.snapshot(7); !reflect.DeepEqual(indexed, []int{11, 13}) {
		t.Fatalf("ownerClientIndex snapshot = %v, want [11 13] after stale prune", indexed)
	}
	if indexed := db.JsonDb.managerClientIndex.snapshot(7); !reflect.DeepEqual(indexed, []int{12, 14}) {
		t.Fatalf("managerClientIndex snapshot = %v, want [12 14] after stale prune", indexed)
	}

	updated := *managed
	updated.ManagerUserIDs = []int{9}
	if err := db.UpdateClient(&updated); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}

	if got := db.GetVisibleManagedClientIDsByUserId(7); !reflect.DeepEqual(got, []int{11}) {
		t.Fatalf("GetVisibleManagedClientIDsByUserId(7) after manager move = %v, want [11]", got)
	}
	if got := db.GetAllManagedClientIDsByUserId(7); !reflect.DeepEqual(got, []int{11, 13, 14}) {
		t.Fatalf("GetAllManagedClientIDsByUserId(7) after manager move = %v, want [11 13 14]", got)
	}
	if got := db.GetVisibleManagedClientIDsByUserId(9); !reflect.DeepEqual(got, []int{12}) {
		t.Fatalf("GetVisibleManagedClientIDsByUserId(9) after manager move = %v, want [12]", got)
	}
	if got := db.GetAllManagedClientIDsByUserId(9); !reflect.DeepEqual(got, []int{12}) {
		t.Fatalf("GetAllManagedClientIDsByUserId(9) after manager move = %v, want [12]", got)
	}
	if indexed := db.JsonDb.managerClientIndex.snapshot(7); !reflect.DeepEqual(indexed, []int{14}) {
		t.Fatalf("managerClientIndex[7] = %v, want [14] after manager move", indexed)
	}
	if indexed := db.JsonDb.managerClientIndex.snapshot(9); !reflect.DeepEqual(indexed, []int{12}) {
		t.Fatalf("managerClientIndex[9] = %v, want [12] after manager move", indexed)
	}
}

func TestUpdateClientRejectsMissingClient(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	if err := db.UpdateClient(&Client{
		Id:        99,
		VerifyKey: "verify-missing",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("UpdateClient() error = %v, want %v", err, ErrClientNotFound)
	}
	if _, err := db.GetClient(99); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("GetClient(99) error = %v, want %v", err, ErrClientNotFound)
	}
}

func TestNewClientRejectsNilAndTrimsVerifyKey(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	if err := db.NewClient(nil); err == nil {
		t.Fatal("NewClient(nil) error = nil, want rejection")
	}

	client := &Client{
		Id:        1,
		VerifyKey: "  verify-trimmed  ",
		Remark:    "trimmed",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.VerifyKey != "verify-trimmed" {
		t.Fatalf("client.VerifyKey = %q, want %q", client.VerifyKey, "verify-trimmed")
	}
	current, err := db.GetClientByVerifyKey("verify-trimmed")
	if err != nil {
		t.Fatalf("GetClientByVerifyKey(trimmed) error = %v", err)
	}
	if current.Id != client.Id {
		t.Fatalf("GetClientByVerifyKey(trimmed) id = %d, want %d", current.Id, client.Id)
	}
}

func TestUpdateClientTrimsVerifyKeyBeforePersisting(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        1,
		VerifyKey: "verify-old",
		Remark:    "before",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	updated := &Client{
		Id:        client.Id,
		VerifyKey: "  verify-trimmed  ",
		Remark:    client.Remark,
		Status:    client.Status,
		Cnf:       client.Cnf,
		Flow:      client.Flow,
	}
	if err := db.UpdateClient(updated); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}

	current, err := db.GetClient(client.Id)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}
	if current.VerifyKey != "verify-trimmed" {
		t.Fatalf("current.VerifyKey = %q, want %q", current.VerifyKey, "verify-trimmed")
	}
	if _, err := db.GetClientByVerifyKey("verify-old"); err == nil {
		t.Fatal("GetClientByVerifyKey(old) error = nil, want old key removed")
	}
	if lookedUp, err := db.GetClientByVerifyKey("verify-trimmed"); err != nil {
		t.Fatalf("GetClientByVerifyKey(trimmed) error = %v", err)
	} else if lookedUp.Id != client.Id {
		t.Fatalf("GetClientByVerifyKey(trimmed) id = %d, want %d", lookedUp.Id, client.Id)
	}
}

func TestDelClientRejectsOwnedTunnelOrHostReferences(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        7,
		VerifyKey: "owned-vkey",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	task := &Tunnel{
		Id:     9,
		Mode:   "tcp",
		Status: true,
		Client: client,
		Target: &Target{TargetStr: "127.0.0.1:80"},
		Flow:   &Flow{},
	}
	if err := db.NewTask(task); err != nil {
		t.Fatalf("NewTask() error = %v", err)
	}
	host := &Host{
		Id:       11,
		Host:     "demo.example.com",
		Location: "/",
		Scheme:   "http",
		Client:   client,
		Target:   &Target{TargetStr: "127.0.0.1:81"},
		Flow:     &Flow{},
	}
	if err := db.NewHost(host); err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}

	if err := db.DelClient(client.Id); err == nil {
		t.Fatal("DelClient() error = nil, want rejection while owned task/host remain")
	}
	if _, err := db.GetClient(client.Id); err != nil {
		t.Fatalf("GetClient(%d) error = %v, want client to remain after rejection", client.Id, err)
	}

	if err := db.DelTask(task.Id); err != nil {
		t.Fatalf("DelTask(%d) error = %v", task.Id, err)
	}
	if err := db.DelHost(host.Id); err != nil {
		t.Fatalf("DelHost(%d) error = %v", host.Id, err)
	}
	if err := db.DelClient(client.Id); err != nil {
		t.Fatalf("DelClient() after resource cleanup error = %v", err)
	}
	if _, err := db.GetClient(client.Id); err == nil {
		t.Fatalf("GetClient(%d) error = nil, want deleted client", client.Id)
	}
}

func TestDelClientRejectsMissingClient(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	if err := db.DelClient(404); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("DelClient(404) error = %v, want %v", err, ErrClientNotFound)
	}
}

func TestDelClientDropsInvalidLiveEntryAndReturnsNotFound(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	db.JsonDb.Clients.Store(7, "invalid")

	if err := db.DelClient(7); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("DelClient(invalid entry) error = %v, want %v", err, ErrClientNotFound)
	}
	if _, ok := db.JsonDb.Clients.Load(7); ok {
		t.Fatal("invalid live client entry should be dropped")
	}
}

func TestClientLookupAndDeleteDropInvalidEntries(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        7,
		VerifyKey: "verify-valid",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	db.JsonDb.Clients.Store("bad-client-key", "invalid")
	db.JsonDb.Clients.Store(99, "invalid")
	db.JsonDb.Tasks.Store("bad-task", "invalid")
	db.JsonDb.Hosts.Store("bad-host", "invalid")

	lookedUp, err := db.GetClientByVerifyKey("verify-valid")
	if err != nil {
		t.Fatalf("GetClientByVerifyKey(valid) error = %v", err)
	}
	if lookedUp.Id != client.Id {
		t.Fatalf("GetClientByVerifyKey(valid) id = %d, want %d", lookedUp.Id, client.Id)
	}
	if _, err := db.GetClient(99); !errors.Is(err, ErrClientNotFound) {
		t.Fatalf("GetClient(99) error = %v, want %v", err, ErrClientNotFound)
	}
	if err := db.DelClient(client.Id); err != nil {
		t.Fatalf("DelClient(valid) error = %v", err)
	}

	if _, ok := db.JsonDb.Clients.Load("bad-client-key"); ok {
		t.Fatal("invalid client key entry should be dropped")
	}
	if _, ok := db.JsonDb.Clients.Load(99); ok {
		t.Fatal("invalid client value entry should be dropped")
	}
	if _, ok := db.JsonDb.Tasks.Load("bad-task"); ok {
		t.Fatal("invalid task entry should be dropped during resource scan")
	}
	if _, ok := db.JsonDb.Hosts.Load("bad-host"); ok {
		t.Fatal("invalid host entry should be dropped during resource scan")
	}
}

func TestVerifyVkeyDropsInvalidEntriesAndStillDetectsDuplicates(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	first := &Client{
		Id:        7,
		VerifyKey: "verify-a",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	second := &Client{
		Id:        8,
		VerifyKey: "verify-b",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(first); err != nil {
		t.Fatalf("NewClient(first) error = %v", err)
	}
	if err := db.NewClient(second); err != nil {
		t.Fatalf("NewClient(second) error = %v", err)
	}

	db.JsonDb.Clients.Store("bad-client-key", "invalid")
	db.JsonDb.Clients.Store(99, "invalid")

	if ok := db.VerifyVkey("verify-a", second.Id); ok {
		t.Fatal("VerifyVkey(verify-a, second) = true, want duplicate rejection")
	}
	if ok := db.VerifyVkey("verify-c", second.Id); !ok {
		t.Fatal("VerifyVkey(verify-c, second) = false, want available verify key")
	}
	if _, ok := db.JsonDb.Clients.Load("bad-client-key"); ok {
		t.Fatal("VerifyVkey() should drop invalid client key entry")
	}
	if _, ok := db.JsonDb.Clients.Load(99); ok {
		t.Fatal("VerifyVkey() should drop invalid client value entry")
	}
}

func TestUpdateClientDropsInvalidOwnerAndReferenceEntries(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        7,
		VerifyKey: "verify-old",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	task := &Tunnel{
		Id:     9,
		Mode:   "tcp",
		Status: true,
		Client: client,
		Target: &Target{TargetStr: "127.0.0.1:80"},
		Flow:   &Flow{},
	}
	if err := db.NewTask(task); err != nil {
		t.Fatalf("NewTask() error = %v", err)
	}
	host := &Host{
		Id:       11,
		Host:     "relink.example.com",
		Location: "/",
		Scheme:   "http",
		Client:   client,
		Target:   &Target{TargetStr: "127.0.0.1:81"},
		Flow:     &Flow{},
	}
	if err := db.NewHost(host); err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}

	db.JsonDb.Users.Store(77, "invalid")
	db.JsonDb.Tasks.Store("bad-task", "invalid")
	db.JsonDb.Hosts.Store("bad-host", "invalid")

	updated, err := db.GetClient(client.Id)
	if err != nil {
		t.Fatalf("GetClient() error = %v", err)
	}
	updated.VerifyKey = "verify-new"
	updated.SetOwnerUserID(77)
	if err := db.UpdateClient(updated); err != nil {
		t.Fatalf("UpdateClient() error = %v", err)
	}

	stored, err := db.GetClient(client.Id)
	if err != nil {
		t.Fatalf("GetClient(updated) error = %v", err)
	}
	if stored.VerifyKey != "verify-new" {
		t.Fatalf("stored.VerifyKey = %q, want verify-new", stored.VerifyKey)
	}
	if stored.OwnerUser() != nil {
		t.Fatalf("stored.OwnerUser() = %+v, want nil for invalid owner entry", stored.OwnerUser())
	}
	currentTask, err := db.GetTask(task.Id)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if currentTask.Client != stored {
		t.Fatalf("task.Client = %p, want updated client %p", currentTask.Client, stored)
	}
	currentHost, err := db.GetHostById(host.Id)
	if err != nil {
		t.Fatalf("GetHostById() error = %v", err)
	}
	if currentHost.Client != stored {
		t.Fatalf("host.Client = %p, want updated client %p", currentHost.Client, stored)
	}
	if _, ok := db.JsonDb.Users.Load(77); ok {
		t.Fatal("UpdateClient() should drop invalid owner user entry")
	}
}

func TestClientResourceIndexesTrackMovesAndPruneStaleEntries(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	clientA := &Client{Id: 7, VerifyKey: "client-a", Status: true, Cnf: &Config{}, Flow: &Flow{}}
	clientB := &Client{Id: 8, VerifyKey: "client-b", Status: true, Cnf: &Config{}, Flow: &Flow{}}
	if err := db.NewClient(clientA); err != nil {
		t.Fatalf("NewClient(clientA) error = %v", err)
	}
	if err := db.NewClient(clientB); err != nil {
		t.Fatalf("NewClient(clientB) error = %v", err)
	}

	task := &Tunnel{
		Id:     21,
		Mode:   "tcp",
		Status: true,
		Client: clientA,
		Target: &Target{TargetStr: "127.0.0.1:80"},
		Flow:   &Flow{},
	}
	host := &Host{
		Id:       31,
		Host:     "move.example.com",
		Location: "/",
		Scheme:   "http",
		Client:   clientA,
		Target:   &Target{TargetStr: "127.0.0.1:81"},
		Flow:     &Flow{},
	}
	if err := db.NewTask(task); err != nil {
		t.Fatalf("NewTask() error = %v", err)
	}
	if err := db.NewHost(host); err != nil {
		t.Fatalf("NewHost() error = %v", err)
	}

	taskUpdate := *task
	taskUpdate.Client = &Client{Id: clientB.Id}
	if err := db.UpdateTask(&taskUpdate); err != nil {
		t.Fatalf("UpdateTask() error = %v", err)
	}
	hostUpdate := *host
	hostUpdate.Client = &Client{Id: clientB.Id}
	if err := db.UpdateHost(&hostUpdate); err != nil {
		t.Fatalf("UpdateHost() error = %v", err)
	}

	if got := db.CountResourcesByClientID(clientA.Id); got != 0 {
		t.Fatalf("CountResourcesByClientID(clientA) = %d, want 0", got)
	}
	if got := db.CountResourcesByClientID(clientB.Id); got != 2 {
		t.Fatalf("CountResourcesByClientID(clientB) = %d, want 2", got)
	}

	db.JsonDb.taskClientIndex.add(clientB.Id, 404)
	db.JsonDb.hostClientIndex.add(clientB.Id, 405)

	tunnelCount := 0
	db.RangeTunnelsByClientID(clientB.Id, func(*Tunnel) bool {
		tunnelCount++
		return true
	})
	hostCount := 0
	db.RangeHostsByClientID(clientB.Id, func(*Host) bool {
		hostCount++
		return true
	})
	if tunnelCount != 1 || hostCount != 1 {
		t.Fatalf("Range*ByClientID(clientB) = tunnels:%d hosts:%d, want 1/1", tunnelCount, hostCount)
	}

	if indexed := db.JsonDb.taskClientIndex.snapshot(clientB.Id); len(indexed) != 1 || indexed[0] != task.Id {
		t.Fatalf("taskClientIndex snapshot = %v, want [%d]", indexed, task.Id)
	}
	if indexed := db.JsonDb.hostClientIndex.snapshot(clientB.Id); len(indexed) != 1 || indexed[0] != host.Id {
		t.Fatalf("hostClientIndex snapshot = %v, want [%d]", indexed, host.Id)
	}
}

func TestLoadClientFromJsonFileTrimsVerifyKeyForLookupAndIndex(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	payload := []byte(`[
  {"Id":7,"VerifyKey":"  verify-trimmed  ","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}}
]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()

	stored, err := db.GetClient(7)
	if err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}
	if stored.VerifyKey != "verify-trimmed" {
		t.Fatalf("stored.VerifyKey = %q, want %q", stored.VerifyKey, "verify-trimmed")
	}
	lookedUp, err := db.GetClientByVerifyKey("verify-trimmed")
	if err != nil {
		t.Fatalf("GetClientByVerifyKey(trimmed) error = %v", err)
	}
	if lookedUp.Id != 7 {
		t.Fatalf("GetClientByVerifyKey(trimmed) id = %d, want 7", lookedUp.Id)
	}
	id, err := db.GetClientIdByBlake2bVkey(crypt.Blake2b("verify-trimmed"))
	if err != nil {
		t.Fatalf("GetClientIdByBlake2bVkey(trimmed) error = %v", err)
	}
	if id != 7 {
		t.Fatalf("GetClientIdByBlake2bVkey(trimmed) = %d, want 7", id)
	}
}

func TestClientDeviceIdentityFieldsSurviveJSONAndConfigClone(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	payload := []byte(`[{
  "Id":7,
  "VerifyKey":"device-vkey",
  "DevicePublicKey":"PUBKEY",
  "DeviceKeyID":"key-id",
  "DeviceEnrolledAt":1700000000,
  "Status":true,
  "Cnf":{},
  "Flow":{"ExportFlow":0,"InletFlow":0}
}]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()

	stored, err := db.GetClient(7)
	if err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}
	if stored.DevicePublicKey != "PUBKEY" || stored.DeviceKeyID != "key-id" || stored.DeviceEnrolledAt != 1700000000 {
		t.Fatalf("stored device fields = %q/%q/%d", stored.DevicePublicKey, stored.DeviceKeyID, stored.DeviceEnrolledAt)
	}

	snapshot := buildConfigSnapshot(db)
	if len(snapshot.Clients) != 1 {
		t.Fatalf("snapshot clients = %d, want 1", len(snapshot.Clients))
	}
	cloned := snapshot.Clients[0]
	if cloned.DevicePublicKey != "PUBKEY" || cloned.DeviceKeyID != "key-id" || cloned.DeviceEnrolledAt != 1700000000 {
		t.Fatalf("config clone device fields = %q/%q/%d", cloned.DevicePublicKey, cloned.DeviceKeyID, cloned.DeviceEnrolledAt)
	}
}

func TestLoadClientFromJsonFileClearsRemovedClientsOnReload(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	payload := []byte(`[
  {"Id":7,"VerifyKey":"verify-reload","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}}
]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()
	if _, err := db.GetClient(7); err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}

	if err := os.WriteFile(db.JsonDb.ClientFilePath, []byte("[]"), 0o600); err != nil {
		t.Fatalf("WriteFile(empty clients.json) error = %v", err)
	}
	db.JsonDb.LoadClientFromJsonFile()

	if _, err := db.GetClient(7); err == nil {
		t.Fatal("GetClient(7) error = nil, want removed client after reload")
	}
	if _, err := db.GetClientByVerifyKey("verify-reload"); err == nil {
		t.Fatal("GetClientByVerifyKey(verify-reload) error = nil, want stale lookup removed after reload")
	}
	if _, err := db.GetClientIdByBlake2bVkey(crypt.Blake2b("verify-reload")); err == nil {
		t.Fatal("GetClientIdByBlake2bVkey(verify-reload) error = nil, want stale hash index removed after reload")
	}
	if db.JsonDb.ClientIncreaseId != 0 {
		t.Fatalf("ClientIncreaseId = %d, want 0 after reloading an empty client file", db.JsonDb.ClientIncreaseId)
	}
}

func TestLoadClientFromJsonFileReplacesSameIDAndRemovesOldVerifyKeyIndex(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	payload := []byte(`[
  {"Id":7,"VerifyKey":"verify-old","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}},
  {"Id":7,"VerifyKey":"verify-new","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}}
]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()

	current, err := db.GetClient(7)
	if err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}
	if current.VerifyKey != "verify-new" {
		t.Fatalf("current.VerifyKey = %q, want verify-new", current.VerifyKey)
	}
	if _, err := db.GetClientByVerifyKey("verify-old"); err == nil {
		t.Fatal("GetClientByVerifyKey(verify-old) error = nil, want stale same-id key removed after reload")
	}
	if lookedUp, err := db.GetClientByVerifyKey("verify-new"); err != nil {
		t.Fatalf("GetClientByVerifyKey(verify-new) error = %v", err)
	} else if lookedUp.Id != 7 {
		t.Fatalf("GetClientByVerifyKey(verify-new) id = %d, want 7", lookedUp.Id)
	}
	if _, err := db.GetClientIdByBlake2bVkey(crypt.Blake2b("verify-old")); err == nil {
		t.Fatal("GetClientIdByBlake2bVkey(verify-old) error = nil, want stale hash removed")
	}
	if id, err := db.GetClientIdByBlake2bVkey(crypt.Blake2b("verify-new")); err != nil {
		t.Fatalf("GetClientIdByBlake2bVkey(verify-new) error = %v", err)
	} else if id != 7 {
		t.Fatalf("GetClientIdByBlake2bVkey(verify-new) = %d, want 7", id)
	}
}

func TestLoadClientFromJsonFileSkipsDuplicateVerifyKeysAcrossDifferentIDs(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	payload := []byte(`[
  {"Id":7,"VerifyKey":"verify-shared","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}},
  {"Id":8,"VerifyKey":"verify-shared","Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}}
]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()

	first, err := db.GetClient(7)
	if err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}
	if first.VerifyKey != "verify-shared" {
		t.Fatalf("first.VerifyKey = %q, want verify-shared", first.VerifyKey)
	}
	if _, err := db.GetClient(8); err == nil {
		t.Fatal("GetClient(8) error = nil, want duplicate verify-key client skipped on reload")
	}
	if lookedUp, err := db.GetClientByVerifyKey("verify-shared"); err != nil {
		t.Fatalf("GetClientByVerifyKey(verify-shared) error = %v", err)
	} else if lookedUp.Id != 7 {
		t.Fatalf("GetClientByVerifyKey(verify-shared) id = %d, want 7", lookedUp.Id)
	}
}

func TestLoadClientFromJsonFileDropsInvalidOwnerEntryAndGetClientDropsInvalidRecord(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	db.JsonDb.Users.Store(9, "bad-owner-entry")
	payload := []byte(`[
  {"Id":7,"VerifyKey":"verify-owner","OwnerUserID":9,"Status":true,"Cnf":{},"Flow":{"ExportFlow":0,"InletFlow":0}}
]`)
	if err := os.WriteFile(db.JsonDb.ClientFilePath, payload, 0o600); err != nil {
		t.Fatalf("WriteFile(clients.json) error = %v", err)
	}

	db.JsonDb.LoadClientFromJsonFile()

	stored, err := db.GetClient(7)
	if err != nil {
		t.Fatalf("GetClient(7) error = %v", err)
	}
	if stored.OwnerID() != 9 {
		t.Fatalf("stored.OwnerID() = %d, want 9", stored.OwnerID())
	}
	if stored.OwnerUser() != nil {
		t.Fatalf("stored.OwnerUser() = %#v, want nil when owner entry is invalid", stored.OwnerUser())
	}
	if _, ok := db.JsonDb.Users.Load(9); ok {
		t.Fatal("invalid owner user entry should be dropped during client reload")
	}

	db.JsonDb.Clients.Store(99, "bad-client-entry")
	if _, err := db.GetClient(99); err != ErrClientNotFound {
		t.Fatalf("GetClient(99) error = %v, want ErrClientNotFound", err)
	}
	if _, ok := db.JsonDb.Clients.Load(99); ok {
		t.Fatal("GetClient() should drop invalid client entries")
	}
}

func TestGetClientByVerifyKeyRepairsStaleBlake2bIndex(t *testing.T) {
	resetMigrationTestDB(t)

	db := GetDb()
	client := &Client{
		Id:        7,
		VerifyKey: "verify-fast",
		Status:    true,
		Cnf:       &Config{},
		Flow:      &Flow{},
	}
	if err := db.NewClient(client); err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	hash := crypt.Blake2b("verify-fast")
	CurrentBlake2bVkeyIndex().Add(hash, 404)

	lookedUp, err := db.GetClientByVerifyKey("verify-fast")
	if err != nil {
		t.Fatalf("GetClientByVerifyKey(verify-fast) error = %v", err)
	}
	if lookedUp.Id != 7 {
		t.Fatalf("GetClientByVerifyKey(verify-fast) id = %d, want 7", lookedUp.Id)
	}

	id, err := db.GetClientIdByBlake2bVkey(hash)
	if err != nil {
		t.Fatalf("GetClientIdByBlake2bVkey(verify-fast) error = %v", err)
	}
	if id != 7 {
		t.Fatalf("GetClientIdByBlake2bVkey(verify-fast) = %d, want 7", id)
	}
}
