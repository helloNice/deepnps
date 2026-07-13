# DeepNPC Zero-Touch Client Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Extend the existing `npc.exe` into a zero-configuration Windows client that enrolls automatically, discovers local services, and publishes up to three HTTP, TCP, or UDP services through NPS.

**Architecture:** Keep the existing NPS bridge and client-scoped management APIs as the data plane and control plane. Add public-key device enrollment to `nps`, then embed a loopback-only control service, discovery engine, and publication adapter in `npc`.

**Tech Stack:** Go 1.26, existing NPS management API, Ed25519, Windows DPAPI, Go `embed`, HTML/CSS/JavaScript, WSL2 distribution `supernps`.

**test** 使用 wsl -d supernps 这个虚拟机进行测试
---

## Confirmed Scope

- Distribute one generic Windows executable; users only double-click it.
- Generate and persist a per-device key under `%LOCALAPPDATA%\DeepNPS`.
- Enroll automatically, create one NPS client, and enforce three combined host/tunnel resources.
- Discover local listeners automatically; run LAN and custom-host scans only on demand.
- Identify common services by port presets and bounded protocol probes.
- Treat HTTP as a host route and TCP/UDP as allocated server ports.
- Keep publications across disconnects and restarts until the user cancels them.
- Use `xxxx.localhost:18080` for isolated first-stage HTTP testing.
- Mark sensitive services and require confirmation; block unsafe Windows RPC exposure.
- Defer trusted HTTPS and real public DNS until a controlled domain is available.

## Implementation Tasks

### 1. Baseline and contracts

Run `go test ./...` and `make build`. Add contract tests before each behavior change and preserve legacy CLI, config-file, launch URI, SDK, and Windows service modes.

### 2. Device enrollment server

Add persisted device identity fields to the client model and cloning/import paths. Add challenge and completion endpoints to `web/api`, backed by a service that verifies Ed25519 signatures, expires one-use challenges, deduplicates public keys, creates clients with `MaxTunnelNum=3`, and applies registration rate limits. Gate enrollment behind explicit server configuration.

### 3. Device identity client

Create a client package that generates Ed25519 keys and stores device state in `%LOCALAPPDATA%\DeepNPS`. Encrypt private material with DPAPI on Windows and provide a test-safe implementation for other platforms. Never expose the private key or NPS `vkey` to browser JavaScript.

### 4. Managed NPC bootstrap

Extend `cmd/npc/bootstrap.go` with a zero-touch mode used when no explicit legacy launch input is supplied. Start the local control service, enroll or restore credentials, build the existing direct client configuration, connect, and retry with bounded exponential backoff.

### 5. Service discovery

Create local listener enumeration and bounded TCP/HTTP probes. Add a data-driven service catalog, confidence and risk classification, protocol-specific UDP probes, cancellable LAN scans, CIDR limits, concurrency limits, and custom target validation.

### 6. Local control Web

Embed a responsive static application into `npc.exe`. Bind only to loopback, use an in-memory random session and strict Origin/CSRF checks, expose status/discovery/publication APIs, auto-open the browser only in interactive mode, and avoid duplicate instances.

### 7. Publication orchestration

Authenticate using the existing client-scoped management token flow. Reuse `/api/hosts` and `/api/tunnels`, idempotency support, ownership checks, automatic port allocation, and the existing combined `MaxTunnelNum` quota. Revalidate targets and risk policy before writes.

### 8. Isolated WSL verification

Use only commands prefixed with `wsl -d supernps --`. Place artifacts under `$HOME/deepnps-test`, use bridge `18024`, management `18081`, HTTP `18080`, and allocation range `19000-19099`. Do not install services, alter global DNS/firewall settings, or stop unrelated processes.

### 9. Verification and documentation

Run targeted tests, `go test ./...`, `make build`, and Windows cross-builds. Verify enrollment, duplicate enrollment, reconnect, discovery, HTTP/TCP/UDP publication, idempotency, quota rejection, risk confirmation, cancellation, and restart recovery. Capture desktop and narrow viewport screenshots and update client/security documentation.

## Acceptance Criteria

Starting a fresh `npc.exe` automatically creates and connects exactly one NPS client. The local page lists discovered services, publishes no more than three resources, returns working isolated test endpoints, preserves them after restart, and never grants access to another client's resources. All existing tests and build targets remain green.
