# Desktop-style WebPanel

[简体中文](webpanel.zh-CN.md) · [Documentation](README.md)

Status: interaction and API plan, with implementation after backend acceptance. The design direction is a browser desktop similar in interaction style to fnOS: an application launcher, taskbar, movable windows and central notifications. The [fnOS setup guide](https://help.fnnas.com/articles/v1/start/install-os) illustrates browser access leading into a desktop. tauCloud will use its own visual design and application structure; no frontend framework is selected yet.

## 1. Desktop shell

- A desktop/workspace with application shortcuts, a launcher and a taskbar/dock showing running and minimized windows.
- A window manager with focus/stacking, move/resize, minimize, maximize, restore and close. Keep dialogs within the viewport and provide keyboard alternatives to dragging.
- A top-level status area for the current user, server connection, service degradation, notifications and long-running tasks.
- Per-user wallpaper/theme, shortcut order and window layout preferences, stored independently of filesystem permissions. Revalidate restored window resources against current authorization.
- Deep links to an application/resource and reliable browser history. Multiple windows are views of backend resources, not separate copies of authoritative data.
- Responsive behavior: smaller screens use a single active full-screen application with navigation rather than forcing floating desktop windows onto a phone.

Keep the initial window manager focused. Multi-monitor emulation, a remote OS desktop and arbitrary terminal execution are outside this milestone.

## 2. Built-in applications

| Application | Initial responsibilities |
| --- | --- |
| File Manager | Private/team spaces, browse, upload/download, rename/move, share policy and transfer progress |
| Control Panel | Users/groups, network listeners, credentials, access policies and service settings |
| Storage Manager | Physical disks → arrays/pools → volumes → mounts; health, capacity, RAID plans, replacement/rebuild and expansion |
| Resource Monitor | CPU/memory/network/disks, per-process resource use, protocol health and historical metrics |
| Applications | Installed plugins, explicit permissions, lifecycle and health; trusted-only policy where required |
| Containers | Docker engine selection, inventory, logs/stats and approved lifecycle actions |
| Update Center | Available versions, verified packages, affected services, maintenance plans and rollback/recovery state |
| Task and Notification Center | Durable jobs, progress, cancellation boundaries, failures and reconnect/resync |

A regular user sees permitted file/space functions and personal preferences; administrative applications require backend authorization. Hiding an icon is not access control.

## 3. Backend and session contracts

The shell and all built-in apps consume the versioned public API; no direct process, disk, database or Docker socket access. Use one authenticated session and a bounded shared event connection, with per-app subscriptions and polling/resync fallback. Backend jobs outlive the window and browser. Closing a task window never implicitly cancels a rebuild, update or file job.

Distinguish browser-local uploads from server-owned jobs: a browser upload can stop when the page closes unless a resumable upload contract exists. Show that difference in transfer status. Persist only nonsecret resumable metadata and revalidate before resuming.

Capabilities determine available actions and provider terminology. Preserve native RAID/Storage Spaces names and show unsupported actions with reasons. Present unavailable/stale telemetry and service degradation explicitly. A disconnected API must not turn a pending operation into a guessed success.

Resource updates use revisions; concurrent edits produce a conflict flow rather than silently overwriting. Session expiry locks the shell and prompts reauthentication without erasing server jobs. An API/frontend version mismatch shows a controlled refresh/reconnect path. Sensitive state is cleared on logout and must not leak between browser users.

## 4. Storage and update flows

Storage Manager uses an inspect → select → preview → confirm → track workflow. Identify disks by stable ID plus model/capacity/location, show affected data and consumers, and obtain confirmation for the actual backend plan. A changed topology invalidates that preview. Do not show a generic “success” toast while a rebuild is still running.

Update Center separates checking/downloading from installing. Show component versions, signature verification, planned disconnects, compatibility and rollback limitations. After approval, track the durable update job; if the API restarts, display reconnecting and recover the job by ID. A recovery-required outcome provides a specific next action instead of a loop of blind retries.

Notifications link to a resource/job, deduplicate recurring failures and remain inspectable after reconnect. Background operations expose phase, affected resources and whether cancellation is currently safe.

## 5. App boundaries and delivery

First-party app views have local loading/error boundaries so one failed view can be closed/reopened without resetting the whole desktop. Browser-level faults can still affect the tab; backend processes remain independent. Third-party plugin UI, if later allowed, runs in a separately sandboxed origin/frame with a narrow validated message bridge. Do not load arbitrary plugin JavaScript into the privileged desktop origin.

Choose the frontend framework in M9 against window management, accessibility, localization, generated API clients and independent packaging needs. Keep backend builds free of Node/frontend requirements. Ship immutable versioned assets with a declared API compatibility range.

M9 acceptance covers keyboard/focus management, window state restoration, narrow-screen layout, two-user isolation, stale/degraded services, session expiry, concurrent edits, browser refresh during a server job, safe destructive-operation previews and component-update reconnects. Implement the backend contracts first; this document does not start frontend implementation.
