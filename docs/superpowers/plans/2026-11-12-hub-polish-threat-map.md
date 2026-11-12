# Sentinela Hub Polish: Raio-X Forense Modal & 2D Threat Map Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement an interactive floating Forensic Raio-X Modal with canonical hexdump and MITRE ATT&CK attribution, alongside a real-time procedural 2D Vector Threat Map with animated Bezier curves and HUD in `sentinela-hub`.

**Architecture:** The Forensic Modal renders as an immediate-mode floating `egui::Window` triggered by clicks on table rows, map beacons, or HUD cards. The 2D Threat Map uses procedural vector rendering in `egui::Painter` with equirectangular coordinates, an offline centroid table, and parametric quadratic Bezier curves with pulsating flight particles.

**Tech Stack:** Rust 2021, `eframe = "0.28"`, `egui = "0.28"`, `egui_plot = "0.28"`, `rusqlite = "0.31"`, `tokio = "1"`.

**Spec:** [docs/superpowers/specs/2026-11-12-hub-polish-threat-map-design.md](file:///home/salvadorpontes/sentinela-hub/docs/superpowers/specs/2026-11-12-hub-polish-threat-map-design.md)

---

## Global Constraints

- 100% pure Rust code, zero external runtime assets or internet tile dependencies.
- Sub-millisecond rendering overhead: 60 FPS guaranteed on Wayland and X11.
- All unit tests must pass (`cargo test`).
- Zero compiler warnings (`#[warn(dead_code)]`, float fallback, or unused imports).

---

## Review Focus

1. **Hexdump String Safety:** Payloads with non-ASCII, UTF-8 surrogate, or binary bytes must format into exact 16-byte aligned lines without panics.
2. **Equirectangular Projection Clamping:** Longitudes (-180..180) and latitudes (-90..90) must clamp to screen rect bounds and never produce NaN coordinates.
3. **Bezier Curve Altitude Dampening:** Arcs spanning across opposite hemispheres (e.g. Asia to Europe) must damp control-point elevation to prevent clipping outside the top viewport.
4. **Decay & Pruning of Map Arcs:** Arcs must smoothly fade and be garbage-collected after their 20-second lifespan to prevent memory leaks in the display buffer.
5. **Modal Focus & Keyboard Escape:** Pressing `Esc` or clicking `[✕ Fechar]` must reliably close the Raio-X modal.

---

## Tasks

### Task 1: Forensic Raio-X Modal & Hexdump Formatter (`src/ui/modal.rs`)

**Files:**
- Create: `/home/salvadorpontes/sentinela-hub/src/ui/modal.rs`
- Modify: `/home/salvadorpontes/sentinela-hub/src/ui/mod.rs`
- Test: unit tests within `/home/salvadorpontes/sentinela-hub/src/ui/modal.rs`

**Interfaces:**
- Consumes: `HubIncident` from `crate::models`
- Produces:
  - `pub fn format_hexdump(data: &[u8]) -> String`
  - `pub fn map_to_mitre(service: &str, port: u16, severity: &str, payload: Option<&str>) -> (&'static str, &'static str)`
  - `pub fn render_raio_x_modal(ctx: &egui::Context, incident: &HubIncident, close_modal: &mut bool, toast_msg: &mut Option<(String, std::time::Instant)>)`

- [ ] **Step 1: Write failing unit tests in `src/ui/modal.rs`**
  - Test `test_format_hexdump_standard`: verifies 16-byte alignment and ASCII representation.
  - Test `test_map_to_mitre_ssh_and_dns`: verifies SSH maps to `T1110.001` and DNS maps to `T1071.004`.

- [ ] **Step 2: Run tests to verify failure**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml -- modal::tests`
  - Expected: FAIL with unresolved module or missing functions.

- [ ] **Step 3: Implement `format_hexdump`, `map_to_mitre`, and `render_raio_x_modal` in `src/ui/modal.rs`**
  - Format canonical hex: `00000000  53 53 48 2d  |SSH-|`.
  - Render modal window using `egui::Window` anchored at center.
  - Implement action buttons `[🚫 Banir IP]` (copies iptables rule to clipboard) and `[📋 Copiar JSON]`.

- [ ] **Step 4: Register `pub mod modal;` in `src/ui/mod.rs` and run tests**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml -- modal::tests`
  - Expected: PASS with 2 passed tests.

- [ ] **Step 5: Commit**
  ```bash
  git -C /home/salvadorpontes/sentinela-hub add src/ui/modal.rs src/ui/mod.rs
  git -C /home/salvadorpontes/sentinela-hub commit -m "feat: add forensic raio-x modal with hexdump and mitre att&ck mapping"
  ```

---

### Task 2: 2D Threat Map Engine & Projection Math (`src/ui/views/map.rs`)

**Files:**
- Create: `/home/salvadorpontes/sentinela-hub/src/ui/views/map.rs`
- Modify: `/home/salvadorpontes/sentinela-hub/src/ui/views/mod.rs`
- Test: unit tests within `/home/salvadorpontes/sentinela-hub/src/ui/views/map.rs`

**Interfaces:**
- Consumes: `HubIncident`, `AgentNode` from `crate::models`
- Produces:
  - `pub fn resolve_coordinates(country: &str, city: &str, ip: &str) -> (f32, f32)`
  - `pub fn project_to_screen(lat: f32, lon: f32, rect: egui::Rect) -> egui::Pos2`
  - `pub struct ActiveAttackArc` with flight interpolation `particle_pos(now: Instant) -> Option<egui::Pos2>`

- [ ] **Step 1: Write failing unit tests in `src/ui/views/map.rs`**
  - Test `test_resolve_coordinates_countries`: verifies Portugal, Germany, US, China return valid lat/lons.
  - Test `test_project_to_screen_bounds`: verifies bounds mapping at canvas corners without panics or NaN.
  - Test `test_active_attack_arc_flight`: verifies particle position moves along the Bezier curve over time.

- [ ] **Step 2: Run tests to verify failure**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml -- views::map::tests`
  - Expected: FAIL with unresolved module or missing functions.

- [ ] **Step 3: Implement coordinate resolution and projection math in `src/ui/views/map.rs`**
  - Equirectangular projection mapping formula with safety clamping.
  - Centroid table for top 30 countries and RFC 1918 LAN offset logic.
  - Quadratic Bezier arc math with altitude damping.

- [ ] **Step 4: Register `pub mod map;` in `src/ui/views/mod.rs` and run tests**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml -- views::map::tests`
  - Expected: PASS with 3 passed tests.

- [ ] **Step 5: Commit**
  ```bash
  git -C /home/salvadorpontes/sentinela-hub add src/ui/views/map.rs src/ui/views/mod.rs
  git -C /home/salvadorpontes/sentinela-hub commit -m "feat: add threat map projection engine and bezier curve math"
  ```

---

### Task 3: Threat Map Canvas Rendering & HUD Live Overlay (`src/ui/views/map.rs`)

**Files:**
- Modify: `/home/salvadorpontes/sentinela-hub/src/ui/views/map.rs`
- Test: integration verification in `src/ui/views/map.rs`

**Interfaces:**
- Consumes: `egui::Ui`, `&[HubIncident]`, `&[AgentNode]`, `&mut Vec<ActiveAttackArc>`
- Produces:
  - `pub fn render_threat_map_view(ui: &mut egui::Ui, nodes: &[AgentNode], incidents: &[HubIncident], arcs: &mut Vec<ActiveAttackArc>, selected_node: &Option<String>, modal_incident: &mut Option<HubIncident>)`

- [ ] **Step 1: Implement vector world map drawing in `src/ui/views/map.rs`**
  - Draw cyber latitude/longitude grid lines in slate `#1f2937`.
  - Draw simplified continental vector outlines (Europe, Americas, Asia, Africa, Oceania).
  - Draw glowing target node beacons with expanding radar rings.

- [ ] **Step 2: Implement Bezier attack arcs and particle rendering**
  - Draw quadratic Bezier curves colored by incident severity.
  - Draw traveling glowing pulse particles along active arcs.
  - Prune expired arcs older than 20 seconds.

- [ ] **Step 3: Implement translucent Live HUD Overlay in bottom-left**
  - Render floating HUD card showing the 5 most recent attacks.
  - Clicking any card in the HUD assigns `*modal_incident = Some(inc.clone())`.

- [ ] **Step 4: Verify test suite compiles cleanly**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml`
  - Expected: PASS with all tests passing and zero compiler warnings.

- [ ] **Step 5: Commit**
  ```bash
  git -C /home/salvadorpontes/sentinela-hub add src/ui/views/map.rs
  git -C /home/salvadorpontes/sentinela-hub commit -m "feat: implement threat map canvas rendering and live attacks hud"
  ```

---

### Task 4: UI Polish, Sorting & Full App Integration (`src/app.rs`, `src/ui/header.rs`, `src/ui/views/incidents.rs`)

**Files:**
- Modify: `/home/salvadorpontes/sentinela-hub/src/ui/header.rs`
- Modify: `/home/salvadorpontes/sentinela-hub/src/ui/views/incidents.rs`
- Modify: `/home/salvadorpontes/sentinela-hub/src/app.rs`
- Test: `/home/salvadorpontes/sentinela-hub/tests` and end-to-end launch verification

**Interfaces:**
- Consumes: All UI components (`modal`, `map`, `header`, `sidebar`, `incidents`, `correlations`, `analytics`)
- Produces: Integrated `HubApp` with `ViewTab::ThreatMap`, `active_modal`, interactive table sorting, and map arc seeding.

- [ ] **Step 1: Update `src/ui/header.rs`**
  - Add `ViewTab::ThreatMap` variant.
  - Add `[ 🗺️ Threat Map ]` tab button in the navigation bar.
  - Add pulsing green activity indicator next to the Ingestion server status.

- [ ] **Step 2: Update `src/ui/views/incidents.rs`**
  - Add clickable column headers for sorting by Threat Score, Hits, and Timestamp.
  - Add double-click / click row interaction to set `modal_incident = Some(inc.clone())`.
  - Style severity badges with rounded pill frames.

- [ ] **Step 3: Integrate into `src/app.rs`**
  - Add `active_modal: Option<HubIncident>` to `HubApp`.
  - Add `active_arcs: Vec<ActiveAttackArc>` to `HubApp`.
  - Implement historical arc seeding on startup and when switching to `ViewTab::ThreatMap`.
  - In `update()`, append incoming `HubEvent::NewIncident` to `active_arcs`.
  - In `update()`, render `modal::render_raio_x_modal` when `active_modal.is_some()`.

- [ ] **Step 4: Run full verification suite**
  - Run: `cargo test --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml`
  - Expected: PASS with 100% tests passing and zero warnings.

- [ ] **Step 5: Build release binary and install to `~/.local/bin/sentinela-hub`**
  - Run: `cargo build --release --manifest-path /home/salvadorpontes/sentinela-hub/Cargo.toml`
  - Copy binary: `cp target/release/sentinela-hub ~/.local/bin/sentinela-hub`
  - Verify execution with timeout: `timeout 2s ~/.local/bin/sentinela-hub`

- [ ] **Step 6: Commit**
  ```bash
  git -C /home/salvadorpontes/sentinela-hub add src/ui/header.rs src/ui/views/incidents.rs src/app.rs
  git -C /home/salvadorpontes/sentinela-hub commit -m "feat: integrate threat map, raio-x modal, and ui polish into hub"
  ```
