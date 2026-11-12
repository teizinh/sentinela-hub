# Sentinela Hub Polish: Raio-X Forense Modal & 2D Threat Map Design Document

## 1. Intent & Context
Sentinela Hub is the central SIEM and distributed correlation dashboard for the Sentinela ecosystem. While the functional core (SQLite WAL, multi-host correlation, 60 FPS egui shell, async ingestion) is solid, the user identified a need for higher visual polish and deeper technical forensic capability.

The goal is to elevate Sentinela Hub from a basic tabular dashboard into an authentic, elite SOC command center by pairing deep forensic inspection (**Raio-X Forense Modal**) with high-impact situational awareness (**2D Threat Map**).

---

## 2. Goals, Non-Goals & Anti-Goals

### Goals
1. **Interactive Raio-X Forense Modal (`src/ui/modal.rs`):**
   - Clicking any incident in the Incidents Table, HUD overlay, or Threat Map markers opens a floating forensic modal window.
   - Formatted canonical hexdump (`00000000  53 53 48...  |SSH...|`) of captured payloads.
   - Automatic MITRE ATT&CK technique mapping (e.g. `T1110.001 Brute Force`, `T1046 Network Service Scanning`, `T1071.004 DNS Tunneling`, `T1486 Data Encrypted for Impact`).
   - Deep network attribution: rDNS hostname, country flag/code, city, ISP, threat score breakdown.
   - One-click actions: `[🚫 Banir IP]` (copies iptables rule & notifies), `[📋 Copiar IOC/JSON]`, `[✕ Fechar]`.
2. **2D Threat Map View (`src/ui/views/map.rs`):**
   - A dedicated tab in the header: `[ 🗺️ Threat Map ]`.
   - 2D equirectangular world projection rendered procedurally in `egui::Painter`.
   - Target nodes plotted as emerald-green glowing beacons with expanding radar rings.
   - Attack trajectories rendered as curved Bezier arcs connecting attacker origin coordinates to target machine coordinates.
   - Animated glowing energy particles traveling along the arcs in real time.
   - Color-coded severity arcs (Crimson for Critical, Purple for Sweep, Amber for Medium, Cyan for Scan).
   - Seeding engine that populates recent attacks from SQLite on tab load so the map is visually alive immediately.
3. **UI Polish & Styling Enhancements:**
   - Rounded pill badges with glow effects for severities.
   - Column sorting support (by Threat Score, Hits, Timestamp).
   - Live activity heartbeat indicator in the top header.

### Non-Goals
- 3D globe rotation requiring heavy OpenGL/Vulkan shaders or GIS crates (keeps the binary compact, dependency-free, and guaranteed 60 FPS).
- External network map tile downloading (the map must work 100% offline in air-gapped homelabs or field environments).
- Full remote SOAR bidirectional agent execution (commands over network).

### Anti-Goals
- Any UI frame drops or stuttering during attack line rendering or bezier particle animation.
- Visual clutter: attacks fade smoothly over a 20-second decay window.

---

## 3. Constraints
- **Language & Runtime:** 100% safe Rust 2021 Edition.
- **GUI Framework:** `eframe = "0.28"`, `egui = "0.28"`.
- **Portability:** Must run natively on Linux Wayland/X11 and Windows with zero dynamic C library dependencies.
- **Storage:** Persisted SQLite database at `~/.local/share/sentinela-hub/sentinela_hub.db`.

---

## 4. Approaches & Tradeoffs

### Approach 1: Procedural Vector Canvas with Built-In Centroids (Selected)
- Continental landmass outlines and equirectangular grid rendered mathematically via `egui::Painter`.
- Geographic coordinates `(lat, lon)` resolved using an offline centroid lookup table for top world countries and local networks.
- Attack arcs drawn as quadratic Bezier curves with parametric `t in 0.0..=1.0` particle animation.
- **Pros:** Zero binary bloat, perfectly crisp at any display DPI (1080p, 4K, 1440p), completely offline, sub-millisecond render cost.
- **Cons:** Continental outlines are stylized/schematic rather than satellite-accurate.

### Approach 2: Embedded Raster World Map Image (`include_bytes!`)
- High-res PNG/SVG embedded in binary, rendered to an `epaint::ColorImage` texture.
- Points plotted on top of the texture.
- **Pros:** Realistic coastlines.
- **Cons:** Increases binary size by several megabytes, blurs or pixelates upon window resizing, and clashes with the clean dark vector cyber aesthetic.

**Decision:** Approach 1 is selected. It aligns with Sentinela's core philosophy: ultra-light, authentic engineering, zero bloat, and total independence from external files.

---

## 5. Architectural Specifications & Builder Decisions

### 5.1 Component: Forensic Raio-X Modal (`src/ui/modal.rs`)
- **State in `HubApp`:**
  ```rust
  pub selected_incident: Option<HubIncident>,
  ```
- **Modal Lifecycle:**
  - Opened when clicking any row in the incident table, an attack marker, or a card in the Threat Map Live HUD.
  - Rendered via `egui::Window::new("🔬 RAIO-X FORENSE").anchor(Align2::CENTER_CENTER, [0.0, 0.0]).resizable(true).collapsible(false)`.
- **Payload Hexdump Formatter:**
  - Converts string/raw payload bytes into 16-byte offset hexdump:
    `00000000  53 53 48 2d 32 2e 30 2d  4f 70 65 6e 53 53 48 5f  |SSH-2.0-OpenSSH_|`
- **MITRE ATT&CK Mapping:**
  - Evaluates `service`, `port`, `severity`, and `threat_score` to tag the attack with Technique ID, Name, and ATT&CK Matrix Tactic (`T1110.001`, `T1046`, `T1071.004`, `T1486`, `T1048`, `T1059`).
- **Action Buttons:**
  - `[🚫 Banir IP]`: Sets toast alert and copies `sudo iptables -A INPUT -s <IP> -j DROP` to clipboard.
  - `[📋 Copiar JSON]`: Copies raw incident JSON to clipboard.
  - `[✕ Fechar]`: Sets `selected_incident = None`.

### 5.2 Component: 2D Threat Map (`src/ui/views/map.rs`)
- **Tab Registration:** Add `ViewTab::ThreatMap` to `src/ui/header.rs`.
- **Projection Formula:**
  - Maps `(lon: -180.0..180.0, lat: -90.0..90.0)` into rect `[x0, y0, width, height]`:
    - `x = x0 + (lon + 180.0) / 360.0 * width`
    - `y = y0 + (90.0 - lat) / 180.0 * height`
- **Target Node Positioning (Builder Decision 1):**
  - Target nodes default to Portugal `(lat: 39.5, lon: -8.0)`. If a node's name contains a specific region (e.g. "Frankfurt", "US", "London"), it resolves to that region's centroid.
  - Local RFC 1918 private network attacks (Wi-Fi, LAN, Docker) are offset slightly around the node's position `(lat + 2.0, lon - 3.0)` with a distinctive cyan ring labeled "LAN / Wi-Fi".
- **Arc Lifecycle & Historical Seeding (Builder Decision 2):**
  - When the map view loads or when starting the app, the engine seeds up to the 10 most recent incidents from SQLite into active display arcs with synthetic staggered flight offsets.
  - Incoming live incidents from `event_rx` append new arcs with `created_at: Instant::now()`.
  - Arcs fade smoothly over 20 seconds.
- **Hit-Testing & Interaction (Builder Decision 3):**
  - A translucent Live Attacks HUD is rendered in the bottom-left corner of the map.
  - Clicking any card in the HUD opens that incident directly in the Raio-X modal.
  - Clicking an attacker origin beacon on the map selects that incident and opens the Raio-X modal.
  - Clicking a target node beacon filters the display to that node.
- **Animated Attack Arcs:**
  - Quadratic Bezier control point lifted upwards:
    `ctrl = center_between(start, end) + vec2(0.0, -distance * 0.25)`
  - Particle traveling along curve based on `(Instant::now() - start_time)`.

### 5.3 Component: Visual Polish & Header Improvements (`src/ui/header.rs`, `src/ui/mod.rs`)
- Top status header includes a pulsing dot `🟢 [60 FPS | Ingestão Ativa :8765]`.
- Navigation tabs updated: `[🚨 Incidentes]`, `[🗺️ Threat Map]`, `[⚡ Correlações]`, `[📊 Analytics]`.
- Severity badges styled with pill borders and colored background tints.
- Table columns in `views/incidents.rs` support interactive clicking for sorting by Threat Score, Hits, or Timestamp.
