# 🛡️ Sentinela Hub

> **SIEM & Multi-Host Threat Correlation Center** — 100% Rust, Native Desktop GUI (`egui`/`eframe`), Embedded SQLite (`WAL`), and Real-time Telemetry Ingestion.

`sentinela-hub` é o centro de comando e agregação distribuída para agentes [Sentinela](https://github.com/teizinh/sentinela). Concebido especificamente para equipas SOC, Blue Teams e homelabs, recebe eventos de segurança em direto de dezenas de máquinas na rede, armazena o histórico forense num SQLite embutido de alto rendimento e **correlaciona ataques coordenados em tempo real** através de janelas temporais deslizantes.

---

## ⚡ Funcionalidades Principais

1. **Dashboard Nativo em Rust Puro (`egui` / `eframe`):**
   - Renderização fluida a 60 FPS com zero consumo de Chromium/Electron/Node.js.
   - Tema *Dark Cyber SOC* elegante (ardósia `#0D1117`, ciano, âmbar e badges coloridos).
   - Filtragem e pesquisa instantânea por IP, porta, serviço, severidade e nó.

2. **Motor de Correlação Multi-Host (SIEM):**
   - Agrupa ataques na janela deslizante (ex: 10 minutos).
   - Quando um atacante atinge **2 ou mais máquinas distintas**, é disparado um alerta correlacionado com pontuação de ameaça acumulada (+15 de bónus multi-host) e mapeamento MITRE ATT&CK (`T1046` e `T1110`).

3. **Ingestão Assíncrona de Telemetria (`tokio`):**
   - Listener HTTP/JSON ultraleve a escutar por padrão em `0.0.0.0:8765`.
   - Rotas dedicadas:
     - `POST /api/v1/incident`: Registo atómico de incidentes e envio imediato para a UI via canais cross-thread.
     - `POST /api/v1/heartbeat`: Registo automático de novos nós e telemetria de presença (*keepalive*).
     - `GET /api/v1/health`: Verificação de saúde da API.

4. **Armazenamento Forense Robusto (SQLite WAL):**
   - Base de dados local em `~/.local/share/sentinela-hub/sentinela_hub.db`.
   - Modo WAL (*Write-Ahead Logging*) com `synchronous = NORMAL` para garantir persistência imediata sem bloquear leituras da interface gráfica.

5. **Visualização Gráfica & Métricas (`egui_plot`):**
   - Timeline interativa da severidade e frequência temporal dos ataques.
   - Ranking do *Top Atacantes Globais* e distribuição percentual dos serviços mais sondados (SSH, HTTP, SMB, DNS, etc.).

---

## 🚀 Instalação & Compilação

### Pré-requisitos
- Rust & Cargo (1.75+)
- Linux (Wayland ou X11) ou Windows

```bash
cd sentinela-hub
cargo build --release
```

O binário final otimizado fica disponível em `target/release/sentinela-hub`. Podes copiá-lo para o teu `~/.local/bin/`:

```bash
cp target/release/sentinela-hub ~/.local/bin/
```

---

## 💻 Como Utilizar

### 1. Iniciar o Hub
```bash
sentinela-hub
```
Podes definir uma porta ou base de dados personalizada através de variáveis de ambiente:
```bash
SENTINELA_HUB_ADDR="0.0.0.0:8765" SENTINELA_HUB_DB="./meu_hub.db" sentinela-hub
```

### 2. Ligar Agentes Sentinela ao Hub
Em qualquer máquina ou servidor da rede, basta arrancar o Sentinela com a flag `--hub`:

```bash
# No teu portátil ou VPS
sentinela --hub http://192.168.1.92:8765

# Em modo simulação para demonstrações
sentinela --simulate --hub http://127.0.0.1:8765
```

---

## 🛡️ Arquitetura do Sistema

```
 ┌──────────────────────┐          ┌──────────────────────┐
 │   Sentinela Nó 1     │          │   Sentinela Nó 2     │
 │ (HP Laptop - Fedora) │          │ (VPS Oracle - Ubuntu)│
 └──────────┬───────────┘          └──────────┬───────────┘
            │                                 │
            │ HTTP POST /api/v1/incident      │
            └───────────────┬─────────────────┘
                            │
                            ▼
          ┌───────────────────────────────────┐
          │      SENTINELA HUB (:8765)        │
          │  ┌─────────────────────────────┐  │
          │  │ Tokio Async Ingestion Engine│  │
          │  └──────────────┬──────────────┘  │
          │                 │                 │
          │        ┌────────┴────────┐        │
          │        ▼                 ▼        │
          │  ┌───────────┐    ┌─────────────┐ │
          │  │  SQLite   │    │ Correlation │ │
          │  │ WAL Store │    │   Engine    │ │
          │  └───────────┘    └──────┬──────┘ │
          │                          │        │
          │        ┌─────────────────┘        │
          │        ▼                          │
          │  ┌─────────────────────────────┐  │
          │  │  Native Desktop GUI (egui)  │  │
          │  │  60 FPS Cyber Dark Theme    │  │
          │  └─────────────────────────────┘  │
          └───────────────────────────────────┘
```

---

## 📄 Licença
Distribuído sob a licença MIT. Desenvolvido por Salvador Teixeira Pontes (`teizinh`).
