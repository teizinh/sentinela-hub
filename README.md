# 🛡️ Sentinela Hub

> **SIEM & Multi-Host Threat Correlation Center** — 100% Rust, Native Desktop GUI (`egui`/`eframe`), Embedded SQLite (`WAL`), and Real-time Telemetry Ingestion.

`sentinela-hub` é o centro de comando e agregação distribuída para agentes [Sentinela](https://github.com/teizinh/sentinela). Concebido especificamente para equipas SOC, Blue Teams e homelabs, recebe eventos de segurança em direto de dezenas de máquinas na rede, armazena o histórico forense num SQLite embutido de alto rendimento e **correlaciona ataques coordenados em tempo real** através de janelas temporais deslizantes.

---

## ⚡ Funcionalidades Principais

1. **Dashboard Nativo em Rust Puro (`egui` / `eframe`):**
   - Renderização fluida a 60 FPS com zero consumo de Chromium/Electron/Node.js.
   - Tema *Dark Cyber SOC* elegante (ardósia `#0D1117`, ciano, âmbar e badges coloridos com efeito pill glow).
   - Filtragem e pesquisa instantânea por IP, porta, serviço, severidade e nó.
   - Ordenação dinâmica e interativa das tabelas com um clique nos cabeçalhos.

2. **🗺️ 2D Threat Map Vetorial em Tempo Real:**
   - Mapa-múndi vetorial procedimental em coordenadas equirretangulares (zero dependência de tiles online, 100% offline).
   - Beacons dos nós SOC (Portugal, Alemanha, etc.) com anéis de radar pulsantes a 60 FPS.
   - Arcos de trajetória balística em curvas de Bezier quadráticas ligando os atacantes aos nós sob ataque.
   - Partículas de energia e feixes com cauda de velocidade, coloridos pela severidade do incidente.
   - Detetor especial para tráfego privado / Wi-Fi local (RFC 1918) com órbitas visuais e etiqueta `LAN/Wi-Fi`.
   - Painel flutuante HUD (*Heads-Up Display*) no canto inferior com os últimos ataques em direto.

3. **🔬 Modal de Raio-X Forense:**
   - Janela flutuante interativa com visualizador canónico de hexdump alinhado a 16 bytes (`00000000 53 53 48 ... |SSH...|`).
   - Mapeamento automático de técnicas **MITRE ATT&CK®** (`T1110.001 Brute Force`, `T1046 Scanning`, `T1071.004 DNS Tunneling`, `T1486 Ransomware`, `T1021 Remote Desktop/Services`).
   - Atribuição geográfica offline, hostname rDNS, ISP e detalhes do socket.
   - Ações imediatas: botão `[🚫 Banir IP]` (copia regra de `iptables` pronta e gera notificação) e `[📋 Copiar JSON]`.

4. **⚡ Grafo Radial de Ataques Distribuídos (SIEM):**
   - Visualização topológica vetorial de ataques multi-host: o IP atacante fica no centro com anéis de radar e vetores laser em direção aos nós visados em simultâneo.
   - Agrupamento em janelas deslizantes (ex: 10 minutos) que identifica campanhas coordenadas de varrimento.
   - Interatividade total: passar o cursor mostra o estado do nó e dos serviços; clicar copia o IP atacante com feedback toast.

5. **📊 Visualização Gráfica & Métricas (`egui_plot`):**
   - Linha temporal contínua dos ataques com suporte a zoom e pan interativo do rato.
   - Matriz visual MITRE ATT&CK com cartões e barras de progresso coloridas pelas técnicas mais observadas.
   - Distribuição percentual dos serviços e protocolos mais visados (SSH, HTTP, SMB, DNS, etc.).

6. **🚨 Alertas Visuais & Relatórios Executivos SOC:**
   - Vinheta suave pulsante a vermelho vivo nas margens do ecrã quando ocorre um incidente de severidade `CRÍTICO`.
   - Botão **`[ 📄 Relatório SOC ]`**: gera e exporta relatórios executivos estruturados em Markdown e JSON com o sumário de incidentes, atacantes de topo e matriz de remediação.

7. **Ingestão Assíncrona de Telemetria (`tokio`):**
   - Listener HTTP/JSON ultraleve a escutar por padrão em `0.0.0.0:8765`.
   - Rotas dedicadas:
     - `POST /api/v1/incident`: Registo atómico de incidentes e envio imediato para a UI via canais cross-thread.
     - `POST /api/v1/heartbeat`: Registo automático de novos nós e telemetria de presença (*keepalive*).
     - `GET /api/v1/health`: Verificação de saúde da API.

8. **Armazenamento Forense Robusto (SQLite WAL):**
   - Base de dados local em `~/.local/share/sentinela-hub/sentinela_hub.db`.
   - Modo WAL (*Write-Ahead Logging*) com `synchronous = NORMAL` para garantir persistência imediata sem bloquear leituras da interface gráfica.

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
