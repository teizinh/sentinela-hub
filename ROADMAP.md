# 🗺️ Roadmap de Evolução — Sentinela-Hub

Este documento mantém o registo planeado das próximas grandes funcionalidades e melhorias técnicas para o **Sentinela-Hub** (SIEM Central & Dashboard GUI).

---

## 🎯 Prioridades Planeadas

### 1. 🔔 Notificações Externas em Tempo Real (Discord & Telegram)
- [ ] Módulo `src/alerts/notifications.rs` para disparo assíncrono de alertas críticos.
- [ ] **Discord Webhooks:** Rich embeds com código de cores por severidade, país atacante, técnicas MITRE ATT&CK e link para o incidente.
- [ ] **Telegram Bot:** Alertas imediatos no telemóvel com opções de comando rápido (ex: `/status`, `/mitigate <ip>`).
- [ ] Integração com o motor de desduplicação (`dedup.rs`) para prevenir fadiga de alertas (*alert fatigue*).

### 2. 📑 Gerador de Relatórios Forenses e Auditoria Executiva
- [ ] Exportação em formato Markdown estruturado e HTML autónomo com estilo CSS moderno embutido.
- [ ] Sumário executivo: total de incidentes, taxa de mitigação e classificação de severidade.
- [ ] Mapeamento dinâmico da matriz MITRE ATT&CK observada no período.
- [ ] Tabela dos Top Threat Actors (IP, ASN, País, Histórico de Ataques).
- [ ] Lista de recomendações automáticas de mitigação prontas para entrega em ambiente académico (CRSI/ESTG) ou profissional de SOC.

### 3. 🌐 Visualização e UX Avançada
- [ ] Filtro temporal interativo na Timeline (última 1h, 24h, 7 dias).
- [ ] Gravação e exportação do histórico de ataques em formato STIX 2.1 com um clique.

---

*Registo mantido por Salvador Teixeira Pontes (`teizinh`) — CTeSP CRSI, ESTG P.PORTO.*
