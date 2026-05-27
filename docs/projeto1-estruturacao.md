# Projeto 1 — CIC0124 Redes de Computadores
## Plataforma IDS/SIEM Simplificada — Documento de Estruturação e Requisitos

---

## 1. Visão Geral do Projeto

### 1.1 Nome
**NetWatch** — Plataforma Inteligente de Monitoramento e Detecção de Segurança em Rede

### 1.2 Descrição
Sistema cliente-servidor distribuído que simula um IDS/SIEM simplificado. Um sensor Python (cliente) coleta métricas da máquina host e detecta comportamentos anômalos, transmitindo dados via UDP (telemetria rotineira) e TCP (alertas críticos) para um servidor Flask que armazena tudo em SQLite e expõe um painel web em tempo real para o operador de segurança.

### 1.3 Objetivos Pedagógicos Atendidos

| Objetivo do projeto | Como é atendido |
|---|---|
| Sockets cliente-servidor | Sensor (cliente) + Servidor Flask com sockets TCP e UDP |
| Protocolo de aplicação próprio | Protocolo JSON documentado (seção 5) |
| HTTP | API REST do Flask serve o painel web |
| Comparar TCP e UDP | Canal de alertas (TCP) vs. canal de telemetria (UDP) |
| Medir RTT e throughput | Timestamps em cada payload; cálculo fim-a-fim no servidor |
| Escalabilidade e desempenho | Múltiplos clientes conectados; medição de pacotes perdidos no UDP |
| Conceitos caps. 1 e 2 | Encapsulamento, multiplexação, handshake, analisado no Wireshark |

---

## 2. Stack Tecnológica

### 2.1 Linguagens e Frameworks

| Camada | Tecnologia | Justificativa |
|---|---|---|
| Sensor/Cliente | Python 3.11+ | Biblioteca `psutil` para métricas de sistema; `socket` nativo para TCP/UDP |
| Servidor | Python 3.11+ + Flask | Leve, simples de configurar, suporte nativo a rotas HTTP |
| Banco de dados | SQLite 3 | Zero configuração, integrado ao Python via `sqlite3`, persistência local |
| Front-end | HTML5 + CSS3 + JavaScript puro | Sem dependências externas; polling via `fetch()` nativo |
| Análise de rede | Wireshark | Captura e análise forense do tráfego na interface loopback |

### 2.2 Bibliotecas Python necessárias

```
flask          # servidor web e API HTTP
psutil         # coleta de métricas do sistema (CPU, RAM, conexões, processos)
hashlib        # cálculo de hash SHA-256 de arquivos críticos (já inclusa no Python)
socket         # sockets TCP e UDP (já inclusa no Python)
threading      # threads para escutar TCP e UDP simultaneamente
sqlite3        # banco de dados (já inclusa no Python)
json           # serialização do protocolo (já inclusa no Python)
time           # timestamps e RTT (já inclusa no Python)
```

> **Instalação**: `pip install flask psutil`
> Todas as demais são da biblioteca padrão do Python.

### 2.3 Ferramentas de Desenvolvimento

| Ferramenta | Uso |
|---|---|
| VS Code | Editor principal |
| Git + GitHub | Controle de versão e entrega do link do código-fonte |
| Wireshark | Análise do protocolo e captura de tráfego |
| Postman (opcional) | Testar manualmente os endpoints da API HTTP |
| Python venv | Isolamento do ambiente de dependências |

---

## 3. Arquitetura do Sistema

### 3.1 Componentes Principais

```
┌─────────────────────────────────────────────────────────────────┐
│                    SENSOR DE SEGURANÇA (Cliente)                │
│  sensor.py                                                      │
│  • Coleta métricas via psutil                                   │
│  • Simula ataques (brute force, port scan)                      │
│  • Envia telemetria via UDP (porta 9999)                        │
│  • Envia alertas críticos via TCP (porta 9998)                  │
└──────────────────────┬──────────────────┬───────────────────────┘
                       │ UDP              │ TCP
                       ▼                  ▼
┌─────────────────────────────────────────────────────────────────┐
│               SERVIDOR DE APLICAÇÃO (Cérebro/SIEM)             │
│  server.py                                                      │
│  • Thread UDP: recebe telemetria, calcula perda de pacotes      │
│  • Thread TCP: recebe alertas, verifica limiares de segurança   │
│  • Persiste todos os eventos no SQLite                          │
│  • Calcula RTT fim-a-fim                                        │
│  • Flask: serve API HTTP e painel web                           │
└──────────────────────┬──────────────────────────────────────────┘
                       │ HTTP (porta 5000)
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PAINEL WEB (Dashboard SOC)                    │
│  templates/dashboard.html                                       │
│  • Polling HTTP GET a cada 2s                                   │
│  • Tabela de eventos em tempo real                              │
│  • Contadores por severidade                                    │
│  • Alertas visuais para eventos críticos                        │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Portas Utilizadas

| Porta | Protocolo | Função |
|---|---|---|
| 9999 | UDP | Canal de telemetria (métricas rotineiras) |
| 9998 | TCP | Canal de alertas críticos |
| 5000 | TCP/HTTP | API Flask + painel web |

### 3.3 Fluxo de Dados

1. **Sensor** coleta métricas a cada N segundos via `psutil`
2. Métricas normais → serializa em JSON → envia via **UDP** para porta 9999
3. Anomalia detectada → serializa em JSON → envia via **TCP** para porta 9998
4. **Servidor UDP** recebe, valida, calcula RTT, persiste no SQLite
5. **Servidor TCP** recebe, valida, aplica regras de segurança, persiste no SQLite
6. **Flask** expõe `/api/events` e `/api/metrics`
7. **Painel web** faz GET a cada 2 segundos e atualiza a tabela de incidentes

---

## 4. Estrutura de Pastas do Projeto

```
netwatch/
│
├── README.md                  # Documentação geral + como executar
├── requirements.txt           # Dependências Python
│
├── sensor/
│   ├── sensor.py              # Cliente principal
│   ├── collector.py           # Funções de coleta psutil
│   └── simulator.py           # Simulação de ataques
│
├── server/
│   ├── server.py              # Servidor principal (threads UDP + TCP + Flask)
│   ├── udp_handler.py         # Lógica do listener UDP
│   ├── tcp_handler.py         # Lógica do listener TCP
│   ├── database.py            # Operações SQLite
│   ├── rules_engine.py        # Motor de regras de segurança
│   └── api.py                 # Rotas Flask (HTTP)
│
├── web/
│   ├── templates/
│   │   └── dashboard.html     # Painel HTML principal
│   └── static/
│       ├── style.css
│       └── dashboard.js       # Polling e atualização da UI
│
├── docs/
│   ├── protocolo.md           # Especificação do protocolo JSON
│   └── wireshark/             # Screenshots e análises do Wireshark
│
└── database/
    └── netwatch.db            # SQLite (gerado em runtime)
```

---

## 5. Especificação do Protocolo de Aplicação

### 5.1 Visão Geral

O protocolo **NetWatch Application Protocol (NAP)** é baseado em mensagens JSON codificadas em UTF-8, trafegando sobre TCP ou UDP. Cada mensagem possui um campo `type` que define sua estrutura.

**Versão**: 1.0  
**Encoding**: UTF-8  
**Formato**: JSON  
**Transporte**: TCP (alertas) ou UDP (telemetria)

### 5.2 Cabeçalho Comum (presente em todas as mensagens)

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "<tipo_da_mensagem>",
  "sensor_id": "<uuid_do_sensor>",
  "timestamp": 1716000000.123,
  "seq_number": 42
}
```

| Campo | Tipo | Descrição |
|---|---|---|
| `protocol` | string | Identificador fixo "NAP" |
| `version` | string | Versão do protocolo |
| `type` | string | Tipo de mensagem (ver seção 5.3) |
| `sensor_id` | string | UUID único do sensor |
| `timestamp` | float | Unix timestamp com milissegundos |
| `seq_number` | int | Número de sequência (para detectar perda UDP) |

### 5.3 Tipos de Mensagem

#### TELEMETRY (UDP) — Métricas rotineiras

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "TELEMETRY",
  "sensor_id": "abc123",
  "timestamp": 1716000000.123,
  "seq_number": 42,
  "payload": {
    "cpu_percent": 34.5,
    "ram_percent": 61.2,
    "active_connections": 18,
    "open_ports": [22, 80, 443],
    "file_hashes": {
      "/etc/passwd": "a1b2c3d4...",
      "/etc/hosts": "e5f6g7h8..."
    }
  }
}
```

#### ALERT (TCP) — Evento de segurança

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "ALERT",
  "sensor_id": "abc123",
  "timestamp": 1716000001.456,
  "seq_number": 5,
  "payload": {
    "severity": "HIGH",
    "category": "BRUTE_FORCE",
    "description": "15 tentativas de login em 10 segundos",
    "count": 15,
    "window_seconds": 10,
    "source_ip": "127.0.0.1"
  }
}
```

**Categorias de alerta**: `BRUTE_FORCE`, `PORT_SCAN`, `FILE_INTEGRITY`, `CONNECTION_FLOOD`  
**Severidades**: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

#### ACK (TCP) — Confirmação do servidor

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "ACK",
  "sensor_id": "abc123",
  "timestamp_received": 1716000001.456,
  "timestamp_ack": 1716000001.461,
  "rtt_ms": 5.1,
  "status": "OK"
}
```

#### HEARTBEAT (UDP) — Keepalive periódico

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "HEARTBEAT",
  "sensor_id": "abc123",
  "timestamp": 1716000005.000,
  "seq_number": 100
}
```

---

## 6. Esquema do Banco de Dados (SQLite)

### Tabela: `events`

```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id   TEXT NOT NULL,
    type        TEXT NOT NULL,          -- TELEMETRY, ALERT, HEARTBEAT
    category    TEXT,                   -- BRUTE_FORCE, PORT_SCAN, etc.
    severity    TEXT,                   -- LOW, MEDIUM, HIGH, CRITICAL
    description TEXT,
    raw_payload TEXT NOT NULL,          -- JSON completo para auditoria
    timestamp   REAL NOT NULL,
    rtt_ms      REAL,
    received_at REAL NOT NULL
);
```

### Tabela: `sensors`

```sql
CREATE TABLE sensors (
    sensor_id   TEXT PRIMARY KEY,
    first_seen  REAL NOT NULL,
    last_seen   REAL NOT NULL,
    ip_address  TEXT,
    status      TEXT DEFAULT 'ACTIVE'   -- ACTIVE, OFFLINE
);
```

### Tabela: `metrics`

```sql
CREATE TABLE metrics (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    sensor_id           TEXT NOT NULL,
    timestamp           REAL NOT NULL,
    cpu_percent         REAL,
    ram_percent         REAL,
    active_connections  INTEGER,
    seq_number          INTEGER,
    udp_loss_percent    REAL
);
```

---

## 7. Endpoints da API HTTP (Flask)

| Método | Rota | Descrição |
|---|---|---|
| GET | `/` | Serve o dashboard HTML |
| GET | `/api/events` | Lista os últimos N eventos (padrão: 50) |
| GET | `/api/events?severity=HIGH` | Filtra por severidade |
| GET | `/api/metrics` | Últimas métricas de telemetria |
| GET | `/api/stats` | Contadores gerais (total de alertas por categoria) |
| GET | `/api/sensors` | Lista de sensores registrados |
| POST | `/api/auth/login` | Autenticação do operador (requisito do projeto) |

---

## 8. Requisitos Funcionais

| ID | Requisito | Prioridade |
|---|---|---|
| RF01 | Sensor coleta CPU, RAM e conexões ativas a cada 5s | Alta |
| RF02 | Sensor calcula hash SHA-256 de arquivos críticos | Alta |
| RF03 | Sensor simula tentativas de login excessivas (brute force) | Alta |
| RF04 | Sensor simula varredura de portas (port scan) | Alta |
| RF05 | Sensor envia telemetria via UDP | Alta |
| RF06 | Sensor envia alertas via TCP | Alta |
| RF07 | Servidor recebe e valida payloads JSON | Alta |
| RF08 | Servidor aplica regras de limiar (ex: > 10 logins/10s = ALERTA) | Alta |
| RF09 | Servidor persiste todos os eventos no SQLite | Alta |
| RF10 | Servidor calcula e registra RTT de cada mensagem | Alta |
| RF11 | Servidor detecta e registra perda de pacotes UDP | Alta |
| RF12 | Painel web exibe eventos em tempo real via polling HTTP | Alta |
| RF13 | Painel web exibe alertas visuais para severidade CRITICAL | Alta |
| RF14 | Sistema possui autenticação básica para o painel web | Média |
| RF15 | Painel exibe gráfico de RTT ao longo do tempo | Média |

---

## 9. Requisitos Não-Funcionais

| ID | Requisito |
|---|---|
| RNF01 | Protocolo totalmente documentado em JSON com campos obrigatórios |
| RNF02 | Servidor deve suportar ao menos 3 sensores simultâneos |
| RNF03 | Painel web atualiza em no máximo 3 segundos |
| RNF04 | Código organizado com separação clara de responsabilidades |
| RNF05 | Repositório no GitHub com README descrevendo como executar |
| RNF06 | Vídeo de demonstração de até 10 minutos |
| RNF07 | Capturas do Wireshark documentadas na pasta `/docs/wireshark` |

---

## 10. Análise com Wireshark — Roteiro

### O que capturar e documentar

| Item obrigatório | O que fazer no Wireshark |
|---|---|
| Protocolo de aplicação | Filtro `udp.port == 9999` e `tcp.port == 9998`; ver payload JSON |
| Handshake TCP | Filtro `tcp.port == 9998`; identificar SYN, SYN-ACK, ACK |
| Pacotes UDP | Filtro `udp.port == 9999`; ver ausência de handshake |
| RTT | Analisar delta de tempo entre pacote enviado e ACK recebido |
| Tamanho dos pacotes | Coluna "Length" no Wireshark |
| Encapsulamento | Expandir camadas: Frame > Ethernet > IP > TCP/UDP > Dados |
| Perda UDP | Enviar rajada de pacotes e verificar `seq_number` gaps |
| Comparação TCP x UDP | Capturar os dois canais e mostrar diferença de comportamento |

### Filtros Wireshark úteis

```
# Ver apenas tráfego do NetWatch
tcp.port == 9998 || udp.port == 9999 || tcp.port == 5000

# Ver handshake TCP
tcp.port == 9998 && tcp.flags.syn == 1

# Ver apenas alertas (TCP)
tcp.port == 9998

# Ver apenas telemetria (UDP)
udp.port == 9999
```

---

## 11. Plano de Implementação (Fases)

### Fase 1 — Fundação (Dia 1-2)
- [ ] Criar estrutura de pastas e repositório Git
- [ ] Configurar `requirements.txt` e `venv`
- [ ] Implementar `database.py` com criação das tabelas SQLite
- [ ] Testar conexão básica TCP e UDP entre sensor e servidor

### Fase 2 — Sensor (Dia 2-3)
- [ ] Implementar `collector.py` com psutil (CPU, RAM, conexões)
- [ ] Implementar cálculo de hash SHA-256 em `collector.py`
- [ ] Implementar `simulator.py` (brute force e port scan)
- [ ] Implementar envio UDP de telemetria com `seq_number`
- [ ] Implementar envio TCP de alertas

### Fase 3 — Servidor (Dia 3-4)
- [ ] Implementar thread UDP listener com detecção de perda de pacotes
- [ ] Implementar thread TCP listener com cálculo de RTT e envio de ACK
- [ ] Implementar `rules_engine.py` com limiares de segurança
- [ ] Integrar persistência no SQLite

### Fase 4 — API e Painel Web (Dia 4-5)
- [ ] Implementar rotas Flask (`/api/events`, `/api/metrics`, `/api/stats`)
- [ ] Implementar autenticação básica (`/api/auth/login`)
- [ ] Desenvolver `dashboard.html` com polling a cada 2 segundos
- [ ] Adicionar alertas visuais para eventos CRITICAL

### Fase 5 — Testes e Wireshark (Dia 5-6)
- [ ] Executar sistema completo e capturar tráfego no Wireshark
- [ ] Documentar handshake TCP, pacotes UDP, RTT e encapsulamento
- [ ] Tirar screenshots e salvar em `/docs/wireshark`
- [ ] Testar com múltiplos sensores simultâneos

### Fase 6 — Documentação e Vídeo (Dia 6-7)
- [ ] Finalizar `README.md` com instruções de execução
- [ ] Finalizar `docs/protocolo.md`
- [ ] Gravar vídeo de demonstração (máx. 10 min)
- [ ] Redigir relatório conforme formato da disciplina

---

## 12. Como Executar (Rascunho do README)

```bash
# 1. Clonar o repositório
git clone https://github.com/seu-usuario/netwatch.git
cd netwatch

# 2. Criar ambiente virtual e instalar dependências
python -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
pip install -r requirements.txt

# 3. Iniciar o servidor (em um terminal)
cd server
python server.py

# 4. Iniciar o sensor (em outro terminal)
cd sensor
python sensor.py

# 5. Abrir o painel web
# Acessar http://localhost:5000 no navegador
```
