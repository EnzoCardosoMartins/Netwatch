# NetWatch SIEM — Plataforma de Monitoramento e Detecção em Rede

> **CIC0124 — Redes de Computadores · UnB**
> Projeto 1 · Entrega: 27/05/2026 · Grupos de 3 alunos

---

## Sumário

1. [Visão Geral](#1-visão-geral)
2. [Arquitetura do Sistema](#2-arquitetura-do-sistema)
3. [Estrutura de Pastas](#3-estrutura-de-pastas)
4. [Pré-requisitos e Instalação](#4-pré-requisitos-e-instalação)
5. [Como Executar](#5-como-executar)
6. [Protocolo de Aplicação (NAP/1.0)](#6-protocolo-de-aplicação-nap10)
7. [Endpoints da API HTTP](#7-endpoints-da-api-http)
8. [Banco de Dados](#8-banco-de-dados)
9. [Análise de Conformidade com os Requisitos do Projeto](#9-análise-de-conformidade-com-os-requisitos-do-projeto)
10. [Bugs Conhecidos e Pendências Críticas](#10-bugs-conhecidos-e-pendências-críticas)
11. [Próximas Etapas para o Grupo](#11-próximas-etapas-para-o-grupo)
12. [Roteiro de Análise no Wireshark](#12-roteiro-de-análise-no-wireshark)
13. [Credenciais Padrão](#13-credenciais-padrão)

---

## 1. Visão Geral

O **NetWatch** é uma plataforma cliente-servidor distribuída que simula um sistema IDS/SIEM (Intrusion Detection System / Security Information and Event Management) simplificado. O sistema foi desenvolvido como projeto prático da disciplina CIC0124 para demonstrar, de forma aplicada, os conceitos fundamentais de redes de computadores estudados nos capítulos 1 e 2 do livro-texto.

### O que o sistema faz

Um sensor Python autônomo coleta métricas do sistema operacional host (CPU, RAM, conexões de rede) e monitora a integridade de arquivos críticos via hash SHA-256. Quando detecta comportamento anômalo, dispara alertas de segurança estruturados. Toda a comunicação com o servidor central é feita através de um **protocolo de aplicação customizado (NAP — NetWatch Application Protocol)** baseado em JSON, bifurcado em dois canais com características distintas:

- **Canal UDP (porta 9999):** transmissão de telemetria rotineira — sem garantia de entrega, permitindo medir perda de pacotes e throughput.
- **Canal TCP (porta 9998):** transmissão de alertas críticos — com garantia de entrega via handshake de três vias, retransmissão automática e confirmação ACK com medição de RTT.

O servidor recebe, valida, aplica regras de segurança, persiste tudo em SQLite e expõe uma API HTTP via Flask. O painel web consome essa API via polling a cada 2 segundos e exibe o estado de segurança em tempo real.

### Conceitos de Redes Demonstrados

| Conceito | Onde é demonstrado |
|---|---|
| Arquitetura cliente-servidor | `sensor.py` ↔ `server.py` |
| Sockets TCP e UDP | `server.py` (listener) e `sensor.py` (emissor) |
| Protocolo de aplicação customizado | Protocolo NAP/1.0 (ver seção 6) |
| HTTP e comunicação Web | API Flask em `api.py` + `dashboard.html` |
| Comparação TCP vs. UDP | Canal de alertas (TCP) vs. telemetria (UDP) |
| Medição de RTT fim-a-fim | Calculado no servidor, exibido no painel |
| Throughput e perda de pacotes UDP | Calculados no painel via `seq_number` |
| Encapsulamento de camadas | Visível no Wireshark: App → TCP/UDP → IP → Enlace |
| Multiplexação por portas | Três portas lógicas distintas (9999, 9998, 5000) |
| Persistência e logs de auditoria | SQLite com modo WAL para acesso concorrente |

---

## 2. Arquitetura do Sistema

```
┌──────────────────────────────────────────────────────────────────┐
│                   SENSOR DE SEGURANÇA                            │
│  sensor/sensor.py  +  sensor/collector.py                        │
│                                                                  │
│  • psutil coleta CPU, RAM e conexões ativas a cada 5s            │
│  • SHA-256 monitora integridade do arquivo collector.py          │
│  • Monta payload JSON no formato NAP/1.0                         │
└────────────────┬──────────────────────┬─────────────────────────┘
                 │                      │
     UDP :9999   │  telemetria rotineira │  alertas críticos
     (sem ACK)   │                      │  TCP :9998 (com ACK + RTT)
                 ▼                      ▼
┌──────────────────────────────────────────────────────────────────┐
│                  SERVIDOR DE APLICAÇÃO                           │
│                                                                  │
│   server/server.py                                               │
│   ┌─────────────────────┐  ┌──────────────────────────────────┐  │
│   │  Thread UDP Listener │  │    Thread TCP Listener           │  │
│   │  porta 9999          │  │    porta 9998                    │  │
│   │  recebe telemetria   │  │    recebe alertas                │  │
│   │  salva em metrics    │  │    calcula RTT                   │  │
│   └──────────┬──────────┘  │    envia ACK de volta            │  │
│              │              │    salva em events               │  │
│              └──────────────┴──────────────┬─────────────────  │  │
│                                            │                    │
│                                       SQLite (WAL)              │
│                                       database/netwatch.db      │
└──────────────────────────────────────────────────────────────────┘
                                            │
                                     lê do banco
                                            │
┌──────────────────────────────────────────────────────────────────┐
│                    API HTTP (Flask)                               │
│  server/api.py · porta 5000                                      │
│                                                                  │
│  GET  /                      → serve dashboard.html              │
│  GET  /api/status            → health check                      │
│  GET  /api/metrics           → últimas 50 telemetrias            │
│  GET  /api/events            → últimos 50 alertas                │
│  GET  /api/stats             → contadores por severidade         │
│  POST /api/auth/login        → autenticação do operador          │
│  POST /api/auth/register     → cadastro de novo operador         │
└──────────────────────────────────────────────────────────────────┘
                                            │
                                   HTTP polling 2s
                                            │
┌──────────────────────────────────────────────────────────────────┐
│                   PAINEL WEB (Dashboard SOC)                     │
│  web/templates/dashboard.html                                    │
│                                                                  │
│  • Modal de login com autenticação real via API                  │
│  • Gráficos de CPU, RAM e Conexões em tempo real (Canvas)        │
│  • Tabela de Log de Incidentes com RTT por alerta                │
│  • Contadores de severidade (CRITICAL / HIGH / MEDIUM / LOW)     │
│  • Banner de alerta visual para eventos CRITICAL                 │
│  • Métricas UDP: perda de pacotes e throughput estimado          │
└──────────────────────────────────────────────────────────────────┘
```

### Portas e Protocolos

| Porta | Protocolo | Processo | Função |
|---|---|---|---|
| **9999** | UDP | `server.py` | Recebe telemetria do sensor |
| **9998** | TCP | `server.py` | Recebe alertas críticos; envia ACK |
| **5000** | TCP / HTTP | `api.py` | API REST + painel web |

> **Importante:** `server.py` e `api.py` são **dois processos separados** que compartilham o mesmo banco SQLite. O modo WAL (Write-Ahead Log) do SQLite garante acesso concorrente seguro entre eles.

---

## 3. Estrutura de Pastas

```
netwatch/
│
├── README.md                        # Este arquivo
├── requirements.txt                 # Dependências Python
│
├── sensor/
│   ├── sensor.py                    # Processo cliente principal
│   └── collector.py                 # Coleta de métricas via psutil + SHA-256
│
├── server/
│   ├── server.py                    # Processo servidor (threads UDP + TCP)
│   └── api.py                       # Processo API Flask (HTTP)
│
├── database/
│   ├── database.py                  # Conexão SQLite + criação do schema
│   └── netwatch.db                  # Banco de dados (gerado em runtime)
│
├── web/
│   └── templates/
│       └── dashboard.html           # Painel web completo (HTML + CSS + JS)
│
└── docs/
    ├── protocolo.md                 # [A CRIAR] Especificação formal do protocolo NAP
    └── wireshark/                   # [A CRIAR] Screenshots e análises do Wireshark
```

---

## 4. Pré-requisitos e Instalação

### Requisitos do Sistema

- Python **3.11** ou superior
- pip
- Wireshark (para a etapa de análise de tráfego)
- Sistema operacional: Windows 10+, Ubuntu 20.04+ ou macOS 12+

### Instalação Passo a Passo

**1. Clone o repositório**

```bash
git clone https://github.com/SEU-USUARIO/netwatch.git
cd netwatch
```

**2. Crie e ative o ambiente virtual**

```bash
# Linux / macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1

# Windows (CMD)
venv\Scripts\activate.bat
```

**3. Instale as dependências**

```bash
pip install -r requirements.txt
```

Conteúdo do `requirements.txt`:

```
flask==3.0.3
flask-cors==4.0.1
psutil==5.9.8
werkzeug==3.0.3
```

> Todas as outras bibliotecas usadas (`socket`, `threading`, `sqlite3`, `json`, `hashlib`, `time`, `uuid`, `os`, `sys`) fazem parte da **biblioteca padrão do Python** e não precisam de instalação.

**4. Inicialize o banco de dados**

```bash
python database/database.py
```

Você deve ver a mensagem:
```
[*] Base de dados SQLite inicializada com sucesso em modo WAL.
```

Isso cria o arquivo `database/netwatch.db` com as tabelas `events`, `metrics`, `sensors` e `users`, além do usuário padrão `admin`.

---

## 5. Como Executar

O sistema possui **três processos independentes** que precisam rodar em terminais separados. Siga a ordem abaixo.

### Terminal 1 — Servidor de Sockets (UDP + TCP)

```bash
cd netwatch/
python server/server.py
```

Saída esperada:
```
[*] Thread TCP ativa na porta 9998
[*] Thread UDP ativa na porta 9999
[Servidor Rodando] Pressione Ctrl+C para encerrar.
```

### Terminal 2 — API HTTP (Flask)

```bash
cd netwatch/
python server/api.py
```

Saída esperada:
```
[*] Iniciando o servidor da API HTTP...
 * Running on http://127.0.0.1:5000
```

### Terminal 3 — Sensor (Cliente)

```bash
cd netwatch/sensor/
python sensor.py
```

Saída esperada:
```
[*] Configurando o Sensor NetWatch...
[+] Coletando e enviando dados...
```

### Acessar o Painel Web

Abra o navegador e acesse:

```
http://127.0.0.1:5000
```

Será exibido o modal de autenticação. Use as credenciais padrão:

- **Usuário:** `admin`
- **Senha:** `admin123`

### Forçar um Alerta Manualmente

Para testar o fluxo TCP de alertas, basta editar e salvar qualquer coisa no arquivo `sensor/collector.py` enquanto o sensor está rodando. O sensor detectará a mudança de hash SHA-256 e disparará um alerta `FILE_INTEGRITY` com severidade `CRITICAL` via TCP.

---

## 6. Protocolo de Aplicação (NAP/1.0)

### Visão Geral

O **NetWatch Application Protocol (NAP)** é um protocolo de aplicação proprietário baseado em mensagens **JSON codificadas em UTF-8**, trafegando sobre **TCP ou UDP** dependendo da criticidade do evento. Ele opera na **camada de Aplicação** do modelo Internet, sendo encapsulado pelas camadas inferiores (Transporte → Rede → Enlace) a cada transmissão.

```
┌────────────────────────────────────┐
│  Camada de Aplicação: NAP/1.0      │  ← Nosso protocolo
├────────────────────────────────────┤
│  Camada de Transporte: TCP ou UDP  │  ← Porta 9999 (UDP) / 9998 (TCP)
├────────────────────────────────────┤
│  Camada de Rede: IP (IPv4)         │  ← Endereço 127.0.0.1
├────────────────────────────────────┤
│  Camada de Enlace: Loopback (lo)   │  ← Interface local
└────────────────────────────────────┘
```

### Cabeçalho Comum

Todo pacote NAP contém estes campos obrigatórios:

| Campo | Tipo | Descrição |
|---|---|---|
| `protocol` | `string` | Sempre `"NAP"` — identificador do protocolo |
| `version` | `string` | Sempre `"1.0"` — versão atual |
| `type` | `string` | Tipo da mensagem: `TELEMETRY`, `ALERT`, `ACK`, `HEARTBEAT` |
| `sensor_id` | `string` | UUID truncado de 8 chars que identifica unicamente o sensor |
| `timestamp` | `float` | Unix timestamp com milissegundos (ex: `1716000000.123`) |
| `seq_number` | `int` | Número de sequência incremental; usado para detectar perda de pacotes no canal UDP |

### Tipo `TELEMETRY` — Enviado via UDP

Transmitido a cada 5 segundos com métricas rotineiras do sistema. Por usar UDP, pode ser perdido sem retransmissão.

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "TELEMETRY",
  "sensor_id": "a1b2c3d4",
  "timestamp": 1716000000.123,
  "seq_number": 42,
  "payload": {
    "cpu_percent": 34.5,
    "ram_percent": 61.2,
    "active_connections": 18,
    "open_ports": [22, 80, 443, 5000, 9998, 9999],
    "file_hashes": {
      "collector.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }
  }
}
```

### Tipo `ALERT` — Enviado via TCP

Disparado imediatamente quando uma anomalia de segurança é detectada. O TCP garante entrega ordenada e confiável.

```json
{
  "protocol": "NAP",
  "version": "1.0",
  "type": "ALERT",
  "sensor_id": "a1b2c3d4",
  "timestamp": 1716000001.456,
  "seq_number": 5,
  "payload": {
    "severity": "CRITICAL",
    "category": "FILE_INTEGRITY",
    "description": "O arquivo collector.py foi modificado de abc123... para def456..."
  }
}
```

**Categorias implementadas:**

| Categoria | Severidade | Trigger |
|---|---|---|
| `FILE_INTEGRITY` | `CRITICAL` | Hash SHA-256 do `collector.py` mudou |

**Categorias planejadas (não implementadas):**

| Categoria | Severidade | Trigger |
|---|---|---|
| `BRUTE_FORCE` | `HIGH` | Mais de N tentativas de login em T segundos |
| `PORT_SCAN` | `MEDIUM` | Varredura de múltiplas portas em sequência |
| `CONNECTION_FLOOD` | `HIGH` | Número excessivo de conexões ativas |

**Severidades disponíveis:** `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

### Tipo `ACK` — Enviado pelo servidor via TCP

Resposta de confirmação enviada pelo servidor após receber um `ALERT`. Contém o RTT calculado.

```json
{
  "protocolo": "NAP",
  "version": "1.0",
  "type": "ACK",
  "status": "SUCESS",
  "rtt_ms": 0.87,
  "timestamp": 1716000001.461
}
```

> **Nota sobre o RTT:** O valor `rtt_ms` representa o tempo entre o `timestamp` de envio no sensor e o momento de recebimento no servidor. Em ambiente loopback, valores típicos ficam entre 0,1ms e 5ms.

### Decisão TCP vs. UDP — Justificativa de Projeto

| Critério | UDP (Telemetria) | TCP (Alertas) |
|---|---|---|
| **Garantia de entrega** | Não | Sim (retransmissão automática) |
| **Ordem dos pacotes** | Não garantida | Garantida |
| **Handshake** | Não | Sim (SYN → SYN-ACK → ACK) |
| **Overhead** | Baixo | Maior |
| **Uso adequado** | Métricas periódicas que toleram perda | Eventos críticos que não podem ser perdidos |
| **O que perdemos** | Telemetria de alguns ciclos — aceitável | Nenhum alerta — inaceitável perder |

---

## 7. Endpoints da API HTTP

Base URL: `http://127.0.0.1:5000`

### `GET /`
Serve o painel web completo (`dashboard.html`).

**Resposta:** HTML completo da interface de monitoramento.

---

### `GET /api/status`
Health check — valida se a API está respondendo.

**Resposta 200:**
```json
{
  "status": "online",
  "projeto": "NetWatch SIEM",
  "mensagem": "API Flask operando com sucesso!",
  "protocolo": "NAP/1.0",
  "portas": {
    "udp_telemetry": 9999,
    "tcp_alerts": 9998,
    "http_api": 5000
  }
}
```

---

### `GET /api/metrics`
Retorna as últimas 50 entradas de telemetria UDP, ordenadas da mais recente para a mais antiga.

**Resposta 200:** Array de objetos com os campos da tabela `metrics`:
```json
[
  {
    "id": 145,
    "sensor_id": "a1b2c3d4",
    "timestamp": 1716000100.0,
    "cpu_percent": 34.5,
    "ram_percent": 61.2,
    "active_connections": 18,
    "seq_number": 42,
    "udp_loss_percent": null
  }
]
```

---

### `GET /api/events`
Retorna os últimos 50 alertas de segurança (apenas registros do tipo `ALERT`), do mais recente para o mais antigo.

**Resposta 200:** Array de objetos com os campos da tabela `events`:
```json
[
  {
    "id": 3,
    "sensor_id": "a1b2c3d4",
    "type": "ALERT",
    "category": "FILE_INTEGRITY",
    "severity": "CRITICAL",
    "description": "O arquivo collector.py foi modificado...",
    "raw_payload": "{...json completo...}",
    "timestamp": 1716000001.456,
    "rtt_ms": 0.87,
    "received_at": 1716000001.457
  }
]
```

---

### `GET /api/stats`
Retorna contadores agregados por severidade e categoria, além de totais gerais.

**Resposta 200:**
```json
{
  "total_alertas": 5,
  "total_metricas": 234,
  "total_sensores": 1,
  "por_severidade": {
    "CRITICAL": 3,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0
  },
  "por_categoria": {
    "FILE_INTEGRITY": 4,
    "BRUTE_FORCE": 1
  }
}
```

---

### `POST /api/auth/login`
Autentica o operador do SOC. Requerido antes de acessar o painel.

**Corpo da requisição:**
```json
{ "username": "admin", "password": "admin123" }
```

**Resposta 200 (sucesso):**
```json
{ "status": "success", "message": "Autenticado com sucesso!" }
```

**Resposta 401 (falha):**
```json
{ "status": "error", "message": "Usuário ou senha incorretos." }
```

---

### `POST /api/auth/register`
Cadastra um novo operador.

**Corpo da requisição:**
```json
{ "username": "novo_operador", "password": "senha_segura" }
```

**Resposta 201:** `{ "status": "success", "message": "Operador cadastrado com sucesso!" }`

**Resposta 400:** `{ "status": "error", "message": "Este usuário já está cadastrado." }`

---

## 8. Banco de Dados

O banco de dados é um arquivo SQLite único localizado em `database/netwatch.db`. O modo **WAL (Write-Ahead Log)** é habilitado para permitir que `server.py` e `api.py` acessem o banco simultaneamente sem bloqueios.

### Tabela: `events`

Armazena todos os alertas de segurança recebidos via TCP, com o payload completo para auditoria.

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INTEGER PK | Identificador autoincrementado |
| `sensor_id` | TEXT | UUID do sensor de origem |
| `type` | TEXT | Tipo da mensagem (sempre `ALERT` nesta tabela) |
| `category` | TEXT | Categoria: `FILE_INTEGRITY`, `BRUTE_FORCE`, etc. |
| `severity` | TEXT | Nível: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `description` | TEXT | Descrição legível do evento |
| `raw_payload` | TEXT | JSON completo original para auditoria forense |
| `timestamp` | REAL | Unix timestamp de envio pelo sensor |
| `rtt_ms` | REAL | RTT calculado pelo servidor em milissegundos |
| `received_at` | REAL | Unix timestamp de recebimento pelo servidor |

### Tabela: `metrics`

Série temporal de métricas de hardware/rede coletadas via UDP.

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INTEGER PK | Identificador autoincrementado |
| `sensor_id` | TEXT | UUID do sensor de origem |
| `timestamp` | REAL | Unix timestamp da coleta |
| `cpu_percent` | REAL | Uso de CPU em % |
| `ram_percent` | REAL | Uso de RAM em % |
| `active_connections` | INTEGER | Total de conexões ativas no host |
| `seq_number` | INTEGER | Número de sequência do pacote UDP (para cálculo de perda) |
| `udp_loss_percent` | REAL | (Reservado — cálculo de perda feito no front-end) |

### Tabela: `users`

Operadores autorizados a acessar o painel.

| Coluna | Tipo | Descrição |
|---|---|---|
| `id` | INTEGER PK | Identificador autoincrementado |
| `username` | TEXT UNIQUE | Nome de usuário |
| `password_hash` | TEXT | Hash bcrypt da senha (gerado pelo Werkzeug) |

### Tabela: `sensors`

Inventário de sensores. **Nota:** esta tabela é criada pelo `database.py` mas ainda não é preenchida automaticamente pelo `server.py` — é uma pendência de implementação.

| Coluna | Tipo | Descrição |
|---|---|---|
| `sensor_id` | TEXT PK | UUID do sensor |
| `first_seen` | REAL | Timestamp do primeiro contato |
| `last_seen` | REAL | Timestamp do último contato |
| `ip_address` | TEXT | Endereço IP do sensor |
| `status` | TEXT | `ACTIVE` ou `OFFLINE` |

---

## 9. Análise de Conformidade com os Requisitos do Projeto

### Funcionalidades Mínimas Obrigatórias (PDF)

| # | Requisito | Status | Implementado em |
|---|---|---|---|
| 1 | Cliente com interface gráfica | ✅ Completo | `dashboard.html` — modal de login, gráficos Canvas, tabela de eventos |
| 2 | Servidor funcional | ✅ Completo | `server.py` + `api.py` |
| 3 | Comunicação HTTP | ✅ Completo | API Flask com 7 endpoints documentados |
| 4 | Comunicação em tempo real | ✅ Completo | Polling HTTP a cada 2 segundos no dashboard |
| 5 | Protocolo documentado | ✅ Completo | Protocolo NAP/1.0 especificado neste README (seção 6); falta criar `docs/protocolo.md` para o relatório |
| 6 | Persistência de dados | ✅ Completo | SQLite em modo WAL com 4 tabelas |
| 7 | Métricas de rede | ✅ Completo | CPU, RAM, conexões ativas, perda UDP, throughput |
| 8 | Medição de RTT | ✅ Completo | Calculado no servidor, exibido por evento na tabela do painel |
| 9 | Tratamento de erros | ✅ Completo | `try/except` em todos os módulos; banner visual de erro no painel |
| 10 | Demonstração prática | ✅ Completo | Sistema funcional end-to-end |

### Requisitos Funcionais Listados no PDF

| Requisito | Status | Observação |
|---|---|---|
| Cadastro e autenticação de usuários | ✅ Completo | `/api/auth/register` e `/api/auth/login` com hash bcrypt |
| Envio e armazenamento de dados | ✅ Completo | Sensor → SQLite via dois canais |
| Visualização em painel web | ✅ Completo | Dashboard com gráficos e tabela em tempo real |
| Envio de alertas automáticos | ⚠️ Parcial | Apenas `FILE_INTEGRITY` implementado; faltam `BRUTE_FORCE` e `PORT_SCAN` |
| Comunicação em tempo real | ✅ Completo | Polling 2s + banner de alerta imediato |
| Medição de RTT e throughput | ✅ Completo | RTT por alerta TCP; throughput UDP estimado no painel |
| Registro de logs | ✅ Completo | Tabela `events` com `raw_payload` completo para auditoria |

### Itens Obrigatórios do Wireshark (a ser realizado pelo grupo)

| # | Item | Status |
|---|---|---|
| 1 | Identificação do protocolo de aplicação (NAP) | 🔲 Pendente |
| 2 | Identificação dos protocolos de transporte e rede | 🔲 Pendente |
| 3 | Análise do handshake TCP | 🔲 Pendente |
| 4 | Análise de pacotes UDP | 🔲 Pendente |
| 5 | Medição aproximada de RTT | 🔲 Pendente |
| 6 | Identificação de tamanho dos pacotes | 🔲 Pendente |
| 7 | Sequência de comunicação cliente-servidor | 🔲 Pendente |
| 8 | Comparação TCP vs. UDP | 🔲 Pendente |

---

## 10. Bugs Conhecidos e Pendências Críticas

Esta seção documenta problemas encontrados no código que devem ser resolvidos **antes da entrega**. Os integrantes do grupo que ficarem responsáveis pela correção devem remover o item desta lista após o fix.

---

### 🔴 BUG 1 — Endpoint `/api/network/throughput` vai travar em runtime

**Arquivo:** `server/api.py`  
**Problema:** A rota tenta fazer `from server import TOTAL_UDP_BYTES, UDP_START_TIME`. Isso não funciona porque `server.py` e `api.py` são processos separados — o `api.py` não tem acesso às variáveis globais do processo `server.py`.

**Sintoma:** A rota retorna erro 500 assim que é chamada. Também há `time.time()` na função sem que `time` esteja importado no arquivo.

**Como corrigir:** Mover o cálculo de throughput para o banco de dados. O servidor UDP deve salvar o `timestamp` do primeiro e do último pacote recebido, e a rota Flask deve calcular o throughput consultando a tabela `metrics`:

```python
# Em api.py — versão corrigida da rota
import time

@app.route("/api/network/throughput", methods=["GET"])
def obter_throughput():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT MIN(timestamp) as inicio, MAX(timestamp) as fim, COUNT(*) as total FROM metrics")
        row = cursor.fetchone()
        conn.close()

        if not row or not row['inicio'] or row['inicio'] == row['fim']:
            return jsonify({"erro": "Dados insuficientes para calcular throughput"}), 400

        tempo_decorrido = row['fim'] - row['inicio']
        # Estimativa: tamanho médio de um pacote TELEMETRY é ~350 bytes
        total_bytes = row['total'] * 350
        throughput_kbps = (total_bytes * 8) / tempo_decorrido / 1000

        return jsonify({
            "total_pacotes_recebidos": row['total'],
            "tempo_ativo_segundos": round(tempo_decorrido, 2),
            "throughput_kbps": round(throughput_kbps, 3)
        }), 200

    except Exception as e:
        return jsonify({"erro": f"Falha ao calcular throughput: {str(e)}"}), 500
```

---

### 🔴 BUG 2 — Flask `app` instanciado duas vezes em `api.py`

**Arquivo:** `server/api.py`  
**Problema:** O objeto `app = Flask(__name__)` é criado na linha ~10 e novamente na linha ~15 (com as pastas de template e static). O segundo cria um Flask novo e o `CORS(app)` aplicado ao primeiro é descartado. O primeiro `app` e o primeiro `CORS(app)` nunca são usados.

**Como corrigir:** Remover a primeira instanciação duplicada. O arquivo deve conter apenas:

```python
app = Flask(__name__,
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR)
CORS(app)
```

---

### 🟡 PENDÊNCIA 3 — Simulação de ataques `BRUTE_FORCE` e `PORT_SCAN` não implementada

**Arquivos afetados:** `sensor/sensor.py` (precisa de novas funções)  
**Problema:** O projeto prevê a simulação de dois cenários de ataque adicionais que são importantes para demonstrar múltiplas categorias de alerta no painel. Atualmente só existe `FILE_INTEGRITY`.

**Como implementar:**

```python
# Adicionar em sensor.py

# Simulação de Brute Force
login_attempts = 0
login_window_start = time.time()

def simular_brute_force():
    global login_attempts, login_window_start
    login_attempts += 1
    agora = time.time()

    if agora - login_window_start > 10:  # janela de 10 segundos
        login_attempts = 1
        login_window_start = agora

    if login_attempts >= 10:  # limiar: 10 tentativas em 10s
        pacote_alerta = {
            "protocol": "NAP", "version": "1.0", "type": "ALERT",
            "sensor_id": SENSOR_ID, "timestamp": time.time(), "seq_number": 0,
            "payload": {
                "severity": "HIGH", "category": "BRUTE_FORCE",
                "description": f"{login_attempts} tentativas de login em {round(agora - login_window_start, 1)}s"
            }
        }
        enviar_alerta_tcp(pacote_alerta)
        login_attempts = 0

# Simulação de Port Scan
def simular_port_scan():
    portas_varridas = []
    for porta in range(20, 30):  # simula varredura de 10 portas
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect(("127.0.0.1", porta))
            portas_varridas.append(porta)
            s.close()
        except:
            pass

    if len(portas_varridas) >= 5:
        pacote_alerta = {
            "protocol": "NAP", "version": "1.0", "type": "ALERT",
            "sensor_id": SENSOR_ID, "timestamp": time.time(), "seq_number": 0,
            "payload": {
                "severity": "MEDIUM", "category": "PORT_SCAN",
                "description": f"Varredura detectada em {len(portas_varridas)} portas: {portas_varridas}"
            }
        }
        enviar_alerta_tcp(pacote_alerta)
```

Depois, chamar `simular_brute_force()` e ocasionalmente `simular_port_scan()` dentro do loop principal do `sensor.py`.

---

### 🟡 PENDÊNCIA 4 — Tabela `sensors` nunca é populada

**Arquivo:** `server/server.py`  
**Problema:** A tabela `sensors` é criada no banco mas nunca recebe inserções. O `server.py` não registra o sensor ao receber o primeiro pacote.

**Como corrigir:** Adicionar um `INSERT OR REPLACE` na tabela `sensors` dentro dos handlers UDP e TCP:

```python
# Adicionar no listen_udp() e listen_tcp() após pegar o sensor_id
cursor.execute("""
    INSERT INTO sensors (sensor_id, first_seen, last_seen, ip_address, status)
    VALUES (?, ?, ?, ?, 'ACTIVE')
    ON CONFLICT(sensor_id) DO UPDATE SET last_seen=excluded.last_seen
""", (sensor_id, time.time(), time.time(), str(endereco_cliente[0])))
```

---

### 🟡 PENDÊNCIA 5 — Criar `docs/protocolo.md`

O relatório da disciplina exige **"uma clara descrição do protocolo de aplicação"**. É necessário criar o arquivo `docs/protocolo.md` com a especificação formal do protocolo NAP (a seção 6 deste README pode ser usada como base).

---

## 11. Próximas Etapas para o Grupo

Tarefas prioritárias para finalizar o projeto antes da entrega em **27/05/2026**:

- [ ] **[CRÍTICO]** Corrigir Bug 1 — endpoint de throughput quebrando em runtime
- [ ] **[CRÍTICO]** Corrigir Bug 2 — instância duplicada do Flask em `api.py`
- [ ] **[IMPORTANTE]** Implementar simulação de `BRUTE_FORCE` e `PORT_SCAN` no sensor (Pendência 3)
- [ ] **[IMPORTANTE]** Popular tabela `sensors` no servidor (Pendência 4)
- [ ] **[IMPORTANTE]** Executar o sistema e fazer as capturas no Wireshark (ver seção 12)
- [ ] **[ENTREGA]** Criar `docs/protocolo.md` com especificação formal do protocolo (Pendência 5)
- [ ] **[ENTREGA]** Salvar screenshots das capturas do Wireshark em `docs/wireshark/`
- [ ] **[ENTREGA]** Gravar vídeo de demonstração (máximo 10 minutos) e adicionar link no relatório
- [ ] **[ENTREGA]** Confirmar que o repositório Git está público e o link do código-fonte está no relatório
- [ ] **[ENTREGA]** Escrever o relatório no formato especificado pela disciplina

---

## 12. Roteiro de Análise no Wireshark

### Preparação

1. Abra o Wireshark.
2. Selecione a interface **Loopback (lo)** no Linux/Mac ou **Adapter for loopback traffic capture** no Windows.
3. Inicie a captura **antes** de rodar o sensor.

### Filtros por Item Obrigatório

**Item 1 e 2 — Protocolo da aplicação + camadas de transporte e rede**

Use o filtro abaixo para ver apenas o tráfego do NetWatch:
```
tcp.port == 9998 || udp.port == 9999 || tcp.port == 5000
```
Expanda um pacote na janela inferior do Wireshark e mostre todas as camadas: Frame → Ethernet/Loopback → IPv4 → TCP ou UDP → Data. Isso demonstra o encapsulamento.

**Item 3 — Handshake TCP**

```
tcp.port == 9998 && (tcp.flags.syn == 1 || tcp.flags.ack == 1)
```
Identifique a sequência de 3 pacotes: `SYN` (sensor → servidor), `SYN-ACK` (servidor → sensor), `ACK` (sensor → servidor). Isso acontece toda vez que o sensor envia um alerta crítico.

**Item 4 — Pacotes UDP**

```
udp.port == 9999
```
Observe que não há handshake antes da chegada dos dados. Os pacotes chegam diretamente sem estabelecimento de conexão prévia — contrastar com o TCP.

**Item 5 — Medição de RTT**

Com o filtro TCP ativo, use `Estatísticas → Análise de Fluxo TCP` ou observe manualmente a coluna `Time` entre o pacote de dados do sensor e o ACK de resposta do servidor.

**Item 6 — Tamanho dos pacotes**

Verifique a coluna **Length** para pacotes UDP (telemetria). Um payload `TELEMETRY` típico do NetWatch tem entre 250 e 400 bytes. Compare com o overhead do handshake TCP.

**Item 7 e 8 — Sequência cliente-servidor e comparação TCP/UDP**

Capture um ciclo completo: vários pacotes UDP chegando sem resposta, depois um alerta TCP com o handshake, troca de dados e fechamento de conexão. Isso demonstra a diferença de comportamento entre os dois protocolos no mesmo capture.

**Item — Perda de pacotes UDP**

Para forçar perda, use o `tc` no Linux para simular delay/perda na loopback:
```bash
sudo tc qdisc add dev lo root netem loss 10%
# Execute o sensor por 30 segundos e observe lacunas no seq_number no painel
sudo tc qdisc del dev lo root  # Remover depois
```

### Screenshots Necessários para o Relatório

Salve em `docs/wireshark/`:

1. `01_encapsulamento.png` — pacote expandido mostrando todas as camadas
2. `02_handshake_tcp.png` — sequência SYN / SYN-ACK / ACK
3. `03_pacotes_udp.png` — fluxo UDP sem handshake
4. `04_rtt_medicao.png` — delta de tempo entre alerta e ACK
5. `05_comparacao_tcp_udp.png` — ambos os canais lado a lado na timeline

---

## 13. Credenciais Padrão

| Campo | Valor |
|---|---|
| Usuário | `admin` |
| Senha | `admin123` |

O usuário `admin` é criado automaticamente pelo `database.py` na primeira execução. Para criar novos operadores, use o botão **"Cadastrar Novo Operador"** na tela de login do painel, ou faça um `POST /api/auth/register`.

---

*Documento gerado como apoio ao Projeto 1 de CIC0124 — Redes de Computadores, UnB.*
