# Especificação do Protocolo de Aplicação — NAP/1.0

## NetWatch Application Protocol

> **CIC0124 — Redes de Computadores · UnB** Projeto 1 — Documento de Protocolo de Aplicação

---

## Sumário

1. [Introdução e Motivação](#1-introdução-e-motivação)
2. [Posição no Modelo Internet](#2-posição-no-modelo-internet)
3. [Visão Geral da Arquitetura de Comunicação](#3-visão-geral-da-arquitetura-de-comunicação)
4. [Identificação dos Participantes](#4-identificação-dos-participantes)
5. [Canais de Transporte e Justificativa TCP vs. UDP](#5-canais-de-transporte-e-justificativa-tcp-vs-udp)
6. [Formato das Mensagens](#6-formato-das-mensagens)
7. [Sequência de Troca de Mensagens](#7-sequência-de-troca-de-mensagens)
8. [Medição de RTT e Throughput](#8-medição-de-rtt-e-throughput)
9. [Comportamento sob Perda de Pacotes UDP](#9-comportamento-sob-perda-de-pacotes-udp)
10. [Retransmissão e Confiabilidade no Canal TCP](#10-retransmissão-e-confiabilidade-no-canal-tcp)
11. [Encapsulamento nas Camadas do Modelo Internet](#11-encapsulamento-nas-camadas-do-modelo-internet)
12. [Multiplexação por Portas](#12-multiplexação-por-portas)
13. [Tratamento de Erros](#13-tratamento-de-erros)
14. [Referência Completa das Mensagens](#14-referência-completa-das-mensagens)

---

## 1. Introdução e Motivação

### 1.1 O que é o NAP

O **NetWatch Application Protocol (NAP)**, versão 1.0, é um protocolo de camada de aplicação projetado especificamente para o sistema NetWatch SIEM. Ele define a sintaxe, a semântica e a sequência de todas as mensagens trocadas entre o Sensor de Segurança (cliente) e o Servidor de Aplicação (servidor).

O protocolo é baseado em mensagens **JSON codificadas em UTF-8** e trafega diretamente sobre os primitivos de transporte **TCP e UDP** da pilha TCP/IP, sem nenhuma camada intermediária de protocolo de aplicação já existente (como HTTP ou WebSocket) entre o sensor e o servidor de sockets.

### 1.2 Objetivos de Design

O NAP foi projetado com os seguintes objetivos:

- **Legibilidade:** mensagens em formato JSON são autodescritiváveis e facilmente inspecionáveis com ferramentas como o Wireshark.
- **Bifurcação por criticidade:** eventos de baixa criticidade usam UDP (eficiência); eventos críticos usam TCP (confiabilidade). Essa decisão é explícita no protocolo, não acidental.
- **Rastreabilidade:** cada mensagem carrega um `seq_number` que permite detectar lacunas (perda de pacotes) e um `timestamp` que habilita o cálculo de RTT fim-a-fim.
- **Auditabilidade:** o servidor persiste o payload JSON bruto completo de cada evento, garantindo que nada seja perdido nos registros de segurança.
- **Extensibilidade:** novos tipos de mensagem podem ser adicionados sem quebrar implementações existentes, bastando introduzir novos valores para o campo `type`.

---

## 2. Posição no Modelo Internet

O NAP opera exclusivamente na **Camada de Aplicação**. Ele depende das camadas inferiores para transporte, endereçamento e entrega física dos dados.

```
┌─────────────────────────────────────────────────────────────────┐
│  CAMADA DE APLICAÇÃO                                            │
│                                                                 │
│   ┌──────────────────────────────────────────────────────────┐  │
│   │  Protocolo NAP/1.0                                       │  │
│   │  Mensagens JSON · UTF-8 · tipos: TELEMETRY, ALERT, ACK  │  │
│   └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│   ┌─────────────────────┐     ┌──────────────────────────────┐  │
│   │  Protocolo HTTP/1.1 │     │  (Futuras extensões do NAP)  │  │
│   │  API Flask (porta   │     │                              │  │
│   │  5000) — Dashboard  │     │                              │  │
│   └─────────────────────┘     └──────────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  CAMADA DE TRANSPORTE                                           │
│                                                                 │
│   ┌───────────────────────────┐  ┌───────────────────────────┐  │
│   │  TCP                      │  │  UDP                      │  │
│   │  • Porta 9998 (Alertas)   │  │  • Porta 9999 (Telemetria)│  │
│   │  • Porta 5000 (HTTP)      │  │                           │  │
│   │  • Conexão orientada      │  │  • Sem conexão            │  │
│   │  • Handshake 3-vias       │  │  • Sem handshake          │  │
│   │  • Retransmissão auto.    │  │  • Best-effort            │  │
│   │  • Entrega ordenada       │  │  • Menor overhead         │  │
│   └───────────────────────────┘  └───────────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  CAMADA DE REDE                                                 │
│                                                                 │
│   IP versão 4 (IPv4)                                            │
│   Endereço de origem e destino: 127.0.0.1 (loopback)           │
│   Protocolo de roteamento: não aplicável (mesma máquina)        │
├─────────────────────────────────────────────────────────────────┤
│  CAMADA DE ENLACE / FÍSICA                                      │
│                                                                 │
│   Interface de Loopback (lo / localhost)                        │
│   MTU: 65536 bytes · sem colisão · sem erro físico             │
└─────────────────────────────────────────────────────────────────┘
```

**Consequência prática:** ao capturar o tráfego do NetWatch no Wireshark, cada pacote exibe exatamente essa pilha de camadas ao ser expandido na janela de detalhes — Frame, Ethernet/Loopback, IPv4, TCP ou UDP e, por fim, os bytes do payload JSON do NAP na camada de dados.

---

## 3. Visão Geral da Arquitetura de Comunicação

O NAP opera em um modelo **cliente-servidor assimétrico** com **dois canais paralelos e independentes** saindo do mesmo processo cliente (Sensor) para o mesmo processo servidor:

```
                    ┌──────────────────────────┐
                    │   SENSOR (Cliente)        │
                    │   127.0.0.1 : porta efêmera│
                    └────────────┬─────────────┘
                                 │
              ┌──────────────────┼──────────────────────┐
              │                  │                       │
              │ UDP              │ TCP                   │ TCP
              │ porta 9999       │ porta 9998            │ porta 5000
              │ (Telemetria)     │ (Alertas)             │ (HTTP dashboard)
              ▼                  ▼                       ▼
  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────┐
  │ Thread UDP      │  │ Thread TCP        │  │  API Flask           │
  │ Listener        │  │ Listener          │  │  (Processo separado) │
  │ server.py       │  │ server.py         │  │  api.py              │
  └────────┬────────┘  └────────┬──────────┘  └──────────┬──────────┘
           │                    │                         │
           └────────────────────┼─────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   SQLite (WAL mode)    │
                    │   database/netwatch.db │
                    └───────────────────────┘
```

### Papel de cada participante

|Participante|Endereço IP|Portas|Papel no NAP|
|---|---|---|---|
|Sensor (Cliente)|`127.0.0.1`|Efêmera (atribuída pelo SO)|Emissor de `TELEMETRY` e `ALERT`; receptor de `ACK`|
|Servidor de Sockets|`127.0.0.1`|`9998` (TCP), `9999` (UDP)|Receptor de `TELEMETRY` e `ALERT`; emissor de `ACK`|
|API Flask|`127.0.0.1`|`5000` (TCP/HTTP)|Serve o painel web; consulta banco; não participa do NAP diretamente|
|Painel Web (Browser)|`127.0.0.1`|Efêmera|Consome a API HTTP; não interage com o NAP diretamente|

---

## 4. Identificação dos Participantes

### 4.1 Endereçamento IP

Toda a comunicação do sistema NetWatch, em ambiente de desenvolvimento e demonstração, ocorre sobre a interface de **loopback** do sistema operacional:

- **Endereço:** `127.0.0.1`
- **Interface:** `lo` (Linux/macOS) ou `Loopback Pseudo-Interface 1` (Windows)
- **Significado:** pacotes enviados para `127.0.0.1` nunca saem fisicamente pela placa de rede — são processados internamente pelo kernel do SO.

> Isso implica que toda a comunicação ocorre dentro da mesma máquina. Em um cenário de produção, o `IP_SERVER` no `sensor.py` seria substituído pelo IP real do servidor de monitoramento, e os pacotes trafegaria pela rede física.

### 4.2 Identificação do Sensor

Cada instância do sensor gera, na inicialização, um identificador único de 8 caracteres extraído de um UUID aleatório:

```python
# collector.py
SENSOR_ID = str(uuid.uuid4())[:8]   # Ex: "a1b2c3d4"
```

Esse `sensor_id` é incluído em **todas** as mensagens NAP, permitindo ao servidor distinguir múltiplos sensores conectados simultaneamente e correlacionar eventos de telemetria com alertas do mesmo host.

### 4.3 Portas de Comunicação

|Porta|Protocolo de Transporte|Processo|Direção|Função|
|---|---|---|---|---|
|**9999**|UDP|`server.py`|Sensor → Servidor|Canal de Telemetria|
|**9998**|TCP|`server.py`|Sensor ↔ Servidor|Canal de Alertas e ACK|
|**5000**|TCP (HTTP/1.1)|`api.py`|Browser ↔ Flask|API REST e Dashboard Web|

---

## 5. Canais de Transporte e Justificativa TCP vs. UDP

Uma das decisões arquiteturais centrais do NAP é a bifurcação do tráfego em dois canais com características de transporte distintas, escolhidos de acordo com a natureza e a criticidade de cada tipo de dado.

### 5.1 Canal de Telemetria — UDP (porta 9999)

O canal UDP transporta as mensagens do tipo `TELEMETRY` — métricas periódicas de hardware e rede coletadas a cada 5 segundos.

**Por que UDP para telemetria?**

O protocolo UDP (User Datagram Protocol) é um protocolo de transporte **sem conexão** e **sem garantia de entrega**. Um datagrama UDP é simplesmente encapsulado em um segmento IP e enviado — sem handshake prévio, sem confirmação de recebimento, sem retransmissão em caso de perda.

Essa característica, que em um primeiro momento parece uma desvantagem, é na verdade adequada para o canal de telemetria pelos seguintes motivos:

1. **Tolerância à perda:** uma leitura de CPU de 5 segundos atrás que se perdeu na rede não compromete o monitoramento. O próximo ciclo (em mais 5 segundos) fornecerá dados atualizados.
2. **Baixo overhead:** UDP não precisa estabelecer conexão nem manter estado. Um datagrama de telemetria sai imediatamente após `sendto()`, sem nenhuma troca prévia de pacotes.
3. **Adequação à alta volumetria:** em cenários com muitos sensores enviando métricas frequentes, o overhead do TCP (handshake, ACK, controle de fluxo) multiplicaria o tráfego de controle significativamente.
4. **Possibilidade de medir degradação:** a ausência de retransmissão automática permite observar e quantificar empiricamente a perda de pacotes através do campo `seq_number`.

**Comportamento observado no Wireshark:**

- Não há pacotes `SYN`/`SYN-ACK` antes dos dados chegarem.
- Cada datagrama UDP chega de forma independente, sem relação com os anteriores.
- O campo "Protocolo" exibe `UDP`; o payload bruto em hexadecimal contém o JSON do NAP.

### 5.2 Canal de Alertas e Controle — TCP (porta 9998)

O canal TCP transporta as mensagens do tipo `ALERT` — eventos de segurança de alta ou crítica severidade que o sensor detecta.

**Por que TCP para alertas?**

O protocolo TCP (Transmission Control Protocol) é um protocolo **orientado à conexão**, com garantia de entrega, ordenação de segmentos e controle de fluxo e congestionamento.

Um alerta de segurança (ex.: arquivo crítico modificado, tentativa de brute force) é um dado que **não pode ser descartado silenciosamente**. A perda de um alerta equivale a uma brecha no sistema de monitoramento — o operador não saberia que um incidente ocorreu. Por isso:

1. **Garantia de entrega:** o TCP retransmite automaticamente o segmento se o ACK não for recebido dentro do timeout, garantindo que o alerta chegue ao servidor.
2. **Handshake de três vias:** antes de cada alerta, o sensor abre uma conexão TCP (SYN → SYN-ACK → ACK), que é fechada logo após o recebimento do ACK da camada de aplicação (NAP ACK).
3. **ACK de aplicação:** além do ACK de transporte (TCP), o servidor envia um ACK do próprio protocolo NAP, confirmando que o alerta foi recebido, validado e persistido no banco — o `rtt_ms` neste ACK é o RTT fim-a-fim da aplicação.

**Comportamento observado no Wireshark:**

- Sequência `SYN` → `SYN-ACK` → `ACK` visível antes de qualquer dado.
- Segmentos de dados com o payload JSON do alerta.
- Segmento de resposta com o JSON do `ACK NAP`.
- Sequência `FIN` → `ACK` encerrando a conexão.

### 5.3 Comparação Lado a Lado

|Característica|Canal UDP (Telemetria)|Canal TCP (Alertas)|
|---|---|---|
|**Tipo de mensagem**|`TELEMETRY`, `HEARTBEAT`|`ALERT`|
|**Porta**|9999|9998|
|**Conexão prévia**|Não|Sim (handshake 3-vias)|
|**Garantia de entrega**|Não|Sim|
|**Retransmissão automática**|Não|Sim (pelo TCP)|
|**ACK de nível de aplicação**|Não|Sim (NAP `ACK`)|
|**Ordenação**|Não garantida|Garantida|
|**Overhead de controle**|Mínimo|Maior (handshake + ACKs)|
|**RTT mensurável pelo app**|Não|Sim (via timestamps)|
|**Tolerância à perda**|Alta|Zero|

---

## 6. Formato das Mensagens

### 6.1 Encoding e Delimitação

- **Formato:** JSON
- **Encoding:** UTF-8
- **Delimitação:** cada mensagem NAP corresponde a exatamente **um payload completo** em cada transmissão:
    - No UDP: um datagrama = uma mensagem (limites naturais do datagrama).
    - No TCP: uma chamada `sendall()` envia a mensagem completa; uma chamada `recv(4096)` a lê integralmente. O tamanho máximo dos payloads NAP (< 1 KB) garante que cabem em um único buffer de 4096 bytes.

### 6.2 Cabeçalho Comum

Todo e qualquer pacote NAP, independentemente do tipo, **deve** conter os seguintes campos no nível raiz do objeto JSON:

|Campo|Tipo JSON|Obrigatório|Descrição|
|---|---|---|---|
|`protocol`|`string`|Sim|Identificador fixo. Valor sempre: `"NAP"`|
|`version`|`string`|Sim|Versão do protocolo. Valor atual: `"1.0"`|
|`type`|`string`|Sim|Discriminador de tipo. Valores: `"TELEMETRY"`, `"ALERT"`, `"ACK"`, `"HEARTBEAT"`|
|`sensor_id`|`string`|Sim|Identificador de 8 caracteres do sensor emissor|
|`timestamp`|`number` (float)|Sim|Unix timestamp com precisão de milissegundos (ex: `1716000000.123`)|
|`seq_number`|`number` (int)|Sim|Contador inteiro incrementado a cada envio. Começa em 0. Usado para detectar perda de pacotes no canal UDP|

### 6.3 Campo `payload`

O campo `payload` é um objeto JSON aninhado cujo conteúdo varia de acordo com o `type` da mensagem. Ele não existe na mensagem `ACK` (que é emitida pelo servidor, não pelo sensor).

---

## 7. Sequência de Troca de Mensagens

### 7.1 Ciclo Normal — Telemetria via UDP

Este é o ciclo padrão, repetido a cada 5 segundos enquanto o sensor está ativo. Não há resposta do servidor.

```
SENSOR                                          SERVIDOR
  │                                                 │
  │  [Socket UDP criado uma única vez]              │
  │                                                 │
  ├─── TELEMETRY (UDP, seq=0) ───────────────────►  │
  │    { type: "TELEMETRY", seq_number: 0, ... }    │ → salva em metrics
  │                                                 │
  │  [espera 5 segundos]                            │
  │                                                 │
  ├─── TELEMETRY (UDP, seq=1) ───────────────────►  │
  │    { type: "TELEMETRY", seq_number: 1, ... }    │ → salva em metrics
  │                                                 │
  │  [espera 5 segundos]                            │
  │                                                 │
  ├─── TELEMETRY (UDP, seq=2) ───────────────────►  │
  │    { type: "TELEMETRY", seq_number: 2, ... }    │ → salva em metrics
  │                                                 │
  │    ~~~ pacote seq=3 perdido na rede ~~~          │   ← lacuna detectável
  │                                                 │
  ├─── TELEMETRY (UDP, seq=4) ───────────────────►  │
  │    { type: "TELEMETRY", seq_number: 4, ... }    │ → lacuna detectada (3 ausente)
  │                                                 │
```

**Sem resposta do servidor:** o canal UDP é unidirecional do ponto de vista do NAP. O servidor processa e persiste silenciosamente cada datagrama recebido.

### 7.2 Ciclo de Alerta — Via TCP com ACK e RTT

Este ciclo ocorre imediatamente ao detectar uma anomalia. Uma nova conexão TCP é estabelecida para cada alerta.

```
SENSOR                                          SERVIDOR
  │                                                 │
  │  [Anomalia detectada: hash mudou]               │
  │                                                 │
  │  ─── SYN ──────────────────────────────────►   │  \
  │  ◄── SYN-ACK ──────────────────────────────    │   │ Handshake
  │  ─── ACK ──────────────────────────────────►   │  /  TCP 3-vias
  │  [conexão TCP estabelecida]                     │
  │                                                 │
  │  Registra timestamp_envio = T₁                 │
  │                                                 │
  ├─── ALERT (TCP) ─────────────────────────────►  │
  │    {                                            │  Registra timestamp_recebimento = T₂
  │      "type": "ALERT",                          │  RTT = (T₂ - T₁) × 1000 ms
  │      "timestamp": T₁,                          │  → salva em events com rtt_ms
  │      "payload": {                              │
  │        "severity": "CRITICAL",                 │
  │        "category": "FILE_INTEGRITY",           │
  │        ...                                      │
  │      }                                          │
  │    }                                            │
  │                                                 │
  │  ◄── ACK NAP (TCP) ─────────────────────────   │
  │    {                                            │
  │      "type": "ACK",                             │
  │      "status": "SUCESS",                        │
  │      "rtt_ms": (T₂ - T₁) × 1000,              │
  │      "timestamp": T₂                           │
  │    }                                            │
  │                                                 │
  │  [Sensor exibe: "RTT medido: X ms"]             │
  │                                                 │
  │  ─── FIN ──────────────────────────────────►   │  \
  │  ◄── ACK ──────────────────────────────────    │   │ Encerramento
  │  ◄── FIN ──────────────────────────────────    │   │ TCP
  │  ─── ACK ──────────────────────────────────►   │  /
  │  [conexão TCP encerrada]                        │
  │                                                 │
```

> **Observação sobre o handshake:** No Wireshark, o handshake de três vias (`SYN`, `SYN-ACK`, `ACK`) aparecerá como os **três primeiros pacotes** de cada fluxo TCP na porta 9998, **antes** de qualquer dado da aplicação. Isso é o TCP estabelecendo a conexão antes que o NAP possa trafegar.

### 7.3 Ciclo da API HTTP — Dashboard Web

Este ciclo ocorre de forma independente dos canais de socket, a cada 2 segundos, iniciado pelo JavaScript do painel web.

```
BROWSER (JavaScript)                        API FLASK (api.py)
  │                                               │
  │  [Usuário faz login com sucesso]              │
  │                                               │
  │  ─── POST /api/auth/login ─────────────────►  │
  │      Body: { username, password }             │  → valida hash bcrypt
  │  ◄── 200 OK { status: "success" } ─────────   │
  │                                               │
  │  [Inicia polling a cada 2 segundos]           │
  │                                               │
  ├── GET /api/metrics ────────────────────────►  │
  │   ◄── 200 OK [ array de métricas ] ─────────  │  → lê tabela metrics (SQLite)
  │                                               │
  ├── GET /api/events ─────────────────────────►  │
  │   ◄── 200 OK [ array de alertas ] ──────────  │  → lê tabela events (SQLite)
  │                                               │
  ├── GET /api/status ─────────────────────────►  │
  │   ◄── 200 OK { status: "online" } ──────────  │
  │                                               │
  │  [Atualiza DOM: gráficos, tabela, contadores] │
  │  [2 segundos...]                              │
  │                                               │
  ├── GET /api/metrics ────────────────────────►  │  (repete indefinidamente)
  │   ...                                         │
```

---

## 8. Medição de RTT e Throughput

### 8.1 RTT — Round-Trip Time (Canal TCP)

O RTT (tempo de ida e volta) é medido pelo servidor no canal TCP de forma **fim-a-fim na camada de aplicação** — não pelo TCP em si.

**Metodologia:**

1. O Sensor registra o momento exato do envio incluindo-o no payload como `"timestamp": T₁`.
2. O Servidor registra o momento de chegada do pacote como `T₂ = time.time()` imediatamente após `recv()`.
3. O RTT de aplicação é calculado como: `RTT_ms = (T₂ - T₁) × 1000`
4. O valor calculado é retornado ao sensor no campo `"rtt_ms"` da mensagem `ACK`, persistido na tabela `events` e exibido na tabela do painel.

**Considerações:**

- O valor medido inclui: tempo de serialização JSON no sensor + latência de transmissão TCP + tempo de desserialização no servidor. Em ambiente loopback, a latência de rede é negligível (< 0,1 ms), então o valor reflete principalmente o processamento das camadas de software.
- Valores típicos em loopback: **0,1 ms a 5 ms**.
- Em rede real (Wi-Fi local): tipicamente **1 ms a 20 ms**.
- O RTT não é medido no canal UDP, pois o UDP não tem resposta — não existe uma resposta `ACK` para fechar o loop de tempo.

**Comparação com RTT do Wireshark:** o Wireshark mede o RTT do TCP (tempo entre um segmento de dados e o `ACK` correspondente do TCP). O RTT medido pelo NAP é **maior**, pois inclui além do tempo de rede o processamento da aplicação no servidor antes de enviar o `ACK NAP`.

### 8.2 Throughput — Canal UDP

O throughput do canal UDP é estimado no painel web a partir dos dados de telemetria armazenados no banco.

**Metodologia (implementada no `dashboard.html`):**

```
throughput_kbps = (N_pacotes × tamanho_médio_bytes × 8) / Δt / 1000
```

Onde:

- `N_pacotes` = quantidade de pacotes recebidos na janela de observação
- `tamanho_médio_bytes` = estimativa de 320 bytes por payload TELEMETRY
- `Δt` = `timestamp_mais_recente - timestamp_mais_antigo` (em segundos)

**Limitação:** o tamanho médio de 320 bytes é uma estimativa. O tamanho real varia com a quantidade de portas abertas e a quantidade de arquivos monitorados. Para uma medição precisa, o servidor deve registrar o tamanho real de cada datagrama (`len(dados_bytes)`) na tabela `metrics`.

---

## 9. Comportamento sob Perda de Pacotes UDP

### 9.1 Mecanismo de Detecção

O campo `seq_number` nas mensagens `TELEMETRY` é um contador inteiro incrementado pelo sensor a cada envio, começando em 0. Como o UDP não garante entrega, o servidor pode receber os pacotes com lacunas nesse contador — o que indica perda.

**Exemplo de detecção:**

```
Pacotes recebidos pelo servidor: seq=0, seq=1, seq=2, seq=4, seq=5
                                                       ▲
                                               seq=3 não chegou → 1 pacote perdido
```

### 9.2 Cálculo da Taxa de Perda

O painel web calcula a taxa de perda usando os `seq_number` armazenados na tabela `metrics`:

```
pacotes_esperados = seq_mais_recente - seq_mais_antigo
pacotes_recebidos = total_de_registros_na_janela - 1
taxa_perda = (pacotes_esperados - pacotes_recebidos) / pacotes_esperados × 100%
```

**Exemplo numérico:**

- Seq mais recente: 50
- Seq mais antigo: 0
- Esperados: 50
- Recebidos: 47 (47 registros na tabela)
- **Taxa de perda: (50 - 47) / 50 × 100 = 6,0%**

### 9.3 Comportamento do Servidor sob Perda

O servidor UDP **não toma nenhuma ação** para recuperar pacotes perdidos — isso é intencional e coerente com a filosofia do protocolo. A perda de telemetria rotineira é aceitável. O servidor simplesmente processa os pacotes que chegam e ignora os que não chegam.

Isso contrasta diretamente com o canal TCP, onde o próprio protocolo de transporte garante a retransmissão automática de segmentos perdidos antes que o dado chegue à aplicação.

### 9.4 Cenário de Simulação com `tc` (Linux)

Para demonstrar empiricamente a perda no Wireshark:

```bash
# Introduz 15% de perda artificial na interface loopback
sudo tc qdisc add dev lo root netem loss 15%

# Execute o sensor por ~60 segundos
# Observe as lacunas no seq_number no painel e no Wireshark

# Remove a regra após o teste
sudo tc qdisc del dev lo root
```

No Wireshark, com o filtro `udp.port == 9999`, será possível observar que alguns seq_numbers simplesmente não aparecem na captura — eles foram descartados pelo kernel antes de chegarem ao servidor.

---

## 10. Retransmissão e Confiabilidade no Canal TCP

### 10.1 Retransmissão pelo TCP

O TCP garante a entrega de dados através de **retransmissão automática**. Se um segmento não for confirmado (via TCP ACK) dentro do tempo de retransmissão (RTO — Retransmission Timeout), o TCP reenvia automaticamente o segmento — sem que a aplicação precise saber ou agir.

No contexto do NAP, isso significa: se o alerta CRITICAL enviado pelo sensor sofrer perda de pacote na rede, **o TCP vai reenviar automaticamente** até que o servidor confirme o recebimento. O sensor não precisa implementar lógica de retransmissão.

### 10.2 Observação no Wireshark

Retransmissões TCP aparecem no Wireshark marcadas com a anotação `[TCP Retransmission]` na coluna Info. Em ambiente loopback, raramente ocorrem, mas podem ser forçadas com `tc netem` conforme descrito na seção 9.4.

### 10.3 Handshake de Três Vias — Detalhe dos Campos TCP

|Passo|Direção|Flags TCP|Significado|
|---|---|---|---|
|1 — SYN|Sensor → Servidor|`SYN=1, ACK=0`|Sensor solicita abertura de conexão; envia `ISN` (Initial Sequence Number)|
|2 — SYN-ACK|Servidor → Sensor|`SYN=1, ACK=1`|Servidor aceita; envia seu próprio `ISN` e confirma o `ISN` do sensor|
|3 — ACK|Sensor → Servidor|`SYN=0, ACK=1`|Sensor confirma o `ISN` do servidor; conexão estabelecida|

Após o passo 3, o sensor envia o payload JSON do `ALERT`. Após receber o `ACK NAP`, o sensor encerra a conexão com uma sequência `FIN → ACK → FIN → ACK`.

---

## 11. Encapsulamento nas Camadas do Modelo Internet

Quando o sensor executa `udp_socket.sendto(mensagem.encode('utf-8'), endereco_destino)`, o que ocorre internamente é uma série de **encapsulamentos sucessivos** pelas camadas da pilha TCP/IP:

```
┌──────────────────────────────────────────────────────────────┐
│  CAMADA DE APLICAÇÃO — Dado gerado pelo NAP                  │
│                                                              │
│  {"protocol":"NAP","version":"1.0","type":"TELEMETRY",       │
│   "sensor_id":"a1b2c3d4","timestamp":1716000000.123,         │
│   "seq_number":42,"payload":{...}}                           │
│                                                              │
│  Tamanho típico: 250–400 bytes                               │
└──────────────────┬───────────────────────────────────────────┘
                   │ encapsula como dado (campo Data)
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  CAMADA DE TRANSPORTE — Cabeçalho UDP adicionado             │
│                                                              │
│  ┌──────────┬──────────┬──────────┬──────────┬─────────────┐ │
│  │ Porta    │ Porta    │ Comprimento│ Checksum│    Dados    │ │
│  │ Origem   │ Destino  │   Total  │          │  (NAP JSON) │ │
│  │ (efêmera)│  9999    │          │          │             │ │
│  └──────────┴──────────┴──────────┴──────────┴─────────────┘ │
│  Overhead do cabeçalho UDP: 8 bytes                           │
└──────────────────┬───────────────────────────────────────────┘
                   │ encapsula como dado (campo Data/Payload)
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  CAMADA DE REDE — Cabeçalho IPv4 adicionado                  │
│                                                              │
│  ┌──────┬────┬────┬─────┬──────┬────┬──────┬───────┬──────┐  │
│  │Versão│IHL │ToS │Comp.│ ID   │Flag│Offset│ TTL  │Proto │  │
│  │  4   │    │    │Total│      │    │      │  64  │  17  │  │
│  └──────┴────┴────┴─────┴──────┴────┴──────┴───────┴──────┘  │
│  ┌──────────────────┬───────────────────────────────────────┐ │
│  │  Checksum Header │ IP Origem: 127.0.0.1                  │ │
│  ├──────────────────┴───────────────────────────────────────┤ │
│  │ IP Destino: 127.0.0.1                                    │ │
│  ├──────────────────────────────────────────────────────────┤ │
│  │ Dados (UDP header + NAP JSON)                            │ │
│  └──────────────────────────────────────────────────────────┘ │
│  Overhead do cabeçalho IPv4: 20 bytes (sem opções)            │
│  Protocolo no cabeçalho: 17 (UDP) ou 6 (TCP)                  │
└──────────────────┬───────────────────────────────────────────┘
                   │ encapsula como dado
                   ▼
┌──────────────────────────────────────────────────────────────┐
│  CAMADA DE ENLACE — Interface Loopback                        │
│                                                              │
│  ┌──────────────┬────────────────────────────────────────┐   │
│  │ Cabeçalho    │ Dados (IPv4 header + UDP/TCP + NAP)    │   │
│  │ Loopback     │                                        │   │
│  │ (4 bytes)    │                                        │   │
│  └──────────────┴────────────────────────────────────────┘   │
│  Tipo: 0x0002 (IPv4 sobre loopback — Linux)                   │
└──────────────────────────────────────────────────────────────┘
```

**Tamanho total estimado de um pacote TELEMETRY:**

- Payload JSON NAP: ~320 bytes
- Cabeçalho UDP: 8 bytes
- Cabeçalho IPv4: 20 bytes
- Cabeçalho Loopback: 4 bytes
- **Total: ~352 bytes** (visível na coluna "Length" do Wireshark)

---

## 12. Multiplexação por Portas

A multiplexação é o mecanismo pelo qual um único endereço IP (`127.0.0.1`) pode simultaneamente hospedar múltiplos serviços independentes — diferenciados pelo número de porta. O NetWatch utiliza **três portas distintas** para três fluxos de dados com propósitos diferentes:

```
                    IP 127.0.0.1
                         │
          ┌──────────────┼──────────────┐
          │              │              │
       Porta          Porta          Porta
        9999           9998           5000
          │              │              │
         UDP            TCP            TCP
          │              │              │
    Thread UDP      Thread TCP       API Flask
    (Telemetria)    (Alertas)        (Dashboard)
```

No Wireshark, a multiplexação é visível pelo campo **Destination Port** no cabeçalho TCP/UDP de cada pacote. Mesmo que todos os pacotes tenham o mesmo IP de destino (`127.0.0.1`), o kernel do sistema operacional os despacha para o processo correto (socket correto) com base exclusivamente no número da porta.

---

## 13. Tratamento de Erros

### 13.1 No Canal UDP (Sensor)

O sensor simplesmente descarta silenciosamente falhas de envio UDP — o protocolo não prevê recuperação:

```python
# sensor.py
udp_socket.sendto(mensagem.encode('utf-8'), endereco_destino)
# Se o servidor não estiver rodando, o SO descarta o datagrama.
# Nenhuma exceção é levantada para UDP — o envio é fire-and-forget.
```

### 13.2 No Canal TCP (Sensor)

Falhas de conexão TCP são capturadas e logadas, sem encerrar o processo:

```python
# sensor.py
def enviar_alerta_tcp(payload_alerta):
    try:
        tcp_socket = socket.socket(...)
        tcp_socket.connect((IP_SERVER, TCP_PORT))  # falha se servidor offline
        ...
    except Exception as e:
        print(f"[ERRO TCP] Não foi possível enviar alerta ou receber ACK: {e}")
        # O sensor continua operando; o alerta é perdido nesta ocorrência
```

### 13.3 No Servidor (Handlers UDP e TCP)

Erros de parsing JSON ou campos ausentes são capturados por bloco `try/except` em ambos os listeners. O servidor loga o erro e continua aguardando o próximo pacote — um pacote malformado não derruba o serviço.

### 13.4 Na API Flask

Todas as rotas encapsulam o acesso ao banco de dados em `try/except`. Em caso de falha, retornam HTTP 500 com um JSON descritivo `{"erro": "..."}`. O painel web captura esse erro e exibe um banner visual de alerta ao operador.

---

## 14. Referência Completa das Mensagens

### Tipo `TELEMETRY` — Canal UDP

**Direção:** Sensor → Servidor  
**Transporte:** UDP, porta 9999  
**Frequência:** a cada 5 segundos

```json
{
  "protocol":   "NAP",
  "version":    "1.0",
  "type":       "TELEMETRY",
  "sensor_id":  "a1b2c3d4",
  "timestamp":  1716000000.123,
  "seq_number": 42,
  "payload": {
    "cpu_percent":        34.5,
    "ram_percent":        61.2,
    "active_connections": 18,
    "open_ports":         [22, 80, 443, 5000, 9998, 9999],
    "file_hashes": {
      "collector.py": "e3b0c44298fc1c149afbf4c8996fb924..."
    }
  }
}
```

|Campo do payload|Tipo|Descrição|
|---|---|---|
|`cpu_percent`|float|Uso da CPU em %, coletado via `psutil.cpu_percent()`|
|`ram_percent`|float|Uso da RAM em %, coletado via `psutil.virtual_memory().percent`|
|`active_connections`|int|Total de conexões de rede ativas no host (`psutil.net_connections()`)|
|`open_ports`|array[int]|Lista de portas em estado `LISTEN`, sem duplicatas, ordenada|
|`file_hashes`|object|Mapeamento `nome_arquivo → hash_sha256` dos arquivos monitorados|

---

### Tipo `ALERT` — Canal TCP

**Direção:** Sensor → Servidor  
**Transporte:** TCP, porta 9998 (nova conexão a cada alerta)  
**Frequência:** imediata, ao detectar anomalia

```json
{
  "protocol":   "NAP",
  "version":    "1.0",
  "type":       "ALERT",
  "sensor_id":  "a1b2c3d4",
  "timestamp":  1716000001.456,
  "seq_number": 5,
  "payload": {
    "severity":    "CRITICAL",
    "category":    "FILE_INTEGRITY",
    "description": "O arquivo collector.py foi modificado de abc123... para def456..."
  }
}
```

|Campo do payload|Tipo|Valores válidos|Descrição|
|---|---|---|---|
|`severity`|string|`"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`|Nível de severidade do evento|
|`category`|string|`"FILE_INTEGRITY"`, `"BRUTE_FORCE"`, `"PORT_SCAN"`, `"CONNECTION_FLOOD"`|Categoria do evento de segurança|
|`description`|string|Texto livre|Descrição legível do evento para o operador|

---

### Tipo `ACK` — Canal TCP

**Direção:** Servidor → Sensor  
**Transporte:** TCP, porta 9998 (na mesma conexão do ALERT)  
**Frequência:** uma resposta para cada ALERT recebido

```json
{
  "protocolo": "NAP",
  "version":   "1.0",
  "type":      "ACK",
  "status":    "SUCESS",
  "rtt_ms":    0.87,
  "timestamp": 1716000001.461
}
```

|Campo|Tipo|Descrição|
|---|---|---|
|`status`|string|`"SUCESS"` indica que o alerta foi recebido, validado e persistido|
|`rtt_ms`|float|RTT fim-a-fim em milissegundos: `(timestamp_recebimento - timestamp_envio) × 1000`|
|`timestamp`|float|Unix timestamp do momento em que o servidor gerou a resposta ACK|

---