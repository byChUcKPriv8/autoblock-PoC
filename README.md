[README_AutoBlock_FortiGate.md](https://github.com/user-attachments/files/22984470/README_AutoBlock_FortiGate.md)
# 🧱 Auto-Block PoC — Bloqueio Dinâmico de IPs para FortiGate  
### Syslog + Bash + Python + Nginx + Systemd

Prova de conceito criada para automatizar o bloqueio de IPs maliciosos detectados pelos logs de IPS/UTM do FortiGate.  
O projeto coleta logs via Syslog, identifica conexões com `action="dropped"`, gera uma lista dinâmica de IPs, aplica TTL e publica essa lista para que o próprio FortiGate consuma automaticamente como **Threat Feed** (External Block List).

---

## ⚙️ Tecnologias e linguagens utilizadas

| Tecnologia | Função |
|-------------|--------|
| **Bash** | Automação principal: extração, publicação e mesclagem da blocklist. |
| **Python 3** | (Opcional) Enriquecimento e validação de IPs com AbuseIPDB (`enrich_and_decide.py`). |
| **Nginx** | Servidor web que disponibiliza a lista em HTTP/HTTPS. |
| **Systemd** | Agendamento automático e controle do pipeline (`auto-block.timer`). |
| **SQLite** | (Opcional) Banco leve para cache e auditoria no módulo de enriquecimento. |

---

## 🎯 Objetivo do projeto

Reduzir o tempo de resposta a incidentes e ataques (DDoS, força bruta, scans, etc.) automatizando o processo de bloqueio:

1. Identificar IPs já bloqueados pelo FortiGate (`action="dropped"`).
2. Atualizar automaticamente uma blocklist acessível via HTTP.
3. Fazer o FortiGate consumir essa lista e aplicar bloqueios futuros.
4. Manter auditoria completa e TTL automático nas entradas.

Resultado: menos intervenção manual, mais eficiência e rastreabilidade.

---

## 📂 Estrutura do projeto

```
/opt/auto-block/
  scripts/
    extract_suspects.sh
    publish_blocklist.sh
    enrich_and_decide.py
  logs/
    suspects_raw.txt
    pending_blocklist_with_meta.txt
    block_audit.csv
/var/www/html/blocklist/
  blocklist.txt
/etc/systemd/system/
  auto-block.service
  auto-block.timer
/etc/auto-block.env
```

---

## 🔄 Como funciona

1. **FortiGate** detecta tráfego malicioso e aplica `action="dropped"`.
2. O log é enviado via **Syslog** para o servidor central.
3. `extract_suspects.sh` lê esses logs e grava as entradas formatadas (`TIME_HUMAN|IP|FULL_LINE`).
4. `publish_blocklist.sh`:
   - filtra apenas linhas com `action="dropped"`;
   - aplica TTL às entradas (exclui IPs antigos);
   - mescla IPs novos com os existentes no `blocklist.txt`;
   - gera auditoria detalhada em `block_audit.csv`.
5. **Nginx** serve `/blocklist/blocklist.txt`.
6. O **FortiGate** consome a URL do feed e atualiza sua política de bloqueio automaticamente.

---

## 🧩 Arquivos principais

### `extract_suspects.sh`
Extrai IPs de origem dos logs FortiGate e gera o arquivo `suspects_raw.txt`.  
Aceita tanto logs clássicos (`srcip=`) quanto logs no formato delimitado por `|`.  
Mantém apenas a última ocorrência de cada IP.

### `publish_blocklist.sh`
Processa `suspects_raw.txt`, filtra apenas `action="dropped"`, aplica TTL e atualiza o `blocklist.txt` de forma segura — sem sobrescrever o arquivo antigo.  
Mescla IPs válidos existentes com novos IPs detectados.  
Registra todas as ações (inclusão, renovação, exclusão) nos arquivos de auditoria.

### `enrich_and_decide.py` *(opcional)*
Etapa adicional em Python para enriquecer e validar IPs contra serviços externos (como AbuseIPDB).  
Mantém cache local e respeita limites diários de requisição.  
Pode ser executado entre o `extract` e o `publish` para validar IPs antes da inclusão.

---

## ⚡ Instalação

1. Instalar dependências:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip nginx jq
   sudo mkdir -p /opt/auto-block/{scripts,logs,db}
   sudo mkdir -p /var/www/html/blocklist
   sudo chown -R $USER:$USER /opt/auto-block /var/www/html/blocklist
   ```

2. Copiar os scripts para `/opt/auto-block/scripts/` e tornar executáveis:
   ```bash
   sudo chmod +x /opt/auto-block/scripts/*.sh
   ```

3. Configurar o Nginx:
   ```nginx
   server {
       listen 80;
       server_name _;
       location /blocklist/ {
           alias /var/www/html/blocklist/;
           add_header Cache-Control "no-cache, no-store, must-revalidate";
       }
   }
   ```

4. (Opcional) Automatizar com Systemd:
   ```ini
   [Unit]
   Description=Auto Block - extract and publish
   After=network.target

   [Service]
   Type=oneshot
   User=SEU_USUARIO
   ExecStart=/bin/bash -lc '/opt/auto-block/scripts/extract_suspects.sh && /opt/auto-block/scripts/publish_blocklist.sh'
   ```

   Timer (`auto-block.timer`):
   ```ini
   [Timer]
   OnBootSec=1min
   OnUnitActiveSec=1min
   [Install]
   WantedBy=timers.target
   ```

---

## ▶️ Uso

Executar manualmente:
```bash
/opt/auto-block/scripts/extract_suspects.sh
/opt/auto-block/scripts/publish_blocklist.sh
```

Verificar lista publicada:
```bash
curl http://SEU_SERVIDOR/blocklist/blocklist.txt
```

Auditar logs:
```bash
less /opt/auto-block/logs/block_audit.csv
less /opt/auto-block/logs/pending_blocklist_with_meta.txt
```

---

## 🔐 Integração opcional: `enrich_and_decide.py`

- **Função:** validar e enriquecer IPs (score, país, relatórios).  
- **Integração:** inserir entre `extract` e `publish`.  
- **Vantagem:** reduz falsos positivos e melhora precisão.  
- **Desvantagem:** depende de APIs externas e possui limitação diária.  

Exemplo de pipeline:
```bash
/opt/auto-block/scripts/extract_suspects.sh
python3 /opt/auto-block/scripts/enrich_and_decide.py
/opt/auto-block/scripts/publish_blocklist.sh
```

---

## ⚙️ Configuração (variáveis e TTL)
Arquivo `/etc/auto-block.env`:

```
TTL_SECONDS=3600          # tempo de vida (1h)
MIN_SCORE=30              # usado pelo enrich (se ativado)
MAX_DAILY_CHECKS=1000     # limite diário da API (opcional)
ABUSEIPDB_KEY=chave_aqui  # se usar enrich
```

---

## 🧱 Boas práticas e recomendações

- Teste em ambiente de homologação antes de produção.  
- Comece com TTL curto (10 a 30 minutos).  
- Monitore `block_audit.csv` nas primeiras semanas.  
- Faça backups regulares dos logs e listas.  
- Não confie apenas nesse método para mitigação de DDoS volumétrico — combine com mitigação no ISP/CDN.  
- Mantenha logs e auditorias centralizados (ex.: Wazuh, Grafana, Loki).  

---

## 💡 Exemplo de contribuição e melhorias futuras

- Implementar API REST para revisão manual dos IPs.  
- Adicionar métricas e dashboards (IPs por hora, países, etc.).  
- Integrar com MISP, Wazuh ou FortiSOAR para playbooks automatizados.  
- Implementar rollback de bloqueios e alerta via Telegram/Slack.  

---

## 📜 Licença / Créditos

Projeto desenvolvido por **Lucas Eziquiel**  
💼 Profissional de Infraestrutura e Segurança • entusiasta de automação e observabilidade  

Este PoC é de uso livre para estudo e aprimoramento de processos de segurança de rede.  
Contribuições, melhorias e forks são bem-vindos.
