# CapstoneAIRuntimeFirewall

**Capstone — AI Agent Firewall**

## Architecture

<img width="1198" alt="AI Agent Firewall architecture diagram" src="https://github.com/user-attachments/assets/dab263d3-1586-4135-955c-e25b747f7f6a" />

The project uses **LiteLLM** as a proxy for a local **Ollama (Llama 3.1)** model. A custom Python guardrail inspects incoming prompts and outgoing model responses. **Prometheus** collects metrics, and **Grafana** can be used to view them.

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) with Docker Compose (start Docker Desktop before running commands)
- [Python 3](https://www.python.org/downloads/) on Windows to run the HTTP tests

## Project files

The project folder should include:

```text
firewall/
├── docker-compose.yml
├── Dockerfile
├── litellm_config.yaml
├── custom_guardrail.py
├── prometheus.yml
├── test_attack.py
├── test_output.py
└── README.md
```

`test_output.py` is the separate controlled-output test script. Make sure it is included in the shared repository/ZIP; it is needed for G17–G19.

## 1. Start Docker

Open **PowerShell** in the folder containing `docker-compose.yml`:

```powershell
docker compose up -d --build
docker compose ps
```

Confirm that the **LiteLLM**, **Ollama**, and **Prometheus** services are running. Grafana is optional for testing the guardrails.

> The first build downloads the LiteLLM image and installs security-scanning packages; it may take longer than later starts.

### Check the Ollama model

```powershell
docker exec ollama ollama list
```

If `llama3.1` is missing:

```powershell
docker exec ollama ollama pull llama3.1
```

The LiteLLM model alias used for requests is **`customer-service-agent`**. Its mapping to Ollama is defined in `litellm_config.yaml`.

## 2. Talk to the model

Send a message through **LiteLLM** so the custom guardrails can inspect it. In PowerShell:

```powershell
$body = @{
    model = "customer-service-agent"
    messages = @(
        @{ role = "user"; content = "What is your refund policy?" }
    )
    max_tokens = 100
} | ConvertTo-Json -Depth 6

$response = Invoke-RestMethod `
    -Uri "http://localhost:4000/v1/chat/completions" `
    -Method Post `
    -ContentType "application/json" `
    -Body $body

$response.choices[0].message.content
```

To ask something else, replace the `content` text and rerun the commands. A normal prompt should return an answer. A blocked input may instead produce an HTTP error containing a **`Security Alert`** message.

**If your LiteLLM configuration requires an API key**, add the configured key as a header (do not commit real keys):

```powershell
$headers = @{ Authorization = "Bearer YOUR_CONFIGURED_KEY" }
```

Add `-Headers $headers` to `Invoke-RestMethod`.

## 3. Run the guardrail tests

### Input / API tests — G01–G16

From the project folder:

```powershell
python -m pip install requests
python test_attack.py
```

The script sends requests through `http://localhost:4000/v1/chat/completions`, compares the actual behavior with the expected `ALLOW` or `BLOCK` result, shows response times, and writes **`test_results.json`**.

Test areas include normal customer questions, prompt injections, system-prompt extraction attempts, administrator impersonation, synthetic credentials, invisible characters, and token limits.

A `500` response **by itself** is not proof of a security block. The current test script checks for a `Security Alert` as well.

### Controlled output tests — G17–G19

These tests check the **actual output guardrail hook** with simulated AI responses containing synthetic sensitive data. They deliberately bypass input scanning so an input rejection cannot be mistaken for successful output protection.

```powershell
docker cp test_output.py litellm_proxy:/app/test_output.py
docker exec litellm_proxy python /app/test_output.py
```

They check that responses containing an **email address**, **credit card number**, or **SSN** are blocked/replaced with the configured security warning. A passing run should show **3/3 passed**.

> **Reporting:** There are **16 end-to-end HTTP/API tests** and **3 controlled output tests**. The output tests do not exercise the entire HTTP request/response path. Record them separately in the final project report. `test_results.json` from the main script covers G01–G16.

If the LiteLLM container is rebuilt or recreated, copy `test_output.py` into it again before running these tests.

## 4. Logs and monitoring

### View LiteLLM logs

```powershell
docker compose logs --tail=100 litellm-proxy
```

If your `custom_guardrail.py` includes the Sprint 4 `SECURITY EVENT` log statements, view only those decisions:

```powershell
docker compose logs --tail=300 litellm-proxy | Select-String "SECURITY EVENT"
```

These statements show allowed or blocked requests and scanner reasons. Scanner logs may be present even if the additional event statements have not been added.

### Prometheus

- LiteLLM metrics: <http://localhost:4000/metrics/>
- Prometheus: <http://localhost:9090>

A `307` redirect from `/metrics` to `/metrics/` is normal. Confirm in Prometheus that the relevant target is being scraped before relying on a dashboard.

### Grafana Dashboard Setup (optional)

This project includes a Grafana dashboard for monitoring the AI Agent Firewall.

### Importing the Dashboard

1. Download `firewall_dashboard.json` from the GitHub repository.
2. Start Docker Desktop and run:
   ```powershell
   docker compose up -d
   ```
3. Open Grafana at `http://localhost:3000` (or the port configured for Grafana).
4. Go to **Connections → Data sources** and add Prometheus.
5. Set the Prometheus URL:
   - Windows Grafana: `http://localhost:9090`
   - Docker Grafana: `http://prometheus:9090`
6. Click **Save & test** to verify the connection.
7. Go to **Dashboards → New → Import**.
8. Upload `firewall_dashboard.json`.
9. Select the Prometheus data source and click **Import**.

### Viewing Metrics

Run the security tests to generate activity:

```powershell
python test_attack.py
```

Refresh the dashboard to view firewall status, guardrail activity, errors, and processing times.

**Note:** The dashboard JSON contains the panel configurations, not saved monitoring data. Each user must connect Grafana to a running Prometheus instance.

## 5. Troubleshooting

| Problem | Suggested check |
| --- | --- |
| Docker service is not running | `docker compose ps`; check `docker compose logs --tail=100 litellm-proxy` |
| `llama3.1` is missing | `docker exec ollama ollama list`; then `docker exec ollama ollama pull llama3.1` |
| Cannot connect to port 4000 | Verify the LiteLLM container is running and port `4000` is published |
| Grafana cannot bind port 3000 | `netstat -ano \| findstr :3000`; use the existing Grafana process or map Docker Grafana to port 3001 |
| Output tests fail after rebuilding | Copy `test_output.py` into `litellm_proxy` again; confirm current guardrail code was rebuilt |
| Docker Compose warns that `version` is obsolete | The warning is not a build failure; remove the top-level `version:` property when convenient |
| Guardrail Python code changes | Rebuild with `docker compose up -d --build litellm-proxy`, then rerun tests |

### Useful Docker commands

```powershell
# See running services
docker compose ps

# Start or rebuild services
docker compose up -d --build

# Rebuild only LiteLLM after editing its guardrail
docker compose up -d --build litellm-proxy

# Stop the Compose services
docker compose down
```

Avoid `docker compose down -v` unless you intentionally want to delete Compose-managed volumes and their stored data.

## 6. Final project demonstration

1. Show `docker compose ps` to confirm the core services are running.
2. Send a harmless customer request to `customer-service-agent` through LiteLLM.
3. Run `python test_attack.py` and show the G01–G16 results plus `test_results.json`.
4. Run `test_output.py` inside the LiteLLM container and show G17–G19.
5. Show guardrail logs and, if configured, Prometheus/Grafana monitoring.

## Resources

### LLM Guard — Code, Examples, and Documentation
- [LiteLLM custom guardrail documentation](https://litellm.docs.miniasp.com/en/docs/proxy/guardrails/custom_guardrail/)
- [LLM Guard documentation](https://therizwan.github.io/llm-guard/docs/guards/)
- [LLM Guard quickstart](https://github.com/protectai/llm-guard/blob/main/docs/get_started/quickstart.md)

### Regular Expressions (RegEx)
- [Python RegEx reference — W3Schools](https://www.w3schools.com/python/python_regex.asp)

### LiteLLM
- [LiteLLM documentation](https://docs.litellm.ai/docs/)

### Grafana and Prometheus — Dashboards and Metrics
- [Grafana OSS download for Windows](https://grafana.com/grafana/download?edition=oss&platform=windows)
- [Local Grafana login (available when running)](http://localhost:3000/login)
- [Prometheus configuration documentation](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [Grafana Prometheus data source](https://grafana.com/docs/grafana/latest/datasources/prometheus/)
- [Grafana Prometheus troubleshooting](https://grafana.com/docs/grafana/latest/datasources/prometheus/troubleshooting/)

### Docker
- [Docker Compose getting started](https://docs.docker.com/compose/gettingstarted/)
- [Docker Compose command reference](https://docs.docker.com/reference/cli/docker/compose/)
