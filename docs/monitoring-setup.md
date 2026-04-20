# Monitoring Setup

Paramant uses Prometheus + Grafana for infrastructure metrics. This document covers installation and configuration.

## Prerequisites

- Docker and Docker Compose installed
- Paramant relay stack running (`docker compose up -d`)

## Quick Start

```bash
# Install node_exporter for host metrics
apt-get install -y prometheus-node-exporter

# Run Prometheus with the bundled config
docker run -d \
  --name prometheus \
  --network host \
  -v /opt/paramant-relay/monitoring/prometheus.yml:/etc/prometheus/prometheus.yml:ro \
  prom/prometheus:latest

# Run Grafana
docker run -d \
  --name grafana \
  --network host \
  -e GF_SECURITY_ADMIN_PASSWORD=changeme \
  grafana/grafana:latest
```

Prometheus UI: http://localhost:9090
Grafana UI: http://localhost:3000 (default admin/changeme — change immediately)

## Scrape Targets

| Job | Target | Notes |
|-----|--------|-------|
| paramant-admin | :4200/metrics | Admin API server |
| paramant-relay-main | :3000/metrics | Main relay |
| paramant-relay-health | :3001/metrics | Health sector relay |
| paramant-relay-finance | :3002/metrics | Finance sector relay |
| paramant-relay-legal | :3003/metrics | Legal sector relay |
| paramant-relay-iot | :3004/metrics | IoT sector relay |
| node-exporter | :9100/metrics | Host CPU/mem/disk |

## Key Metrics to Watch

- `http_request_duration_seconds` — p95 latency per endpoint
- `http_requests_total` — request rate and error rate (5xx)
- `process_resident_memory_bytes` — container memory
- `node_cpu_seconds_total` — host CPU utilization
- `node_filesystem_avail_bytes` — disk space remaining

## Alerts (recommended)

```yaml
# Add to prometheus.yml under rule_files:
rule_files:
  - /etc/prometheus/alerts.yml
```

Suggested thresholds:
- p95 latency > 500ms for 5m
- Error rate (5xx) > 1% for 2m
- Disk < 10% free
- Memory > 85% for 10m

## UFW Rules

If UFW is active, allow Prometheus to scrape (localhost only — no external exposure needed):

```bash
# node_exporter — bind to localhost only at install time
# or add: ufw allow in on lo
```

Prometheus and Grafana should NOT be exposed on public interfaces. Use SSH tunneling or Tailscale for remote access.
