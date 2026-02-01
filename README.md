# Tinman OpenClaw Eval

Security evaluation harness for OpenClaw agents. Powered by [Tinman](https://github.com/oliveskin/Agent-Tinman).

## Features

- **270+ attack probes** across 13 categories
- **Synthetic Gateway** for isolated testing
- **CI integration** via SARIF, JUnit, and JSON outputs
- **Baseline assertions** for regression testing
- **Real-time monitoring** via Gateway WebSocket

## Attack Categories

| Category | Probes | Description |
|----------|--------|-------------|
| **Prompt Injection** | 15 | Jailbreaks, DAN, instruction override, prompt leaking |
| **Tool Exfiltration** | 42 | SSH keys, cloud creds, supply-chain tokens, crypto wallets |
| **Context Bleed** | 14 | Cross-session leaks, memory extraction |
| **Privilege Escalation** | 15 | Sandbox escape, elevation bypass |
| **Supply Chain** | 18 | Malicious skills, dependency attacks |
| **Financial** | 26 | Crypto wallets (BTC, ETH, SOL, Base), transactions, exchange APIs |
| **Unauthorized Action** | 28 | Actions without consent, implicit execution |
| **MCP Attacks** | 20 | MCP tool abuse, server injection, cross-MCP exfil |
| **Indirect Injection** | 20 | Injection via files, URLs, documents, configs |
| **Evasion Bypass** | 30 | Unicode bypass, URL/base64/hex encoding, shell injection |
| **Memory Poisoning** | 25 | Context injection, RAG poisoning, history fabrication |
| **Platform Specific** | 35 | Windows (mimikatz, schtasks, PowerShell), macOS (LaunchAgents), Linux (systemd), cloud metadata |

## Installation

```bash
pip install tinman-openclaw-eval
```

Or from source:

```bash
git clone https://github.com/oliveskin/tinman-openclaw-eval
cd tinman-openclaw-eval
pip install -e ".[dev]"
```

## Quick Start

```bash
# Run all attacks (mock gateway)
tinman-eval run

# Run specific category
tinman-eval run -c prompt_injection
tinman-eval run -c financial
tinman-eval run -c evasion_bypass

# Run only high severity (S3+)
tinman-eval run -s S3

# Save report
tinman-eval run -o report.md

# List all attacks
tinman-eval list-attacks

# Run single attack
tinman-eval run-single PI-001 -v
```

## CI Integration

### GitHub Actions

```yaml
name: Security Eval
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - run: pip install tinman-openclaw-eval

      - name: Run security evaluation
        run: |
          tinman-eval run \
            --output security-report.json \
            --format json

      - name: Assert baseline
        run: |
          tinman-eval assert \
            security-report.json \
            --baseline expected/baseline.json

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: security-report.sarif
        if: always()
```

### Generate Baseline

```bash
# Create initial baseline
tinman-eval baseline --output expected/baseline.json

# Update after intentional changes
tinman-eval run -o new-results.json
# Review and approve
mv new-results.json expected/baseline.json
```

## Output Formats

| Format | Use Case |
|--------|----------|
| `markdown` | Human-readable reports |
| `json` | Programmatic analysis |
| `sarif` | GitHub Code Scanning |
| `junit` | CI test results |

## Custom Attacks

Add YAML files to `attacks/` directory:

```yaml
# attacks/custom.yaml
attacks:
  - id: CUSTOM-001
    name: "My custom attack"
    severity: S2
    payload: "Custom attack payload..."
    target: dm_channel
    expected_behavior: rejected_by_soul
    tags:
      - custom
```

## Programmatic Usage

```python
import asyncio
from tinman_openclaw_eval import EvalHarness, AttackCategory

async def main():
    harness = EvalHarness()

    # Run all attacks
    result = await harness.run()

    # Check for vulnerabilities
    print(f"Vulnerabilities: {result.vulnerabilities}")

    # Run specific categories
    result = await harness.run(categories=[
        AttackCategory.PROMPT_INJECTION,
        AttackCategory.FINANCIAL_TRANSACTION,
        AttackCategory.EVASION_BYPASS,
    ])

    # Run high severity only
    result = await harness.run(min_severity="S3")

asyncio.run(main())
```

## Testing Against Real Gateway

```bash
# Connect to local OpenClaw Gateway
tinman-eval run --no-mock --gateway-url ws://127.0.0.1:18789

# With custom config
tinman-eval run --no-mock --gateway-url ws://192.168.1.100:18789
```

## Attack Probe IDs

| Prefix | Category |
|--------|----------|
| `PI-*` | Prompt Injection |
| `TE-*` | Tool Exfiltration |
| `CB-*` | Context Bleed |
| `PE-*` | Privilege Escalation |
| `SC-*` | Supply Chain |
| `FT-*` | Financial Transaction |
| `UA-*` | Unauthorized Action |
| `MCP-*` | MCP Attacks |
| `II-*` | Indirect Injection |
| `EB-*` | Evasion Bypass |
| `MP-*` | Memory Poisoning |
| `PS-*` | Platform Specific |

## Severity Levels

| Level | Description | Action |
|-------|-------------|--------|
| **S4** | Critical | Immediate fix required |
| **S3** | High | Fix before deploy |
| **S2** | Medium | Review recommended |
| **S1** | Low | Monitor |
| **S0** | Info | Observation only |

## Integration with OpenClaw Skill

For continuous monitoring in OpenClaw, use the [Tinman Skill](https://github.com/oliveskin/openclaw-skill-tinman):

```bash
# In OpenClaw
/tinman sweep                    # Run security sweep
/tinman sweep --category financial
/tinman watch                    # Real-time monitoring
```

## Links

- [Tinman](https://github.com/oliveskin/Agent-Tinman) - AI Failure Mode Research
- [Tinman Skill](https://github.com/oliveskin/openclaw-skill-tinman) - OpenClaw Integration
- [OpenClaw](https://github.com/openclaw/openclaw) - Personal AI Assistant

## License

Apache-2.0
