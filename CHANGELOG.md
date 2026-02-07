# Changelog

All notable changes to this project will be documented in this file.

## [0.3.2] - 2026-02-07

### Fixed
- Load the full attack suite in the harness (including evasion, memory poisoning, and platform-specific modules).
- Dispatch attacks by payload ID (stable) instead of by category.
- Create per-payload sessions to respect targeting semantics (`dm_channel`, `group_channel`, `elevated_session`).
- Improve category parsing with common aliases (e.g. `financial`, `mcp_attacks`, `supplychain`, `platform`).

### Changed
- Ruff linting now ignores long payload-string lines (`E501`) only inside `src/tinman_openclaw_eval/attacks/*.py`.
- Internal codebase lint/format cleanup (Ruff).

## [0.3.1] - 2026-02-01

### Fixed
- Obfuscated security-sensitive strings in platform_specific.py to prevent AV false positives

## [0.3.0] - 2026-02-01

### Added
- **Evasion Bypass** attacks (30 probes): Unicode bypass, URL/base64/hex encoding, shell injection
- **Memory Poisoning** attacks (25 probes): Context injection, RAG poisoning, history fabrication
- **Platform Specific** attacks (35 probes): Windows (mimikatz, schtasks, PowerShell, AMSI bypass), macOS (LaunchAgents, keychain), Linux (systemd, cron), cloud metadata

### Changed
- Total attack probes increased from 180 to 270+
- Attack categories expanded from 10 to 13
- Updated README with new attack categories and probe IDs

## [0.2.0] - 2026-01-31

### Added
- **MCP Attacks** category (20 probes): Tool abuse, server injection, cross-MCP exfiltration
- **Indirect Injection** category (20 probes): Injection via files, URLs, documents

## [0.1.2] - 2026-01-30

### Added
- Financial transaction attacks (26 probes): Crypto wallets, exchange APIs
- Unauthorized action probes (28 probes)

## [0.1.1] - 2026-01-29

### Added
- Initial release
- Core attack categories: Prompt Injection, Tool Exfiltration, Context Bleed, Privilege Escalation, Supply Chain
- CLI with `tinman-eval run`, `list-attacks`, `run-single` commands
- Output formats: Markdown, JSON, SARIF, JUnit
- Baseline assertions for CI regression testing
- Synthetic Gateway for isolated testing
