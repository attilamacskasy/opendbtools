# OpenDBTools – Copilot Instructions

## Mission
Build an interactive PowerShell tool to backup and restore Microsoft SQL Server databases (start with SQL Server Express, latest). It must prefer Windows/Kerberos authentication and fall back to SQL Auth (sa/username+password). It stores defaults in a JSON config, integrates the exact OpenIDSync logging module, and supports cross‑server restores. On startup, ask: "What do you want to do today? Backup or Restore?"

## Core behaviors
- Interactive UX with numeric menus (1, 2, 3…) and support for "*" to select all databases
- Instance detection should be fast and robust: query running services/registry first; optionally WMI/SqlServer module
- Authentication: try Windows Auth first; if connect fails, prompt for SQL Auth credentials; exit on repeated failure
- Database list: show only user DBs by default; ask to include system DBs (default: no)
- Config cache: persist defaults and last choices in `config.json`; offer reuse/update; avoid re-detection when unchanged
- Backup naming: `[servername]-[dbinstancename]-[databasename]-[timestamp].bak` with timestamp `yyyyMMddTHHmmss`
- Restore discovery: scan known locations from config; parse filenames; show readable table (Server, Instance, DB, Timestamp), newest first
- Cross-server restore: allow choosing a different server/instance than backup origin
- Logging: use `50_OpenIDSync_Logging.ps1` unchanged; log to console and file with INFO/WARN/ERROR/PROMPT/ACTION/RESULT/DEBUG
- Failure policy: on any critical failure, write detailed log and exit

## Project structure (target)
```
OpenDBTools.ps1                # Main interactive script (entry point)
config.json                    # Configuration cache and defaults
modules/
  AuthModule.ps1               # Instance discovery, authentication helpers
  SqlServerModule.ps1          # DB list, backup, restore (uses Invoke-Sqlcmd)
  50_OpenIDSync_Logging.ps1    # Copied verbatim from OpenIDSync (do not modify)
README.md
```

## Config contract (config.json)
- defaultSqlInstance: string (e.g., "localhost\\SQLEXPRESS")
- backupPaths: { local: string, remote: string }
- knownBackupLocations: string[]
- excludeSystemDbs: bool (default true)
- logging: { level: string, logPath: string }
- modulesChecked: { SqlServer: bool }
- lastUsedSettings: { sqlInstance: string, operation: string, backupLocation: "local"|"remote" }

Behavior:
- On first run, create missing keys with sensible defaults; prompt to fill blanks.
- After checking/installing required modules (SqlServer), set `modulesChecked.SqlServer = true`.

## Implementation notes
- Use `Invoke-Sqlcmd` from the SqlServer module for queries and backup/restore T-SQL
- Instance detection: prefer reading `HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL` and/or service names like `MSSQL$<Instance>`; cache result
- Exclude system DBs unless explicitly requested (master, model, msdb, tempdb)
- Backup with compression; ensure SQL service account can access target paths
- Parse backup filenames for restore list; sort by timestamp desc
- Always write clear ACTION/RESULT/ERROR logs; include key context in `-Data` hashtables for structured logging

## Startup flow
1) Initialize logging (file path from config)
2) Ensure SqlServer module exists; install if missing; update config
3) Load or detect SQL instance(s); present choices (use cache if available)
4) Ask: Backup or Restore
5) Authenticate: try Windows; fallback to SQL Auth prompt
6) Execute chosen operation with progress and validation

## Security
- Never store SQL passwords in config; only collect via `Get-Credential`
- Validate path access and fail fast with actionable logs

## Definition of done (MVP)
- Scripts run locally on a SQL Server machine
- Backup: select DB(s) by index or `*`, create `.bak` with naming convention in local/remote paths
- Restore: detect `.bak` files, parse metadata, present newest-first table, restore selected DB to chosen instance
- Logging module is copied unchanged
- On failure, log and exit