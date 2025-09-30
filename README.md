# OpenDBTools

Interactive PowerShell toolkit to back up and restore Microsoft SQL Server, starting with SQL Server Express (latest). It’s interactive, config‑driven, prefers Kerberos/Windows auth, falls back to SQL Auth, uses standardized logging, and supports cross‑server restores.

## Highlights

- Fast instance detection via registry + services; caches your choice in config
- Kerberos/Windows first, then SQL Auth fallback with secure credential prompt
- Numeric menus for DB selection; enter 1,2,3 or * for all
- Local‑first backups, optional remote copy after success (robust vs. UNC writes)
- Express‑safe backups: auto‑detect edition and omit COMPRESSION on Express
- Preflight write test: verifies the SQL Engine can write to the local folder before backup
- One‑click NTFS fix: prompt to grant Modify to the SQL service account (icacls) when needed
- Parseable filenames and a readable restore picker (newest-first)
- Cross‑server restore support
- Structured logging via the OpenIDSync logger (unchanged)
- Config.json cache for defaults, choices, and known locations

## How backups work (local-first + optional remote copy)

1) Pick DB(s) by number or *.
2) Choose/confirm a local backup folder (relative paths resolve under the script folder).
3) Preflight: the tool performs a tiny COPY_ONLY test backup of master to that folder to ensure the SQL Server service account has write access.
   - If it fails, the tool:
     - Shows the SQL service account (e.g., NT SERVICE\MSSQL$SQLEXPRESS) and the OS error
     - Suggests SQL’s default backup directory
     - Offers a one‑click “Grant permissions” (icacls) fix, then retests
4) Actual backups run to the local folder with edition‑aware options (no COMPRESSION on Express).
5) If you choose, completed .bak files are copied to a remote folder (UNC or other path) after local success.

Why local-first? It avoids SQL Server writing directly to UNC shares and improves reliability; copying from the filesystem is simpler and gives clearer errors.

## NTFS permissions and icacls (what the tool does and why)

SQL Server writes .bak files using the SQL Engine service account, not your interactive Windows user—being sysadmin in SQL doesn’t grant NTFS rights. If the service account lacks Modify on your target folder, backups fail with operating system error 5 (Access is denied).

When the preflight test detects this:
- The tool logs the exact service account and the failing path
- It offers to run this command (with your confirmation) and logs the result:

    icacls "<folder>" /grant "<account>:(OI)(CI)M" /T

- (OI)(CI) applies inheritance to files and subfolders; M is Modify. After granting, the tool retries the preflight and proceeds when it succeeds.

If you don’t want the tool to grant rights, select SQL’s default backup folder or any other path where the service account already has Modify.

## Edition detection and COMPRESSION

We detect the engine edition via SERVERPROPERTY('EngineEdition') and 'Edition'. If EngineEdition = 4 (Express), BACKUP … WITH COMPRESSION is not supported, so we omit COMPRESSION automatically. On higher editions, COMPRESSION is used by default.

## Backup filename format

    [servername]-[dbinstancename]-[databasename]-[yyyyMMddTHHmmss].bak

Example:

    WIN-D6GFGMD22C5-SQLEXPRESS-SalesDB-20250930T231015.bak

These filenames are parsed for the restore picker, which shows newest‑first with columns: Server, Instance, Database, Timestamp.

## Authentication flow (and identity diagnostics)

1) Try Windows Auth (Kerberos) to the chosen instance.
2) If it fails, prompt for SQL Auth (e.g., sa) using Get‑Credential.
3) On success, we log who SQL thinks you are (SUSER_SNAME, ORIGINAL_LOGIN, sysadmin flag, and role memberships) for transparent debugging.
4) If both fail, the tool logs the error and exits (fail‑fast).

## Configuration (config.json)

Key settings the tool maintains:

- defaultSqlInstance: string (e.g., "localhost\\SQLEXPRESS")
- backupPaths: { local: string, remote: string }
- knownBackupLocations: string[]
- excludeSystemDbs: bool (default true)
- logging: { level: string, logPath: string }
- modulesChecked: { SqlServer: bool }
- lastUsedSettings: { sqlInstance: string, operation: string, backupLocation: "local"|"remote" }

Behavior:
- On first run, missing keys are created with sensible defaults (e.g., local="backup").
- The SqlServer module check/install is performed once and cached (modulesChecked.SqlServer=true).
- Relative folders (like "backup") are resolved under the script folder after your confirmation.

## Usage

```powershell
# Run on the SQL Server host (PowerShell 5.1)
git clone https://github.com/attilamacskasy/opendbtools.git
cd opendbtools
./OpenDBTools.ps1
```

Flow:
1) Instance detection -> pick one
2) Backup or Restore
3) Auth (Windows first, then SQL Auth)
4) Backup: choose DBs; confirm local folder; preflight; optional remote copy; watch progress and results
5) Restore: pick a backup from the newest‑first list; optionally choose a different target instance; restore

## Requirements

- Windows PowerShell 5.1+
- SQL Server Express (or higher) installed on the host
- PowerShell SqlServer module (the tool checks/installs if missing)
- NTFS Modify permissions for the SQL Engine service account on your backup folder

## Logging

- Uses the exact `modules/50_OpenIDSync_Logging.ps1` from OpenIDSync, unmodified
- Console + file logging with structured levels: INFO, WARN, ERROR, PROMPT, ACTION, RESULT, DEBUG
- Logs include context (instance, auth mode, service account, command snippets) for fast troubleshooting

## Failure policy (MVP)

- On critical failures (module install, auth, backup, restore), the tool logs details and exits. Fix the issue (often NTFS rights) and re‑run.

## What’s implemented (MVP)

- Instance detection, auth fallback, identity diagnostics
- DB listing with numeric menus and * for all
- Local‑first backups, edition‑aware options (Express‑safe), optional remote copies
- Restore with newest‑first picker and cross‑server targeting
- Config cache + known backup locations
- Robust logging with structured context

## What’s next

- Restore WITH MOVE planner (file relocation) for cross‑server restores
- Optional robocopy for remote copies (retries, resume, logs)
- Optional cleanup of local .bak after successful remote copy

## The build journey (human + AI, iterative and efficient)

This project came together through tight collaboration between domain expertise and an AI agent:

- We started from a clear MVP spec focusing on SQL Server Express, Windows‑first auth, and the OpenIDSync logging module.
- Iterated quickly on real‑world hurdles: module availability, PowerShell 5.1 parsing quirks, instance aliasing, SQL Auth fallback, and JSON config evolution.
- Hardened authentication by probing multiple provider aliases (original name, tcp, localhost, named pipes) and always using the resolved instance alias thereafter.
- Eliminated common pitfalls with arrays and interactive prompts; ensured reliable menus and selections.
- Solved the classic backup blocker—NTFS permissions—from the SQL Engine’s perspective with a preflight test and an optional one‑click icacls grant, with full transparency and logging.
- Switched to local‑first backups and added an optional remote copy to avoid SQL writing directly to UNC shares.
- Made backups Express‑safe by detecting edition and omitting COMPRESSION where unsupported.

Each iteration tightened UX, reliability, and observability, turning field issues into guided, actionable prompts. The result is a pragmatic tool that “just works” on real servers and tells you exactly what to fix when it can’t.
