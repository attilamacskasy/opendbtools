# OpenDBTools

Interactive PowerShell toolkit for database backup and restore operations, starting with Microsoft SQL Server Express Edition support.

## Overview

OpenDBTools provides a user-friendly command-line interface for database backup and restore operations. The tool intelligently handles authentication (Windows Auth first, SQL Auth fallback) and provides cross-server compatibility for disaster recovery scenarios.

## Key Features

- **Interactive Menu System**: Simple numbered choices for database selection
- **Smart Authentication**: Automatic Windows Authentication with SQL Auth fallback
- **Cross-Server Support**: Backup on one server, restore on another
- **Flexible Storage**: Support for local disk and remote UNC paths (NAS/file shares)
- **Standardized Logging**: Integration with OpenIDSync logging library
- **Configuration-Driven**: JSON config file for default settings

## Quick Start

```powershell
# Clone and run
git clone https://github.com/attilamacskasy/opendbtools.git
cd opendbtools
.\OpenDBTools.ps1
```

## Configuration

Create `config.json` with your default settings:

```json
{
  "defaultSqlInstance": "localhost\\SQLEXPRESS",
  "backupPaths": {
    "local": "C:\\Backups\\",
    "remote": "\\\\nas\\backups\\sql\\"
  },
  "excludeSystemDbs": true,
  "logging": {
    "level": "Information", 
    "logPath": "logs\\opendbtools.log"
  }
}
```

## Usage Flow

1. **Start**: Run `.\OpenDBTools.ps1`
2. **Choose Operation**: Select Backup or Restore
3. **Select Instance**: Choose SQL Server instance (or use default)
4. **Select Databases**: Pick individual databases (1, 2, 3...) or all (*)
5. **Execute**: Operations run with progress feedback and logging

## Requirements

- PowerShell 5.1 or higher
- SQL Server Express Edition (latest version)
- SqlServer PowerShell module (`Install-Module -Name SqlServer`)
- Appropriate database permissions (backup operator role minimum)

## Roadmap

- Phase 1: SQL Server Express Edition support ✅ (Current)
- Phase 2: Oracle XE support
- Phase 3: Advanced scheduling and automation features
