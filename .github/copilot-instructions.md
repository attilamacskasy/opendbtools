# OpenDBTools - Copilot Instructions

## Project Overview
OpenDBTools is an interactive PowerShell-based database backup and restore toolkit, starting with Microsoft SQL Server Express Edition support. The tool provides user-friendly database operations with intelligent authentication fallback and standardized logging.

## Core Design Principles
- **Interactive PowerShell script**: User-driven menu system for backup/restore operations
- **Smart authentication**: Windows Authentication (Kerberos) first, fallback to SQL Authentication with prompts
- **Configuration-driven**: JSON config file stores default paths, settings, and preferences
- **Cross-server capable**: Backup on one server, restore on another with same tool
- **Standardized logging**: Integrates with existing logging library from OpenIDSync project

## Project Structure
```
├── OpenDBTools.ps1           # Main interactive script
├── config.json               # Configuration file with defaults
├── modules/
│   ├── SqlServerModule.ps1   # SQL Server backup/restore functions
│   ├── AuthModule.ps1        # Authentication handling
│   └── LoggingModule.ps1     # Logging integration (from OpenIDSync)
└── README.md
```

## Development Patterns
- **Interactive menus**: Use numbered options (1, 2, 3...) and "*" for "all" selections
- **Authentication flow**: Try Windows Auth first, prompt for SQL Auth on failure
- **Database listing**: Show user databases only, exclude system DBs by default
- **Cross-server support**: Same script works for backup source and restore destination
- **Logging integration**: Use OpenIDSync logging patterns for consistency across projects

## Configuration (config.json)
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
```powershell
# Start the interactive script
.\OpenDBTools.ps1

# User selects: 1) Backup or 2) Restore
# Script discovers SQL instances and databases
# User selects databases (1, 2, 3 or * for all)
# Operations execute with progress feedback
```

## SQL Server Implementation Details
- **Connection**: Use `Invoke-Sqlcmd` PowerShell module for database operations
- **Authentication**: Windows Authentication via current user context, fallback to SQL Authentication
- **Backup commands**: Generate T-SQL BACKUP DATABASE statements with compression
- **Instance discovery**: Query WMI or registry for SQL Server instances
- **Database enumeration**: Exclude system databases (master, model, msdb, tempdb) unless explicitly requested

## Security & Best Practices
- **Credential handling**: Prompt for SQL Auth credentials, don't store in config
- **File permissions**: Ensure backup locations are accessible to SQL Server service account  
- **Validation**: Verify backup file integrity after creation
- **Error handling**: Use structured logging with correlation IDs for troubleshooting
- **Cross-platform**: Support UNC paths for network backup storage (NAS/file shares)