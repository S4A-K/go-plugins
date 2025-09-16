# Library Configuration Hot Reload

## Overview

The Library Configuration system provides runtime configuration management for all library-level settings through Argus integration. This system allows you to modify logging levels, observability settings, default policies, security configuration, and environment variables without restarting your application.

The configuration system supports both centralized configuration (all settings in one file) and distributed configuration (separate files for different components like whitelist files) to accommodate various deployment scenarios.

## Table of Contents

1. [Key Features](#key-features)
2. [Architecture](#architecture)
3. [Configuration Structure](#configuration-structure)
4. [Getting Started](#getting-started)
5. [Configuration Options](#configuration-options)
6. [Security Configuration](#security-configuration)
7. [Environment Variables](#environment-variables)
8. [Hot Reload Workflow](#hot-reload-workflow)
9. [Security and Validation](#security-and-validation)
10. [Best Practices](#best-practices)
11. [Troubleshooting](#troubleshooting)
12. [API Reference](#api-reference)

## Key Features

- **Hot Reload**: Update configuration without application restart
- **Multi-Format Support**: JSON and YAML configuration files
- **Security Integration**: Comprehensive plugin authorization with multiple enforcement modes
- **Flexible Configuration**: Centralized or distributed security configuration approaches
- **Environment Variable Expansion**: Dynamic `${VAR}` syntax with security validation
- **Comprehensive Audit Trail**: Track all configuration changes and security events for compliance
- **Rollback on Failure**: Automatic rollback to previous configuration on validation errors
- **Thread-Safe**: Concurrent access with atomic operations
- **Performance Optimized**: Ultra-fast configuration application with 12.10ns/op
- **Validation**: Comprehensive configuration validation before application

## Architecture

The library configuration system is built on top of the existing Argus integration and consists of several key components:

```
┌─────────────────────────┐
│   Application Code      │
├─────────────────────────┤
│  LibraryConfigWatcher   │
├─────────────────────────┤
│     Argus Watcher       │
├─────────────────────────┤
│   Configuration File    │
│   (JSON/YAML)          │
└─────────────────────────┘
```

### Component Responsibilities

- **LibraryConfigWatcher**: Main orchestrator for configuration management
- **Argus Integration**: File watching and change detection
- **Environment Expander**: Secure expansion of environment variables
- **Configuration Validator**: Structure and business logic validation
- **Audit Logger**: Comprehensive audit trail for compliance

## Configuration Structure

The library configuration is organized into logical sections:

```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "structured": true,
    "include_caller": false,
    "include_stack_trace": false,
    "component_levels": {
      "manager": "debug",
      "health_checker": "warn"
    }
  },
  "observability": {
    "metrics_enabled": true,
    "metrics_interval": "30s",
    "tracing_enabled": false,
    "tracing_sample_rate": 0.1,
    "health_metrics_enabled": true,
    "performance_metrics_enabled": true
  },
  "default_policies": {
    "retry": {
      "max_retries": 3,
      "initial_interval": "100ms",
      "max_interval": "5s",
      "multiplier": 2.0,
      "random_jitter": true
    },
    "circuit_breaker": {
      "enabled": true,
      "failure_threshold": 5,
      "recovery_timeout": "30s",
      "min_request_threshold": 3,
      "success_threshold": 2
    },
    "health_check": {
      "enabled": true,
      "interval": "30s",
      "timeout": "10s",
      "failure_limit": 3,
      "endpoint": "/health"
    },
    "connection": {
      "max_connections": 10,
      "max_idle_connections": 5,
      "idle_timeout": "30s",
      "connection_timeout": "10s",
      "request_timeout": "30s",
      "keep_alive": true,
      "disable_compression": false
    },
    "rate_limit": {
      "enabled": false,
      "requests_per_second": 10.0,
      "burst_size": 20,
      "time_window": "1s"
    }
  },
  "security": {
    "enabled": true,
    "policy": 2,
    "whitelist_file": "/etc/go-plugins/whitelist.json",
    "auto_update": true,
    "hash_algorithm": "sha256",
    "validate_on_start": true,
    "max_file_size": 104857600,
    "allowed_types": [".so", ".dll", ".dylib"],
    "forbidden_paths": ["/tmp", "/var/tmp"],
    "audit": {
      "enabled": true,
      "audit_file": "/var/log/go-plugins/security.log",
      "log_unauthorized": true,
      "log_authorized": false,
      "log_config_changes": true
    },
    "watch_config": true,
    "reload_delay": "100ms"
  },
  "environment": {
    "expansion_enabled": true,
    "variable_prefix": "GO_PLUGINS_",
    "fail_on_missing": false,
    "overrides": {
      "metrics_port": "${GO_PLUGINS_METRICS_PORT}",
      "environment": "${GO_PLUGINS_ENV}",
      "log_level": "${GO_PLUGINS_LOG_LEVEL}"
    }
  },
  "performance": {
    "watcher_poll_interval": "10s",
    "cache_ttl": "5s",
    "max_concurrent_health_checks": 10
  },
  "metadata": {
    "version": "v1.0.0",
    "environment": "production",
    "last_modified": "2025-09-16T19:42:12Z"
  }
}
```

## Getting Started

### 1. Basic Setup

```go
package main

import (
    "context"
    "log"
    "time"

    goplugins "github.com/agilira/go-plugins"
)

func main() {
    // Create plugin manager
    manager := goplugins.NewManager[MyRequest, MyResponse]()
    
    // Create logger
    logger := log.New(os.Stdout, "[CONFIG] ", log.LstdFlags)
    
    // Configure library config watcher
    options := goplugins.LibraryConfigOptions{
        PollInterval:        5 * time.Second,
        CacheTTL:           2 * time.Second,
        EnableEnvExpansion: true,
        ValidateBeforeApply: true,
        RollbackOnFailure:  true,
        AuditConfig: goplugins.AuditConfig{
            Enabled:    true,
            OutputPath: "audit.log",
        },
    }
    
    // Create watcher
    watcher, err := goplugins.NewLibraryConfigWatcher(
        manager, 
        "library_config.json", 
        options, 
        logger,
    )
    if err != nil {
        log.Fatalf("Failed to create config watcher: %v", err)
    }
    
    // Start watching
    ctx := context.Background()
    if err := watcher.Start(ctx); err != nil {
        log.Fatalf("Failed to start config watcher: %v", err)
    }
    defer watcher.Stop()
    
    // Your application code here...
}
```

### 2. Configuration File

Create a `library_config.json` file:

```json
{
  "logging": {
    "level": "${GO_PLUGINS_LOG_LEVEL}",
    "format": "json",
    "structured": true
  },
  "observability": {
    "metrics_enabled": true,
    "metrics_interval": "30s"
  },
  "environment": {
    "expansion_enabled": true,
    "variable_prefix": "GO_PLUGINS_",
    "overrides": {
      "log_level": "${GO_PLUGINS_LOG_LEVEL}"
    }
  },
  "metadata": {
    "version": "v1.0.0",
    "environment": "development"
  }
}
```

### 3. Environment Variables

Set your environment variables:

```bash
export GO_PLUGINS_LOG_LEVEL=debug
export GO_PLUGINS_METRICS_PORT=8080
export GO_PLUGINS_ENV=development
```

## Configuration Options

### LibraryConfigOptions

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `PollInterval` | `time.Duration` | `10s` | File polling interval |
| `CacheTTL` | `time.Duration` | `5s` | Configuration cache TTL |
| `EnableEnvExpansion` | `bool` | `true` | Enable environment variable expansion |
| `ValidateBeforeApply` | `bool` | `true` | Validate configuration before applying |
| `RollbackOnFailure` | `bool` | `true` | Rollback on application failure |
| `AuditConfig` | `AuditConfig` | - | Audit logging configuration |

### AuditConfig

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable audit logging |
| `OutputPath` | `string` | `""` | Audit log file path |
| `MaxFileSize` | `int64` | `100MB` | Maximum log file size |
| `MaxBackups` | `int` | `5` | Maximum backup files |
| `MaxAge` | `int` | `30` | Maximum age in days |
| `Compress` | `bool` | `true` | Compress rotated files |

### SecurityConfig

The security configuration provides comprehensive plugin authorization and audit capabilities. It supports both centralized configuration (all settings in the main config file) and distributed configuration (separate whitelist files).

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `Enabled` | `bool` | `false` | Enable security validation |
| `Policy` | `SecurityPolicy` | `0` | Security enforcement mode (0=disabled, 1=permissive, 2=strict, 3=audit-only) |
| `WhitelistFile` | `string` | `""` | Path to separate whitelist file (optional) |
| `AutoUpdate` | `bool` | `false` | Auto-update whitelist from trusted sources |
| `HashAlgorithm` | `string` | `"sha256"` | Hash algorithm for plugin validation |
| `ValidateOnStart` | `bool` | `true` | Validate plugins on startup |
| `MaxFileSize` | `int64` | `104857600` | Maximum plugin file size (100MB default) |
| `AllowedTypes` | `[]string` | `[]` | Allowed file extensions (e.g., `.so`, `.dll`) |
| `ForbiddenPaths` | `[]string` | `[]` | Paths where plugins cannot be loaded from |
| `AuditConfig.Enabled` | `bool` | `false` | Enable security audit logging |
| `AuditConfig.AuditFile` | `string` | `""` | Path to security audit log file |
| `AuditConfig.LogUnauthorized` | `bool` | `true` | Log unauthorized plugin access attempts |
| `AuditConfig.LogAuthorized` | `bool` | `false` | Log successful plugin authorizations |
| `AuditConfig.LogConfigChanges` | `bool` | `true` | Log security configuration changes |
| `WatchConfig` | `bool` | `true` | Watch security config file for changes |
| `ReloadDelay` | `duration` | `100ms` | Delay before applying security config changes |

#### Security Policy Modes

- **Disabled (0)**: No security validation - plugins load without checks
- **Permissive (1)**: Log violations but allow plugin loading
- **Strict (2)**: Block unauthorized plugins from loading  
- **Audit-only (3)**: Only audit activity, no validation or blocking

#### Flexible Configuration Approaches

1. **Centralized**: All security settings in main config file
2. **Distributed**: Main config + separate whitelist file via `WhitelistFile`
3. **Hybrid**: Some settings centralized, whitelist separate

Example centralized configuration:
```json
{
  "security": {
    "enabled": true,
    "policy": 2,
    "max_file_size": 104857600,
    "allowed_types": [".so", ".dll", ".dylib"]
  }
}
```

Example with separate whitelist file:
```json
{
  "security": {
    "enabled": true,
    "policy": 2,
    "whitelist_file": "/etc/go-plugins/whitelist.json"
  }
}
```

## Security Configuration

The security configuration system provides comprehensive plugin authorization through multiple enforcement modes and audit capabilities. The system is designed to be flexible, supporting both centralized configuration (everything in one file) and distributed approaches (separate whitelist files).

### Configuration Examples

**Basic Security Setup:**
```json
{
  "security": {
    "enabled": true,
    "policy": 2,
    "validate_on_start": true,
    "allowed_types": [".so", ".dll", ".dylib"],
    "max_file_size": 104857600,
    "audit": {
      "enabled": true,
      "log_unauthorized": true
    }
  }
}
```

**With Separate Whitelist File:**
```json
{
  "security": {
    "enabled": true,
    "policy": 2,
    "whitelist_file": "/etc/go-plugins/whitelist.json",
    "auto_update": true,
    "watch_config": true
  }
}
```

**Development Mode (Permissive):**
```json
{
  "security": {
    "enabled": true,
    "policy": 1,
    "audit": {
      "enabled": true,
      "log_authorized": true,
      "log_unauthorized": true
    }
  }
}
```

### Whitelist File Format

When using a separate whitelist file (via `whitelist_file` option), use this format:

```json
{
  "plugins": [
    {
      "name": "auth-plugin",
      "type": "authentication",
      "algorithm": "sha256",
      "hash": "2153810191098d339e2794460f9462643bc7c5f01b0afad9cd6f7d54469c25ea",
      "file_path": "/opt/plugins/auth.so"
    }
  ]
}
```

## Environment Variables

### Variable Expansion Syntax

The system supports `${VARIABLE_NAME}` syntax with optional default values:

```json
{
  "logging": {
    "level": "${LOG_LEVEL}",           // Required variable
    "format": "${LOG_FORMAT:json}",   // Optional with default
    "output": "${LOG_OUTPUT:stdout}"  // Optional with default
  }
}
```

### Security Features

- **Prefix Validation**: Only variables with configured prefix are allowed
- **Length Limits**: Maximum variable value length (default: 1024 characters)
- **Pattern Validation**: Variables must match `^[A-Z][A-Z0-9_]*$` pattern
- **Injection Protection**: Values are sanitized to prevent command injection

### Environment Configuration

```json
{
  "environment": {
    "expansion_enabled": true,
    "variable_prefix": "GO_PLUGINS_",
    "fail_on_missing": false,
    "max_value_length": 1024,
    "allowed_patterns": ["^GO_PLUGINS_[A-Z_]+$"],
    "overrides": {
      "custom_key": "${GO_PLUGINS_CUSTOM_VALUE}"
    }
  }
}
```

## Hot Reload Workflow

### 1. File Change Detection

The system uses Argus to detect configuration file changes:

```
File Modified → Argus Event → LibraryConfigWatcher → Reload Process
```

### 2. Configuration Processing

```
1. Load Configuration File (JSON/YAML)
2. Expand Environment Variables
3. Validate Configuration Structure
4. Apply to Manager (with rollback capability)
5. Update Current Configuration
6. Log Audit Event
```

### 3. Error Handling

If any step fails:

```
Error Detected → Log Error → Rollback to Previous Config → Audit Event
```

## Security and Validation

### Configuration Validation

The system performs comprehensive validation:

#### Logging Configuration
- Log level must be one of: `debug`, `info`, `warn`, `error`
- Format must be valid
- Component levels must use valid log levels

#### Observability Configuration
- Tracing sample rate must be between 0.0 and 1.0
- Metrics interval must be at least 1 second
- Timeouts must be positive values

#### Default Policies Validation
- Retry max_retries must be >= 0
- Retry multiplier must be > 0
- Circuit breaker thresholds must be >= 0
- Health check intervals must be > 0 when enabled
- Connection limits must be >= 0
- Rate limit values must be >= 0

### Security Best Practices

1. **Environment Variable Security**
   ```bash
   # Use restricted prefixes
   export GO_PLUGINS_LOG_LEVEL=info
   # Avoid sensitive data in config files
   export GO_PLUGINS_DB_PASSWORD=secure_password
   ```

2. **File Permissions**
   ```bash
   chmod 600 library_config.json  # Read/write for owner only
   chmod 700 config_directory/    # Directory access for owner only
   ```

3. **Audit Configuration**
   ```json
   {
     "audit": {
       "enabled": true,
       "output_path": "/secure/audit/library_config.log",
       "max_file_size": 104857600,
       "rotate": true
     }
   }
   ```

## Best Practices

### Configuration Management

1. **Version Your Configurations**
   ```json
   {
     "metadata": {
       "version": "v1.2.3",
       "environment": "production",
       "last_modified": "2025-09-16T19:42:12Z"
     }
   }
   ```

2. **Use Environment-Specific Configs**
   ```
   configs/
   ├── development.json
   ├── staging.json
   └── production.json
   ```

3. **Validate Before Deployment**
   ```bash
   go run validate_config.go production.json
   ```

### Performance Optimization

1. **Appropriate Poll Intervals**
   ```go
   options := LibraryConfigOptions{
       PollInterval: 30 * time.Second,  // Don't poll too frequently
       CacheTTL:     10 * time.Second,  // Cache for reasonable time
   }
   ```

2. **Selective Environment Expansion**
   ```json
   {
     "environment": {
       "expansion_enabled": true,
       "overrides": {
         // Only expand what you need
         "log_level": "${GO_PLUGINS_LOG_LEVEL}"
       }
     }
   }
   ```

### Error Handling

1. **Enable Rollback**
   ```go
   options.RollbackOnFailure = true
   ```

2. **Monitor Audit Logs**
   ```bash
   tail -f audit.log | grep "config_application_failed"
   ```

3. **Set Appropriate Timeouts**
   ```go
   ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
   defer cancel()
   watcher.Start(ctx)
   ```

## Troubleshooting

### Common Issues

#### 1. Configuration Not Reloading

**Symptoms**: Changes to config file are not applied

**Solutions**:
- Check file permissions (must be readable)
- Verify file path is correct
- Check poll interval (may need to wait)
- Review audit logs for errors

```bash
# Check file permissions
ls -la library_config.json

# Check audit logs
grep "configuration_loaded\|configuration_changed" audit.log
```

#### 2. Environment Variable Expansion Failing

**Symptoms**: Variables not expanded, showing `${VAR}` in logs

**Solutions**:
- Verify environment variables are set
- Check variable prefix configuration
- Ensure expansion is enabled

```bash
# Check environment variables
env | grep GO_PLUGINS_

# Verify expansion in config
jq '.environment.expansion_enabled' library_config.json
```

#### 3. Validation Errors

**Symptoms**: Configuration changes rejected with validation errors

**Solutions**:
- Check configuration structure
- Verify data types and ranges
- Review validation error messages

```go
// Enable detailed validation logging
logger := log.New(os.Stdout, "[CONFIG] ", log.LstdFlags|log.Lshortfile)
```

#### 4. Performance Issues

**Symptoms**: High CPU usage or slow response times

**Solutions**:
- Increase poll interval
- Reduce cache TTL
- Disable unnecessary features

```go
options := LibraryConfigOptions{
    PollInterval:        60 * time.Second,  // Reduce polling frequency
    EnableEnvExpansion: false,              // Disable if not needed
    ValidateBeforeApply: false,             // Skip validation in production
}
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```json
{
  "logging": {
    "level": "debug",
    "component_levels": {
      "library_config_watcher": "debug",
      "environment_expander": "debug"
    }
  }
}
```

## API Reference

### LibraryConfigWatcher

#### Constructor

```go
func NewLibraryConfigWatcher[Req, Resp any](
    manager *Manager[Req, Resp],
    configPath string,
    options LibraryConfigOptions,
    logger Logger,
) (*LibraryConfigWatcher[Req, Resp], error)
```

#### Methods

```go
// Start begins watching the configuration file
func (lcw *LibraryConfigWatcher[Req, Resp]) Start(ctx context.Context) error

// Stop gracefully stops the configuration watcher
func (lcw *LibraryConfigWatcher[Req, Resp]) Stop() error

// GetCurrentConfig returns the current configuration
func (lcw *LibraryConfigWatcher[Req, Resp]) GetCurrentConfig() *LibraryConfig

// IsEnabled returns whether the watcher is currently running
func (lcw *LibraryConfigWatcher[Req, Resp]) IsEnabled() bool
```

### Environment Variable Functions

```go
// ExpandEnvironmentVariables expands environment variables in configuration
func ExpandEnvironmentVariables(config interface{}, options EnvExpansionOptions) error

// ProcessConfiguration processes configuration with environment expansion
func ProcessConfiguration(configData []byte, config interface{}, options EnvExpansionOptions) error
```

### Configuration Types

#### LibraryConfig

The main configuration structure containing all library settings.

#### LoggingConfig

Configuration for logging behavior including levels and formatting.

#### ObservabilityRuntimeConfig

Configuration for metrics, tracing, and performance monitoring.

#### DefaultPoliciesConfig

Default policies applied to new plugins (retry, circuit breaker, health checks, etc.).

#### EnvironmentConfig

Configuration for environment variable expansion and processing.

#### PerformanceConfig

Performance-related settings for the configuration system.

#### ConfigMetadata

Metadata about the configuration including version and modification time.

---

## Examples

See the [examples directory](../examples/) for complete working examples:

- [Basic Usage](../examples/library_config_basic/)
- [Advanced Configuration](../examples/library_config_advanced/)
- [Production Setup](../examples/library_config_production/)

---

**Copyright (c) 2025 AGILira - A. Giordano**  
**SPDX-License-Identifier: MPL-2.0**