# Plugin Security System Documentation

The go-plugins security system provides a robust whitelist mechanism with authorized hashes to validate and authorize plugins before loading.

## Key Features

- **Hash-Based Whitelist**: SHA-256 cryptographic validation of plugins
- **JSON/ENV Configuration**: Support for configuration via JSON files and environment variables
- **Hot Reload with Argus**: Real-time monitoring of configuration changes
- **Complete Audit Trail**: Structured logging of all security events
- **Flexible Policies**: Support for different enforcement modes (strict, permissive, audit-only)

## Configuration

### Enabling Security

```go
package main

import (
    "log"
    "github.com/agilira/go-plugins"
)

func main() {
    // Create the manager
    logger := goplugins.NewLogger(nil)
    manager := goplugins.NewManager[MyRequest, MyResponse](logger)
    
    // Configure security
    securityConfig := goplugins.SecurityConfig{
        Enabled:       true,
        Policy:        goplugins.SecurityPolicyStrict,
        WhitelistFile: "/etc/goplugins/whitelist.json",
        WatchConfig:   true, // Enable hot-reload with Argus
        HashAlgorithm: goplugins.HashAlgorithmSHA256,
        
        AuditConfig: goplugins.SecurityAuditConfig{
            Enabled:          true,
            AuditFile:        "/var/log/goplugins/security.jsonl",
            LogUnauthorized:  true,
            LogAuthorized:    false,
            LogConfigChanges: true,
            IncludeMetadata:  true,
        },
    }
    
    // Enable security
    err := manager.EnablePluginSecurity(securityConfig)
    if err != nil {
        log.Fatal("Failed to enable security:", err)
    }
    
    log.Println("Plugin security enabled successfully")
}
```

### Configuration via Environment Variables

#### Environment Variables Setup

```bash
export GOPLUGINS_SECURITY_ENABLED=true
export GOPLUGINS_SECURITY_POLICY=strict
export GOPLUGINS_WHITELIST_FILE=/etc/goplugins/whitelist.json
export GOPLUGINS_SECURITY_AUTO_UPDATE=false
export GOPLUGINS_HASH_ALGORITHM=sha256
export GOPLUGINS_VALIDATE_ON_START=true
export GOPLUGINS_MAX_FILE_SIZE=104857600  # 100MB
export GOPLUGINS_WATCH_CONFIG=true
export GOPLUGINS_RELOAD_DELAY=1s

# Audit Configuration
export GOPLUGINS_AUDIT_ENABLED=true
export GOPLUGINS_AUDIT_FILE=/var/log/goplugins/security.jsonl
export GOPLUGINS_LOG_UNAUTHORIZED=true
export GOPLUGINS_LOG_AUTHORIZED=false
export GOPLUGINS_LOG_CONFIG_CHANGES=true
export GOPLUGINS_INCLUDE_METADATA=true
```

#### Loading from Environment Variables

**For cloud environments and container deployments:**

```go
package main

import (
    "log"
    "github.com/agilira/go-plugins"
)

func main() {
    // Load configuration directly from environment variables
    securityConfig, err := goplugins.LoadSecurityConfigFromEnv()
    if err != nil {
        log.Fatal("Failed to load security config from environment:", err)
    }
    
    // Create manager and enable security
    logger := goplugins.NewLogger(nil)
    manager := goplugins.NewManager[MyRequest, MyResponse](logger)
    
    err = manager.EnablePluginSecurity(*securityConfig)
    if err != nil {
        log.Fatal("Failed to enable security:", err)
    }
    
    log.Printf("Security enabled with policy: %s", securityConfig.Policy)
}
```

#### Deployment Docker/Kubernetes

```yaml
# docker-compose.yml
version: '3.8'
services:
  app:
    image: myapp:latest
    environment:
      - GOPLUGINS_SECURITY_ENABLED=true
      - GOPLUGINS_SECURITY_POLICY=strict
      - GOPLUGINS_WHITELIST_FILE=/etc/plugins/whitelist.json
      - GOPLUGINS_AUDIT_ENABLED=true
      - GOPLUGINS_AUDIT_FILE=/var/log/security.jsonl
    volumes:
      - ./whitelist.json:/etc/plugins/whitelist.json:ro
      - ./logs:/var/log
```

```yaml
# Kubernetes ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: goplugins-security-config
data:
  GOPLUGINS_SECURITY_ENABLED: "true"
  GOPLUGINS_SECURITY_POLICY: "strict"
  GOPLUGINS_WHITELIST_FILE: "/etc/plugins/whitelist.json"
  GOPLUGINS_AUDIT_ENABLED: "true"
  GOPLUGINS_AUDIT_FILE: "/var/log/plugins/security.jsonl"
```

#### Supported Values for Boolean Variables

```bash
# All these variants are supported for true:
GOPLUGINS_SECURITY_ENABLED=true
GOPLUGINS_SECURITY_ENABLED=TRUE
GOPLUGINS_SECURITY_ENABLED=1
GOPLUGINS_SECURITY_ENABLED=yes
GOPLUGINS_SECURITY_ENABLED=on
GOPLUGINS_SECURITY_ENABLED=enabled

# All these variants are supported for false:
GOPLUGINS_SECURITY_ENABLED=false
GOPLUGINS_SECURITY_ENABLED=FALSE
GOPLUGINS_SECURITY_ENABLED=0
GOPLUGINS_SECURITY_ENABLED=no
GOPLUGINS_SECURITY_ENABLED=off
GOPLUGINS_SECURITY_ENABLED=disabled
```

### Configurazione nel ManagerConfig

```json
{
  "log_level": "info",
  "plugins": [
    {
      "name": "auth-service",
      "type": "http",
      "transport": "https",
      "endpoint": "https://auth.example.com",
      "enabled": true
    }
  ],
  "security": {
    "enabled": true,
    "policy": "strict",
    "whitelist_file": "/etc/goplugins/whitelist.json",
    "auto_update": false,
    "hash_algorithm": "sha256",
    "validate_on_start": true,
    "max_file_size": 104857600,
    "allowed_types": ["http", "grpc"],
    "forbidden_paths": ["/tmp", "/var/tmp"],
    "watch_config": true,
    "reload_delay": "1s",
    "audit": {
      "enabled": true,
      "audit_file": "/var/log/goplugins/security.jsonl",
      "log_unauthorized": true,
      "log_authorized": false,
      "log_config_changes": true,
      "include_metadata": true
    }
  }
}
```

## Whitelist Configuration

### Whitelist Structure

```json
{
  "version": "1.0.0",
  "updated_at": "2025-01-16T10:30:00Z",
  "description": "Plugin security whitelist",
  "default_policy": "strict",
  "hash_algorithm": "sha256",
  "plugins": {
    "auth-service": {
      "name": "auth-service",
      "type": "http",
      "version": "1.2.0",
      "algorithm": "sha256",
      "hash": "a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789ab",
      "file_path": "/opt/plugins/auth-service",
      "description": "Authentication service plugin",
      "allowed_endpoints": [
        "https://auth.example.com",
        "https://auth-staging.example.com"
      ],
      "max_file_size": 52428800,
      "metadata": {
        "owner": "security-team",
        "approved_by": "security-officer",
        "approval_date": "2025-01-15"
      },
      "added_at": "2025-01-15T09:00:00Z",
      "updated_at": "2025-01-16T10:30:00Z"
    },
    "logging-plugin": {
      "name": "logging-plugin",
      "type": "grpc",
      "version": "2.1.0",
      "algorithm": "sha256",
      "hash": "b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
      "description": "Centralized logging plugin",
      "allowed_endpoints": [
        "grpc://logs.example.com:9090"
      ],
      "max_file_size": 26214400,
      "added_at": "2025-01-15T09:00:00Z",
      "updated_at": "2025-01-16T10:30:00Z"
    }
  },
  "global_constraints": {
    "max_file_size": 104857600,
    "allowed_types": ["http", "grpc", "https"],
    "forbidden_paths": [
      "/tmp",
      "/var/tmp",
      "~/.ssh"
    ]
  }
}
```

### Sample Whitelist Creation

```go
// Create a sample whitelist for testing
err := goplugins.CreateSampleWhitelist("/etc/goplugins/whitelist.json")
if err != nil {
    log.Fatal("Failed to create sample whitelist:", err)
}
```

## Security Policies

### SecurityPolicyDisabled
- **Behavior**: No validation
- **Usage**: Complete security system disabling
- **Default**: Yes (for backward compatibility)

### SecurityPolicyPermissive
- **Behavior**: Logs violations but allows loading
- **Usage**: Transition mode or development
- **Audit**: Complete

### SecurityPolicyStrict
- **Behavior**: Blocks unauthorized plugins
- **Usage**: Production with strict security
- **Audit**: Complete

### SecurityPolicyAuditOnly
- **Behavior**: Audit only, no validation
- **Usage**: Monitoring without enforcement
- **Audit**: Complete

## Argus Integration

### Automatic Hot Reload

The system uses Argus for real-time whitelist monitoring:

```go
// Hot reload is automatic when watch_config is true
manager := goplugins.NewManager[MyRequest, MyResponse](logger)

config := goplugins.SecurityConfig{
    Enabled:     true,
    WatchConfig: true, // Enable Argus monitoring
    WhitelistFile: "/etc/goplugins/whitelist.json",
}

err := manager.EnablePluginSecurity(config)
// Now any changes to whitelist.json are automatically applied
```

### Audit Trail

```jsonl
{"timestamp":"2025-01-16T10:30:00.123Z","level":"INFO","event":"plugin_authorized","component":"plugin_security","plugin_name":"auth-service","authorized":true,"policy":"strict"}
{"timestamp":"2025-01-16T10:30:05.456Z","level":"SECURITY","event":"plugin_rejected","component":"plugin_security","plugin_name":"malicious-plugin","authorized":false,"violations":[{"type":"plugin_not_whitelisted","reason":"Plugin not found in security whitelist"}]}
{"timestamp":"2025-01-16T10:30:10.789Z","level":"INFO","event":"whitelist_reloaded","component":"plugin_security","file":"/etc/goplugins/whitelist.json","plugins":5}
```

## Management API

### Security Management

```go
// Enable security
err := manager.EnablePluginSecurity(config)

// Disable security
err := manager.DisablePluginSecurity()

// Check status
enabled := manager.IsPluginSecurityEnabled()

// Get statistics
stats, err := manager.GetPluginSecurityStats()

// Get current configuration
config, err := manager.GetPluginSecurityConfig()
```

### Whitelist Management

```go
// Manual whitelist reload
err := manager.ReloadPluginWhitelist()

// Whitelist information
info, err := manager.GetPluginWhitelistInfo()

// Manual validation
result, err := manager.ValidatePluginSecurity(pluginConfig, "/path/to/plugin")
```

### Argus Information

```go
// Get Argus integration information
argusInfo := manager.GetArgusIntegrationInfo()
if argusInfo["enabled"].(bool) {
    watchedFiles := argusInfo["watched_files"].([]string)
    stats := argusInfo["stats"]
    log.Printf("Watching %d files: %v", len(watchedFiles), watchedFiles)
}
```

## Usage Examples

### Basic Production Setup

```go
func setupSecurePluginManager() (*goplugins.Manager[Request, Response], error) {
    logger := goplugins.NewLogger(nil)
    manager := goplugins.NewManager[Request, Response](logger)
    
    // Production security configuration
    securityConfig := goplugins.SecurityConfig{
        Enabled:       true,
        Policy:        goplugins.SecurityPolicyStrict,
        WhitelistFile: "/etc/goplugins/production-whitelist.json",
        WatchConfig:   true,
        ValidateOnStart: true,
        MaxFileSize:   50 * 1024 * 1024, // 50MB limit
        AllowedTypes:  []string{"http", "grpc"},
        ForbiddenPaths: []string{"/tmp", "/var/tmp", "/dev"},
        
        AuditConfig: goplugins.SecurityAuditConfig{
            Enabled:          true,
            AuditFile:        "/var/log/goplugins/security-audit.jsonl",
            LogUnauthorized:  true,
            LogAuthorized:    false, // Reduce noise in production
            LogConfigChanges: true,
            IncludeMetadata:  false, // Performance optimization
        },
    }
    
    if err := manager.EnablePluginSecurity(securityConfig); err != nil {
        return nil, fmt.Errorf("security setup failed: %w", err)
    }
    
    return manager, nil
}
```

### Development Mode

```go
func setupDevelopmentManager() (*goplugins.Manager[Request, Response], error) {
    logger := goplugins.NewLogger(nil)
    manager := goplugins.NewManager[Request, Response](logger)
    
    // Permissive configuration for development
    securityConfig := goplugins.SecurityConfig{
        Enabled:     true,
        Policy:      goplugins.SecurityPolicyPermissive, // Log but don't block
        WatchConfig: true, // Hot reload for development
        
        AuditConfig: goplugins.SecurityAuditConfig{
            Enabled:         true,
            LogUnauthorized: true,
            LogAuthorized:   true, // Complete logging for debug
            IncludeMetadata: true, // Complete info for debug
        },
    }
    
    return manager, manager.EnablePluginSecurity(securityConfig)
}
```

### Cloud Environment Setup

```go
func setupCloudManager() (*goplugins.Manager[Request, Response], error) {
    logger := goplugins.NewLogger(nil)
    manager := goplugins.NewManager[Request, Response](logger)
    
    // Load configuration from environment variables
    // Perfect for Docker, Kubernetes, AWS, Azure, GCP
    securityConfig, err := goplugins.LoadSecurityConfigFromEnv()
    if err != nil {
        return nil, fmt.Errorf("failed to load security config from environment: %w", err)
    }
    
    // Enable security with ENV configuration
    if err := manager.EnablePluginSecurity(*securityConfig); err != nil {
        return nil, fmt.Errorf("failed to enable security: %w", err)
    }
    
    logger.Info("Security enabled from environment variables",
        "policy", securityConfig.Policy.String(),
        "whitelist_file", securityConfig.WhitelistFile,
        "audit_enabled", securityConfig.AuditConfig.Enabled)
    
    return manager, nil
}
```

#### AWS ECS/Fargate Example

```json
{
  "family": "goplugins-app",
  "taskDefinition": {
    "containerDefinitions": [
      {
        "name": "app",
        "image": "myapp:latest",
        "environment": [
          {
            "name": "GOPLUGINS_SECURITY_ENABLED",
            "value": "true"
          },
          {
            "name": "GOPLUGINS_SECURITY_POLICY", 
            "value": "strict"
          },
          {
            "name": "GOPLUGINS_WHITELIST_FILE",
            "value": "/etc/plugins/whitelist.json"
          },
          {
            "name": "GOPLUGINS_AUDIT_FILE",
            "value": "/var/log/security.jsonl"
          }
        ]
      }
    ]
  }
}
```

#### Google Cloud Run Example

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: goplugins-app
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/execution-environment: gen2
    spec:
      containers:
      - image: gcr.io/PROJECT-ID/goplugins-app
        env:
        - name: GOPLUGINS_SECURITY_ENABLED
          value: "true"
        - name: GOPLUGINS_SECURITY_POLICY
          value: "strict"
        - name: GOPLUGINS_WHITELIST_FILE
          value: "/etc/plugins/whitelist.json"
        - name: GOPLUGINS_AUDIT_ENABLED
          value: "true"
```

## Monitoring and Metrics

### Security Statistics

```go
stats, err := manager.GetPluginSecurityStats()
if err == nil {
    log.Printf("Security Stats:")
    log.Printf("  Validation attempts: %d", stats.ValidationAttempts)
    log.Printf("  Authorized loads: %d", stats.AuthorizedLoads)
    log.Printf("  Rejected loads: %d", stats.RejectedLoads)
    log.Printf("  Config reloads: %d", stats.ConfigReloads)
    log.Printf("  Hash mismatches: %d", stats.HashMismatches)
    log.Printf("  Last validation: %s", stats.LastValidation)
}
```

### Integration with Monitoring Systems

```go
// Example Prometheus integration
func registerSecurityMetrics(manager *goplugins.Manager[Request, Response]) {
    go func() {
        ticker := time.NewTicker(30 * time.Second)
        defer ticker.Stop()
        
        for range ticker.C {
            stats, err := manager.GetPluginSecurityStats()
            if err != nil {
                continue
            }
            
            // Update Prometheus metrics
            securityValidationTotal.Set(float64(stats.ValidationAttempts))
            securityAuthorizedTotal.Set(float64(stats.AuthorizedLoads))
            securityRejectedTotal.Set(float64(stats.RejectedLoads))
            securityConfigReloads.Set(float64(stats.ConfigReloads))
        }
    }()
}
```

## Troubleshooting

### Common Issues

1. **Plugin not authorized**: Verify that the plugin is in the whitelist
2. **Hash mismatch**: The plugin file was modified after approval
3. **File not found**: Verify the whitelist file path
4. **Insufficient permissions**: Verify read permissions for whitelist and audit

### Debug

```go
// Enable detailed logging
logger := goplugins.NewLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelDebug,
})))

// Verify configuration
config, err := manager.GetPluginSecurityConfig()
if err == nil {
    log.Printf("Current security config: %+v", config)
}

// Verify whitelist
whitelistInfo, err := manager.GetPluginWhitelistInfo()
if err == nil {
    log.Printf("Whitelist info: %+v", whitelistInfo)
}

// Manual validation test
result, err := manager.ValidatePluginSecurity(pluginConfig, pluginPath)
if err == nil {
    log.Printf("Validation result: %+v", result)
    for _, violation := range result.Violations {
        log.Printf("Violation: %+v", violation)
    }
}
```