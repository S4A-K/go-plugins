---
title: Security System
description: Implement plugin whitelisting and security policies
weight: 30
---

# Security System Guide

go-plugins includes a comprehensive security system to protect your application from malicious plugins and ensure only authorized plugins can be executed.

## Overview

The security system provides multiple layers of protection:

- **Plugin Whitelisting**: SHA256 hash validation of plugin binaries
- **Security Policies**: Strict, Permissive, and Audit modes
- **Authentication**: Multiple authentication methods for plugin communication
- **Audit Logging**: Comprehensive security event logging
- **Path Traversal Protection**: Prevents malicious path manipulation
- **Process Isolation**: Subprocess plugins run in isolated processes

## Enabling Security

### Simple API
```go
manager, err := goplugins.Production[Req, Resp]().
    WithSecurity("./config/plugins.whitelist").
    WithPlugin("auth", goplugins.Subprocess("./auth-plugin")).
    Build()
```

### Advanced Configuration
```go
securityConfig := goplugins.SecurityConfig{
    Enabled:       true,
    Policy:        goplugins.SecurityPolicyStrict,
    WhitelistFile: "./config/plugins.whitelist",
    WatchConfig:   true,  // Hot-reload security config
    HashAlgorithm: goplugins.HashAlgorithmSHA256,
    
    // Audit configuration
    AuditConfig: goplugins.SecurityAuditConfig{
        Enabled:    true,
        LogFile:    "./logs/security-audit.log",
        LogFormat:  "json",
        MaxSize:    100, // MB
        MaxBackups: 5,
        MaxAge:     30, // days
    },
}

err := manager.EnablePluginSecurity(securityConfig)
```

## Plugin Whitelist

Create a `plugins.whitelist` file to define authorized plugins:

```yaml
# Plugin Whitelist Configuration
version: "1.0"
created_at: "2025-01-01T00:00:00Z"
updated_at: "2025-01-15T10:30:00Z"

# Global security settings
settings:
  hash_algorithm: "sha256"
  enforce_signatures: true
  allow_dev_plugins: false

plugins:
  - name: "auth-service"
    path: "./plugins/auth-service"
    hash: "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456"
    algorithm: "sha256"
    enabled: true
    metadata:
      version: "1.2.3"
      author: "security-team@company.com"
      description: "Authentication and authorization service"
      last_updated: "2025-01-15T10:30:00Z"
      
  - name: "payment-service"
    path: "./plugins/payment-service"
    hash: "sha256:fedcba0987654321098765432109876543210fedcba0987654321098765432"
    algorithm: "sha256"
    enabled: true
    metadata:
      version: "2.1.0"
      author: "payments-team@company.com"
      description: "Payment processing service"
      last_updated: "2025-01-10T14:20:00Z"
      
  - name: "logging-service"
    path: "./plugins/logging-service"
    hash: "sha256:123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01"
    algorithm: "sha256"
    enabled: false  # Temporarily disabled
    metadata:
      version: "1.0.5"
      author: "platform-team@company.com"
      description: "Centralized logging service"
      last_updated: "2025-01-05T09:15:00Z"
```

## Generating Plugin Hashes

Use the built-in hash generation utility:

```go
// Generate hash for a plugin
hash, err := goplugins.GeneratePluginHash("./auth-plugin", goplugins.HashAlgorithmSHA256)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Plugin hash: sha256:%s\n", hash)
```

Or use the command-line tool:

```bash
# Install the hash utility
go install github.com/agilira/go-plugins/cmd/plugin-hash@latest

# Generate hash for a plugin
plugin-hash --file ./auth-plugin --algorithm sha256
```

## Security Policies

### Strict Policy (Recommended for Production)
```go
securityConfig := goplugins.SecurityConfig{
    Policy: goplugins.SecurityPolicyStrict,
}
```

**Behavior:**
- Only whitelisted plugins with valid hashes can be loaded
- Any security violation immediately stops plugin execution
- All security events are logged
- No exceptions or overrides allowed

### Permissive Policy (Development/Testing)
```go
securityConfig := goplugins.SecurityConfig{
    Policy: goplugins.SecurityPolicyPermissive,
}
```

**Behavior:**
- Warnings for non-whitelisted plugins, but allows execution
- Hash mismatches generate warnings but don't block execution
- Useful for development and testing environments
- All events are still logged for analysis

### Audit Policy (Compliance/Monitoring)
```go
securityConfig := goplugins.SecurityConfig{
    Policy: goplugins.SecurityPolicyAuditOnly,
}
```

**Behavior:**
- All plugin operations are logged for compliance
- No enforcement, purely observational
- Useful for compliance requirements and security monitoring
- Generates detailed audit trails

## Authentication Methods

### API Key Authentication
```go
auth := goplugins.AuthConfig{
    Method: goplugins.AuthAPIKey,
    APIKey: "your-secure-api-key",
}
```

### Bearer Token Authentication
```go
auth := goplugins.AuthConfig{
    Method: goplugins.AuthBearer,
    Token:  "your-jwt-token",
}
```

### Mutual TLS (mTLS)
```go
auth := goplugins.AuthConfig{
    Method:   goplugins.AuthMTLS,
    CertFile: "/etc/certs/client.crt",
    KeyFile:  "/etc/certs/client.key",
    CAFile:   "/etc/certs/ca.crt",
}
```

### Basic Authentication
```go
auth := goplugins.AuthConfig{
    Method:   goplugins.AuthBasic,
    Username: "plugin-user",
    Password: "secure-password",
}
```

### Custom Authentication
```go
auth := goplugins.AuthConfig{
    Method: goplugins.AuthCustom,
    Headers: map[string]string{
        "X-Custom-Auth": "custom-token",
        "X-Client-ID":   "client-123",
    },
}
```

## Audit Logging

Security events are automatically logged when audit logging is enabled:

### Sample Audit Log Entry
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "event_type": "plugin_validation_success",
  "plugin_name": "auth-service",
  "plugin_path": "./plugins/auth-service",
  "hash_expected": "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "hash_actual": "sha256:a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
  "policy": "strict",
  "result": "allowed",
  "user_agent": "go-plugins/1.0.0",
  "source_ip": "127.0.0.1"
}
```

### Security Violation Example
```json
{
  "timestamp": "2025-01-15T10:35:00Z",
  "event_type": "security_violation",
  "violation_type": "hash_mismatch",
  "plugin_name": "suspicious-plugin",
  "plugin_path": "./plugins/suspicious-plugin",
  "hash_expected": "sha256:expected_hash_here",
  "hash_actual": "sha256:actual_hash_here",
  "policy": "strict",
  "result": "blocked",
  "severity": "high",
  "action_taken": "plugin_execution_blocked"
}
```

## Hot-Reload Security Configuration

Enable hot-reload to update security configuration without restarting:

```go
securityConfig := goplugins.SecurityConfig{
    WatchConfig: true,
    WhitelistFile: "./config/plugins.whitelist",
}
```

When the whitelist file is updated, the security system will automatically:
1. Reload the new configuration
2. Re-validate all loaded plugins
3. Log the configuration change
4. Apply new security policies

## Best Practices

### 1. Use Strict Policy in Production
```go
// Production security configuration
securityConfig := goplugins.SecurityConfig{
    Policy:        goplugins.SecurityPolicyStrict,
    Enabled:       true,
    WatchConfig:   true,
    HashAlgorithm: goplugins.HashAlgorithmSHA256,
}
```

### 2. Regularly Update Plugin Hashes
```bash
# Script to update hashes after plugin updates
#!/bin/bash
for plugin in ./plugins/*; do
    if [ -x "$plugin" ]; then
        hash=$(plugin-hash --file "$plugin" --algorithm sha256)
        echo "Updated hash for $(basename "$plugin"): $hash"
    fi
done
```

### 3. Monitor Security Logs
```go
// Set up log monitoring
auditConfig := goplugins.SecurityAuditConfig{
    Enabled:    true,
    LogFile:    "./logs/security-audit.log",
    LogFormat:  "json",
    MaxSize:    100,
    MaxBackups: 10,
    MaxAge:     90,
}
```

### 4. Use Environment Variables for Secrets
```bash
export PLUGIN_API_KEY="your-secure-api-key"
export PLUGIN_CERT_PATH="/secure/path/to/certs"
```

```go
auth := goplugins.AuthConfig{
    Method: goplugins.AuthAPIKey,
    APIKey: os.Getenv("PLUGIN_API_KEY"),
}
```

### 5. Implement Plugin Signing (Advanced)
```go
// For high-security environments, implement plugin signing
securityConfig := goplugins.SecurityConfig{
    RequireSignatures: true,
    SigningKey:        "/path/to/signing-key.pem",
    TrustedCerts:      []string{"/path/to/trusted-cert.pem"},
}
```

## Troubleshooting

### Common Security Issues

**Hash Mismatch:**
```
ERROR: Plugin hash mismatch for 'auth-service'
Expected: sha256:abc123...
Actual:   sha256:def456...
```

**Solution:** Regenerate the hash after plugin updates and update the whitelist.

**Plugin Not Whitelisted:**
```
ERROR: Plugin 'new-service' not found in whitelist
```

**Solution:** Add the plugin to the whitelist with its correct hash.

**Authentication Failure:**
```
ERROR: Authentication failed for plugin 'service'
Method: api-key
```

**Solution:** Verify the API key and authentication configuration.

## Security Checklist

- [ ] Enable security system in production
- [ ] Use strict security policy
- [ ] Maintain up-to-date plugin whitelist
- [ ] Enable audit logging
- [ ] Monitor security logs regularly
- [ ] Use strong authentication methods
- [ ] Regularly rotate API keys and certificates
- [ ] Test security configuration in staging
- [ ] Have incident response procedures
- [ ] Keep security documentation updated

{{% alert title="Critical Security Note" %}}
Always test security configuration in a staging environment before deploying to production. Misconfigured security settings can block legitimate plugins or allow unauthorized access.
{{% /alert %}}

## Next Steps

- Learn about [Observability](/guides/observability/) to monitor security events
- Explore [Production Deployment](/guides/production/) for security best practices
- Check out the [Security API Reference](/api/security/) for detailed configuration options
