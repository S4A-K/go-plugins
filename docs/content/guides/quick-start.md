---
title: Quick Start
description: Get up and running with go-plugins in minutes
weight: 10
---

# Quick Start Guide

This guide will help you get started with go-plugins quickly and easily.

## Prerequisites

- Go 1.24 or later
- Basic understanding of Go programming

## Installation

Add go-plugins to your project:

```bash
go get github.com/agilira/go-plugins
```

## Your First Plugin Manager

Let's create a simple plugin manager using the Simple API:

```go
package main

import (
    "context"
    "log"
    
    "github.com/agilira/go-plugins"
)

// Define your plugin request/response types
type AuthRequest struct {
    UserID string `json:"user_id"`
    Token  string `json:"token"`
}

type AuthResponse struct {
    Valid   bool   `json:"valid"`
    UserID  string `json:"user_id,omitempty"`
    Error   string `json:"error,omitempty"`
}

func main() {
    // Create a manager with development defaults
    manager, err := goplugins.Development[AuthRequest, AuthResponse]().
        WithPlugin("auth", goplugins.Subprocess("./auth-plugin")).
        Build()
    if err != nil {
        log.Fatal("Failed to build manager:", err)
    }
    defer manager.Shutdown(context.Background())

    // Execute plugin operations
    ctx := context.Background()
    response, err := manager.Execute(ctx, "auth", AuthRequest{
        UserID: "user123",
        Token:  "jwt-token-here",
    })
    if err != nil {
        log.Printf("Authentication failed: %v", err)
        return
    }

    log.Printf("Authentication result: %+v", response)
}
```

## Creating a Simple Plugin

Create a basic plugin executable:

```go
package main

import (
    "context"
    "time"
    
    "github.com/agilira/go-plugins"
)

type AuthPlugin struct {
    name string
}

func (p *AuthPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     "1.0.0",
        Description: "Simple authentication plugin",
        Author:      "your-team@company.com",
    }
}

func (p *AuthPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request AuthRequest) (AuthResponse, error) {
    // Simple validation logic
    if request.UserID == "user123" && request.Token == "valid-token" {
        return AuthResponse{Valid: true, UserID: request.UserID}, nil
    }
    
    return AuthResponse{Valid: false, Error: "Invalid credentials"}, nil
}

func (p *AuthPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    return goplugins.HealthStatus{
        Status:    goplugins.StatusHealthy,
        Message:   "Plugin is healthy",
        LastCheck: time.Now(),
    }
}

func (p *AuthPlugin) Close() error {
    return nil
}

func main() {
    plugin := &AuthPlugin{name: "auth"}
    
    goplugins.Serve(goplugins.ServeConfig{
        PluginName: "auth",
        Plugin:     plugin,
    })
}
```

## Running the Example

1. **Build the plugin:**
   ```bash
   go build -o auth-plugin ./plugin/
   ```

2. **Run your application:**
   ```bash
   go run main.go
   ```

## Next Steps

- Learn about [Configuration](/guides/configuration/) for more advanced setups
- Explore [Security](/guides/security/) to secure your plugins
- Check out [Production Deployment](/guides/production/) for production best practices

{{% alert title="Tip" %}}
Use the `Development()` builder for local development and `Production()` for production environments. They have different default settings optimized for each use case.
{{% /alert %}}
