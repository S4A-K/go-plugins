---
title: Hello World Plugin
description: A simple plugin that demonstrates the basic concepts
weight: 10
---

# Hello World Plugin Example

This example demonstrates the basic concepts of go-plugins with a simple "Hello World" plugin.

## Overview

We'll create:
1. A simple plugin that processes greetings
2. A host application that uses the plugin
3. Basic error handling and health checks

## Plugin Implementation

### Request/Response Types

```go
// types.go
package main

type GreetingRequest struct {
    Name     string `json:"name"`
    Language string `json:"language,omitempty"`
}

type GreetingResponse struct {
    Message string `json:"message"`
    Error   string `json:"error,omitempty"`
}
```

### Plugin Implementation

```go
// plugin/main.go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/agilira/go-plugins"
)

type HelloWorldPlugin struct {
    name string
}

func (p *HelloWorldPlugin) Info() goplugins.PluginInfo {
    return goplugins.PluginInfo{
        Name:        p.name,
        Version:     "1.0.0",
        Description: "A simple greeting plugin",
        Author:      "go-plugins examples",
        Capabilities: []string{"greet", "multilingual"},
        Metadata: map[string]string{
            "supported_languages": "en,es,fr,de",
        },
    }
}

func (p *HelloWorldPlugin) Execute(ctx context.Context, execCtx goplugins.ExecutionContext, request GreetingRequest) (GreetingResponse, error) {
    if request.Name == "" {
        return GreetingResponse{
            Error: "Name is required",
        }, fmt.Errorf("name cannot be empty")
    }
    
    // Generate greeting based on language
    greeting := p.getGreeting(request.Language)
    message := fmt.Sprintf("%s, %s!", greeting, request.Name)
    
    return GreetingResponse{
        Message: message,
    }, nil
}

func (p *HelloWorldPlugin) getGreeting(language string) string {
    greetings := map[string]string{
        "en": "Hello",
        "es": "Hola",
        "fr": "Bonjour",
        "de": "Hallo",
        "it": "Ciao",
    }
    
    if greeting, exists := greetings[language]; exists {
        return greeting
    }
    
    return greetings["en"] // Default to English
}

func (p *HelloWorldPlugin) Health(ctx context.Context) goplugins.HealthStatus {
    return goplugins.HealthStatus{
        Status:    goplugins.StatusHealthy,
        Message:   "Plugin is ready to greet",
        LastCheck: time.Now(),
        Metadata: map[string]string{
            "uptime": time.Since(time.Now()).String(),
        },
    }
}

func (p *HelloWorldPlugin) Close() error {
    fmt.Println("HelloWorld plugin shutting down...")
    return nil
}

func main() {
    plugin := &HelloWorldPlugin{
        name: "hello-world",
    }
    
    // Serve the plugin
    goplugins.Serve(goplugins.ServeConfig{
        PluginName: "hello-world",
        Plugin:     plugin,
        Transport:  goplugins.TransportExecutable,
    })
}
```

## Host Application

### Simple Implementation

```go
// main.go
package main

import (
    "context"
    "fmt"
    "log"
)

func main() {
    // Create a simple manager
    manager, err := goplugins.Development[GreetingRequest, GreetingResponse]().
        WithPlugin("hello-world", goplugins.Subprocess("./hello-world-plugin")).
        Build()
    if err != nil {
        log.Fatal("Failed to create manager:", err)
    }
    defer manager.Shutdown(context.Background())

    // Test basic greeting
    ctx := context.Background()
    
    // English greeting
    response, err := manager.Execute(ctx, "hello-world", GreetingRequest{
        Name:     "World",
        Language: "en",
    })
    if err != nil {
        log.Printf("Error: %v", err)
    } else {
        fmt.Printf("Response: %s\n", response.Message)
    }
    
    // Spanish greeting
    response, err = manager.Execute(ctx, "hello-world", GreetingRequest{
        Name:     "Mundo",
        Language: "es",
    })
    if err != nil {
        log.Printf("Error: %v", err)
    } else {
        fmt.Printf("Response: %s\n", response.Message)
    }
    
    // Test error handling
    response, err = manager.Execute(ctx, "hello-world", GreetingRequest{
        Name: "", // Empty name should cause error
    })
    if err != nil {
        fmt.Printf("Expected error: %v\n", err)
        fmt.Printf("Error response: %s\n", response.Error)
    }
    
    // Check plugin health
    health := manager.Health()
    for pluginName, status := range health {
        fmt.Printf("Plugin %s status: %s - %s\n", 
            pluginName, status.Status.String(), status.Message)
    }
}
```

### Advanced Implementation with Error Handling

```go
// advanced-main.go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
)

func main() {
    // Create manager with custom configuration
    manager, err := goplugins.Simple[GreetingRequest, GreetingResponse]().
        WithPlugin("hello-world", goplugins.Subprocess("./hello-world-plugin")).
        WithTimeout(10 * time.Second).
        WithLogger(createLogger()).
        Build()
    if err != nil {
        log.Fatal("Failed to create manager:", err)
    }
    defer gracefulShutdown(manager)

    // Test multiple greetings
    testCases := []struct {
        name     string
        request  GreetingRequest
        expectError bool
    }{
        {
            name: "English greeting",
            request: GreetingRequest{Name: "Alice", Language: "en"},
            expectError: false,
        },
        {
            name: "Spanish greeting",
            request: GreetingRequest{Name: "Carlos", Language: "es"},
            expectError: false,
        },
        {
            name: "French greeting",
            request: GreetingRequest{Name: "Marie", Language: "fr"},
            expectError: false,
        },
        {
            name: "Invalid empty name",
            request: GreetingRequest{Name: "", Language: "en"},
            expectError: true,
        },
        {
            name: "Unknown language (should default to English)",
            request: GreetingRequest{Name: "Yuki", Language: "ja"},
            expectError: false,
        },
    }

    ctx := context.Background()
    
    for _, tc := range testCases {
        fmt.Printf("\n--- %s ---\n", tc.name)
        
        response, err := manager.Execute(ctx, "hello-world", tc.request)
        
        if tc.expectError {
            if err != nil {
                fmt.Printf("✓ Expected error: %v\n", err)
                fmt.Printf("  Error message: %s\n", response.Error)
            } else {
                fmt.Printf("✗ Expected error but got success: %s\n", response.Message)
            }
        } else {
            if err != nil {
                fmt.Printf("✗ Unexpected error: %v\n", err)
            } else {
                fmt.Printf("✓ Success: %s\n", response.Message)
            }
        }
    }
    
    // Demonstrate plugin info
    plugin, err := manager.GetPlugin("hello-world")
    if err != nil {
        log.Printf("Failed to get plugin: %v", err)
    } else {
        info := plugin.Info()
        fmt.Printf("\n--- Plugin Information ---\n")
        fmt.Printf("Name: %s\n", info.Name)
        fmt.Printf("Version: %s\n", info.Version)
        fmt.Printf("Description: %s\n", info.Description)
        fmt.Printf("Author: %s\n", info.Author)
        fmt.Printf("Capabilities: %v\n", info.Capabilities)
        fmt.Printf("Metadata: %v\n", info.Metadata)
    }
}

func createLogger() goplugins.Logger {
    return goplugins.SimpleDefaultLogger()
}

func gracefulShutdown(manager *goplugins.Manager[GreetingRequest, GreetingResponse]) {
    fmt.Println("\nShutting down gracefully...")
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    if err := manager.Shutdown(ctx); err != nil {
        log.Printf("Shutdown completed with warnings: %v", err)
    } else {
        fmt.Println("Shutdown completed successfully")
    }
}
```

## Building and Running

### 1. Create the project structure
```bash
mkdir hello-world-example
cd hello-world-example

# Create directories
mkdir plugin

# Initialize Go module
go mod init hello-world-example
go get github.com/agilira/go-plugins
```

### 2. Create the files
- Copy the plugin code to `plugin/main.go`
- Copy the host application code to `main.go`
- Create `types.go` with the request/response types

### 3. Build the plugin
```bash
cd plugin
go build -o ../hello-world-plugin .
cd ..
```

### 4. Run the host application
```bash
go run main.go types.go
```

## Expected Output

```
--- English greeting ---
✓ Success: Hello, Alice!

--- Spanish greeting ---
✓ Success: Hola, Carlos!

--- French greeting ---
✓ Success: Bonjour, Marie!

--- Invalid empty name ---
✓ Expected error: name cannot be empty
  Error message: Name is required

--- Unknown language (should default to English) ---
✓ Success: Hello, Yuki!

--- Plugin Information ---
Name: hello-world
Version: 1.0.0
Description: A simple greeting plugin
Author: go-plugins examples
Capabilities: [greet multilingual]
Metadata: map[supported_languages:en,es,fr,de]

Shutting down gracefully...
HelloWorld plugin shutting down...
Shutdown completed successfully
```

## Key Concepts Demonstrated

1. **Plugin Interface Implementation**: How to implement the required methods
2. **Type Safety**: Using Go generics for request/response types
3. **Error Handling**: Proper error handling in both plugin and host
4. **Health Checks**: Implementing and checking plugin health
5. **Graceful Shutdown**: Proper cleanup and shutdown procedures
6. **Plugin Metadata**: Providing plugin information and capabilities

## Next Steps

- Try the [Authentication Plugin Example](/examples/auth-plugin/)
- Learn about [Configuration](/guides/configuration/)
- Explore [Security Features](/guides/security/)

{{% alert title="Tip" %}}
This example uses the Development builder which includes verbose logging. For production use, switch to the Production builder with appropriate security and monitoring configuration.
{{% /alert %}}
