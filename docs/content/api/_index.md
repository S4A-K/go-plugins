---
title: API Reference
linkTitle: API Reference
menu: {main: {weight: 20}}
weight: 20
description: Complete API reference for go-plugins
---

# API Reference

This section contains the complete API reference for go-plugins, automatically generated from the Go source code.

## Core Interfaces

The go-plugins library is built around several key interfaces:

- **[Plugin](/api/plugin/)** - The main plugin interface that all plugins must implement
- **[PluginManager](/api/manager/)** - Manages plugin lifecycle, execution, and health monitoring
- **[PluginFactory](/api/factory/)** - Creates plugin instances from configuration

## Configuration

- **[ManagerConfig](/api/config/#managerconfig)** - Complete configuration for the plugin manager
- **[PluginConfig](/api/config/#pluginconfig)** - Configuration for individual plugins
- **[SecurityConfig](/api/security/#securityconfig)** - Security system configuration

## Simple API

For most use cases, the Simple API provides an easy-to-use builder pattern:

- **[SimpleBuilder](/api/simple/)** - Fluent interface for building plugin managers
- **[AutoBuilder](/api/simple/#autobuilder)** - Auto-discovery capabilities

## Transport Protocols

- **[Subprocess Transport](/api/subprocess/)** - Execute plugins as separate processes (recommended)
- **[gRPC Transport](/api/grpc/)** - High-performance gRPC communication

## Security System

- **[SecurityValidator](/api/security/)** - Plugin security validation and enforcement
- **[PluginWhitelist](/api/security/#pluginwhitelist)** - Plugin whitelisting with hash validation

## Observability

- **[MetricsCollector](/api/observability/)** - Metrics collection and export
- **[TracingProvider](/api/observability/#tracing)** - Distributed tracing support
- **[HealthChecker](/api/health/)** - Plugin health monitoring

## Error Handling

- **[Error Types](/api/errors/)** - Structured error types with specific error codes

{{% alert title="Note" %}}
The API reference is automatically generated from the Go source code using `gomarkdoc`. 
For the most up-to-date information, you can also view the [official Go package documentation](https://pkg.go.dev/github.com/agilira/go-plugins).
{{% /alert %}}
