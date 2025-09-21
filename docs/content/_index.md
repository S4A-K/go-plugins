---
title: go-plugins
linkTitle: go-plugins
menu: {main: {weight: 10}}
weight: 10
---

{{% blocks/cover title="go-plugins" image_anchor="top" height="full" %}}

<p class="lead mt-5">Production-ready, type-safe plugin architecture for Go applications</p>

{{% blocks/link-down color="info" %}}

{{% /blocks/cover %}}

{{% blocks/section color="dark" type="row" %}}

{{% blocks/feature icon="fa-solid fa-shield-halved" title="Enterprise Security" %}}
Advanced security system with plugin whitelisting, SHA256 hash validation, and comprehensive audit logging.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-gauge-high" title="High Performance" %}}
Built-in connection pooling, circuit breakers, atomic request tracking, and intelligent caching for optimal performance.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-chart-line" title="Full Observability" %}}
Comprehensive metrics, distributed tracing, health monitoring, and real-time operational visibility.
{{% /blocks/feature %}}

{{% /blocks/section %}}

{{% blocks/section %}}

## What is go-plugins?

go-plugins provides a production-ready, type-safe plugin architecture for Go applications. It supports gRPC and subprocess transport protocols with built-in circuit breaking, health monitoring, authentication, and graceful degradation.

### Key Features

- **Type-safe plugin interfaces** using Go generics
- **Multiple transport protocols** (gRPC, subprocess execution)
- **Circuit breaker pattern** for resilience
- **Health monitoring** and automatic recovery
- **Authentication and authorization** (API key, Bearer, mTLS, Basic, Custom)
- **Advanced security system** with plugin whitelisting and hash validation
- **Hot-reloading** of plugin configurations with active request monitoring
- **Production-grade graceful draining** with atomic request tracking
- **Pluggable logging system** supporting any framework
- **Comprehensive observability** with metrics exporters and distributed tracing
- **Zero-downtime deployments** and graceful shutdown
- **Simple API** with fluent builder pattern for common use cases

{{% /blocks/section %}}

{{% blocks/section type="row" %}}

{{% blocks/feature icon="fab fa-github" title="Open Source" url="https://github.com/agilira/go-plugins" %}}
Available on GitHub under the Mozilla Public License 2.0
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-book" title="Documentation" url="/guides/" %}}
Comprehensive guides, examples, and API reference
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-solid fa-users" title="Community" url="https://github.com/agilira/go-plugins/discussions" %}}
Join our community for support and discussions
{{% /blocks/feature %}}

{{% /blocks/section %}}
