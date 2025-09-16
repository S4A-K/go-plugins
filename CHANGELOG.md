# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Multi-Format Configuration Support**: Comprehensive configuration format support with automatic detection
  - **Native Format Support**: JSON, YAML (.yaml/.yml), TOML (.toml) with identical functionality
  - **Hybrid Parsing Strategy**: Argus for format detection and file watching, specialized parsers for complex structures
  - **Specialized Parsers**: gopkg.in/yaml.v3 for YAML, github.com/BurntSushi/toml for TOML parsing
  - **Complete TOML Tag Implementation**: All configuration structures support TOML format with full nested configurations
  - **Hot Reload Compatibility**: All formats support hot reloading through Argus file watching
  - **Seamless Migration**: Convert between JSON, YAML, TOML formats without code changes
  - **Performance Optimized**: Format-specific parsers for optimal performance characteristics
- **Active Request Monitoring System**: Production-grade request tracking for zero-downtime operations
  - Real-time active request counting using atomic operations
  - Context-based request tracking for selective cancellation
  - Intelligent graceful draining with 10ms precision monitoring
  - `RequestTracker` component with comprehensive drain options
  - `DrainOptions` configuration for fine-tuned graceful operations
- **Enhanced Graceful Operations**:
  - `GracefulUnregister()` method with active request monitoring
  - `DrainPlugin()` method for selective plugin draining
  - `GetActiveRequestCount()` and `GetAllActiveRequests()` for observability
  - Progress callbacks for real-time drain monitoring
- **Pluggable Logging System**: Interface-first design with backward compatibility
  - `Logger` interface supporting any logging framework
  - Smart auto-detection of logger types (slog, custom, nil)
  - Zero breaking changes with existing slog-based code
- **Enhanced Observability Interfaces**:
  - `MetricsExporter` interface for pluggable metrics backends
  - `MetricsRegistry` interface for comprehensive metrics collection
  - Support for Prometheus, OpenTelemetry, and custom exporters
- Documentation improvements and comprehensive usage examples

### Changed
- **Configuration System Architecture**: Enhanced with hybrid parsing strategy for multi-format support
  - Modified `loadConfigFromFile()` to use format-aware parsing via `parseConfigWithHybridStrategy()`
  - Improved configuration loading performance with format-specific optimizations
  - Enhanced error handling and validation across all configuration formats
- **Dependencies**: Added support for specialized parsers
  - Added `gopkg.in/yaml.v3 v3.0.1` for advanced YAML parsing capabilities
  - Added `github.com/BurntSushi/toml v1.5.0` for comprehensive TOML support
  - Maintained backward compatibility with existing Argus-based JSON parsing
- **Graceful Draining Implementation**: Replaced `time.Sleep()` with active request monitoring
  - Config loader now uses intelligent request tracking instead of fixed delays
  - Improved precision from 100ms/1s delays to 10ms active monitoring
  - Enhanced reliability with request completion guarantees
- Enhanced error messages for better debugging experience
- Updated README with detailed technical implementation documentation

### Fixed
- Eliminated race conditions in graceful draining operations
- Improved timeout handling in plugin reload scenarios

## [v1.0.0] - 2025-01-15

### Added
- **Core Plugin System**: Complete plugin management with lifecycle control
- **Multiple Transport Protocols**: 
  - HTTP/HTTPS with configurable timeouts and authentication
  - gRPC with TLS support and streaming capabilities
  - Unix domain sockets for high-performance local communication
- **Authentication Methods**:
  - API Key authentication with custom header support
  - Bearer token authentication
  - Basic HTTP authentication
  - Mutual TLS (mTLS) for secure communication
  - Custom authentication method support
- **Resilience Patterns**:
  - Circuit breaker with configurable failure thresholds
  - Health monitoring with automatic status tracking
  - Load balancing with multiple strategies (round-robin, random, weighted)
  - Hot reload with graceful connection draining
- **Observability System**:
  - Comprehensive metrics collection with per-plugin granularity
  - Structured logging with configurable log levels
  - Performance monitoring with latency tracking
  - Error categorization and reporting
  - Optional distributed tracing support
- **Advanced Features**:
  - Rate limiting with token bucket algorithm
  - Plugin factory pattern for dynamic instantiation
  - Configuration management with environment variable support
  - Extensive test coverage with benchmarks
- **Go Generics Support**: Type-safe plugin interfaces using Go 1.24+ generics

### Technical Details
- **Minimum Go Version**: 1.24 (required for latest dependencies)
- **Dependencies**:
  - `github.com/agilira/go-errors v1.1.0` for enhanced error handling
  - `github.com/agilira/go-timecache v1.0.1` for high-performance time operations
  - `google.golang.org/grpc v1.75.1` for gRPC transport
  - `golang.org/x/net` for advanced networking features
- **Architecture**: Thread-safe with atomic operations and mutex-protected critical sections
- **Performance**: Optimized for high-throughput scenarios with minimal allocations

### Security
- Secure defaults for all authentication methods
- Input validation and sanitization for all user-provided data
- Protection against common attack vectors (path traversal, injection attacks)
- Comprehensive audit logging for security-sensitive operations

## Version History

- **v1.0.0** (2025-01-15): Initial release with comprehensive plugin system
- **Unreleased**: Ongoing improvements and community feedback integration

## Migration Guide

### From Other Plugin Systems

When migrating from other Go plugin systems:

1. **Interface Adaptation**: Implement the `Plugin[Req, Resp]` interface
2. **Transport Configuration**: Choose appropriate transport (HTTP/gRPC/Unix)
3. **Authentication Setup**: Configure authentication method if required
4. **Observability Integration**: Enable metrics and logging as needed

### Breaking Changes

This is the initial release, so no breaking changes yet. Future versions will document any breaking changes here with migration instructions.

## Contributing

When contributing to this project, please:

1. **Update Documentation**: Ensure all new features are documented
2. **Add Tests**: Include comprehensive test coverage for new functionality
3. **Update Changelog**: Add entries under the "Unreleased" section
4. **Follow Semantic Versioning**: Increment versions appropriately based on changes

### Types of Changes

- **Added** for new features
- **Changed** for changes in existing functionality  
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes

## Links

- [Repository](https://github.com/agilira/go-plugins)
- [Issues](https://github.com/agilira/go-plugins/issues)
- [Releases](https://github.com/agilira/go-plugins/releases)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
