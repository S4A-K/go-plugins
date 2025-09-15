module github.com/agilira/go-plugins/examples/grpc-plugin

go 1.24.5

replace github.com/agilira/go-plugins => ../../

require (
	github.com/agilira/go-plugins v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.76.0-dev
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/agilira/argus v1.0.1 // indirect
	github.com/agilira/flash-flags v1.0.1 // indirect
	github.com/agilira/go-errors v1.1.0 // indirect
	github.com/agilira/go-timecache v1.0.2 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
)
