//go:generate go run pkg/codegen/buildconfig/writer.go pkg/codegen/buildconfig/chart_writer.go pkg/codegen/buildconfig/main.go
//go:generate go run pkg/codegen/generator/cleanup/main.go
//go:generate go run pkg/codegen/main.go
//go:generate scripts/build-crds
//go:generate client-gen --output-dir pkg/client --output-pkg "github.com/rancher/rancher/pkg/client" --clientset-name versioned --input-base "github.com/rancher/rancher/pkg/apis" --input management.cattle.io/v3
package main
