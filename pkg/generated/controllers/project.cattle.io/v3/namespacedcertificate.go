/*
Copyright 2025 Rancher Labs, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Code generated by main. DO NOT EDIT.

package v3

import (
	v3 "github.com/rancher/rancher/pkg/apis/project.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic"
)

// NamespacedCertificateController interface for managing NamespacedCertificate resources.
type NamespacedCertificateController interface {
	generic.ControllerInterface[*v3.NamespacedCertificate, *v3.NamespacedCertificateList]
}

// NamespacedCertificateClient interface for managing NamespacedCertificate resources in Kubernetes.
type NamespacedCertificateClient interface {
	generic.ClientInterface[*v3.NamespacedCertificate, *v3.NamespacedCertificateList]
}

// NamespacedCertificateCache interface for retrieving NamespacedCertificate resources in memory.
type NamespacedCertificateCache interface {
	generic.CacheInterface[*v3.NamespacedCertificate]
}
