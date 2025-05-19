package changes

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/rancher/rancher/pkg/migrations/test"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

func TestCreateMergePatchChange(t *testing.T) {
	oldObj := test.NewService(func(s *corev1.Service) {
		s.ObjectMeta.Labels = map[string]string{
			"app.kubernetes.io/managed-by": "Helm",
		}
		s.Spec = corev1.ServiceSpec{
			ClusterIP: "10.43.25.18",
			ClusterIPs: []string{
				"10.43.25.18",
			},
			InternalTrafficPolicy: ptr.To(corev1.ServiceInternalTrafficPolicyCluster),
			IPFamilies: []corev1.IPFamily{
				corev1.IPv4Protocol,
			},
			IPFamilyPolicy: ptr.To(corev1.IPFamilyPolicySingleStack),
			Selector: map[string]string{
				"app": "gitjob",
			},
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					Name:       "http-80",
					Port:       80,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.IntOrString{IntVal: int32(8080)},
				},
			},
		}
	})
	newObj := oldObj.DeepCopy()
	newObj.Spec.ClusterIPs = []string{
		"10.43.25.18",
		"10.43.26.16",
	}
	newObj.ObjectMeta.Labels = map[string]string{
		"app.kubernetes.io/managed-by": "Helm",
		"example.com/testing":          "test",
	}
	change, err := CreateMergePatchChange(oldObj, newObj, test.NewFakeMapper())
	if err != nil {
		t.Fatal(err)
	}

	want := &PatchChange{
		ResourceRef: ResourceReference{
			ObjectRef: types.NamespacedName{
				Name:      oldObj.Name,
				Namespace: oldObj.Namespace,
			},
			Resource: "services",
			Version:  "v1",
		},
		MergePatch: map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{
					"example.com/testing": "test",
				},
			},
			"spec": map[string]any{
				"clusterIPs": []any{
					"10.43.25.18",
					"10.43.26.16",
				},
			},
		},
		Type: MergePatchJSON,
	}

	if diff := cmp.Diff(want, change); diff != "" {
		t.Fatalf("unexpected changes: diff -want +got\n%s", diff)
	}
}

func TestCreateMergePatchChangeValidation(t *testing.T) {
	validationTests := map[string]struct {
		newObj runtime.Object
		oldObj runtime.Object
	}{
		"GVKs must match old and new objects": {},
	}

	for name, tt := range validationTests {
		t.Run(name, func(t *testing.T) {
		})
	}
}
