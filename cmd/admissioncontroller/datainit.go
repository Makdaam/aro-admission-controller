package main

import (
	"github.com/openshift/origin/pkg/security/apis/security"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/apis/core"
)

func toStringPtr(s string) *string {
	return &s
}

func toInt32Ptr(i int32) *int32 {
	return &i
}

func toBoolPtr(b bool) *bool {
	return &b
}

func (ac *admissionController) InitProtectedSCCs() map[string]security.SecurityContextConstraints {
	result := map[string]security.SecurityContextConstraints{
		"anyuid": {
			Priority:                 toInt32Ptr(10),
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   []core.Capability{},
			RequiredDropCapabilities: []core.Capability{"MKNOD"},
			AllowedCapabilities:      []core.Capability{},
			Volumes: []security.FSType{
				security.FSTypeConfigMap,
				security.FSTypeDownwardAPI,
				security.FSTypeEmptyDir,
				security.FSTypePersistentVolumeClaim,
				security.FSProjected,
				security.FSTypeSecret,
			},
			AllowHostNetwork:         false,
			AllowHostPorts:           false,
			AllowHostPID:             false,
			AllowHostIPC:             false,
			AllowPrivilegeEscalation: toBoolPtr(true),
			TypeMeta: metav1.TypeMeta{
				APIVersion: "security.openshift.io/v1",
				Kind:       "SecurityContextConstraints",
			},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyRunAsAny,
			},
			Groups: []string{
				"system:cluster-admins",
			},

			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyRunAsAny,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
		},
		//TODO add other SCCs
	}
	return result
}
