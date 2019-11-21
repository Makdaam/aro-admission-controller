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
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"MKNOD"},
			AllowedCapabilities:      nil,
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
			TypeMeta:                 metav1.TypeMeta{},
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
		"hostaccess": {
			Priority:                 nil,
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"KILL", "MKNOD", "SETUID", "SETGID"},
			AllowedCapabilities:      nil,
			Volumes: []security.FSType{
				security.FSTypeConfigMap,
				security.FSTypeDownwardAPI,
				security.FSTypeEmptyDir,
				security.FSTypeHostPath,
				security.FSTypePersistentVolumeClaim,
				security.FSProjected,
				security.FSTypeSecret,
			},
			AllowHostNetwork:         true,
			AllowHostPorts:           true,
			AllowHostPID:             true,
			AllowHostIPC:             true,
			AllowPrivilegeEscalation: toBoolPtr(true),
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyMustRunAs,
			},
			Groups: []string{},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyMustRunAsRange,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
		},
		"hostmount-anyuid": {
			Priority:                 nil,
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"MKNOD"},
			AllowedCapabilities:      nil,
			Volumes: []security.FSType{
				security.FSTypeConfigMap,
				security.FSTypeDownwardAPI,
				security.FSTypeEmptyDir,
				security.FSTypeHostPath,
				security.FSTypeNFS,
				security.FSTypePersistentVolumeClaim,
				security.FSProjected,
				security.FSTypeSecret,
			},
			AllowHostNetwork:         false,
			AllowHostPorts:           false,
			AllowHostPID:             false,
			AllowHostIPC:             false,
			AllowPrivilegeEscalation: toBoolPtr(true),
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyRunAsAny,
			},
			Groups: []string{},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyRunAsAny,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
			Users: []string{
				"system:serviceaccount:openshift-azure-monitoring:etcd-metrics",
				"system:serviceaccount:openshift-infra:pv-recycler-controller",
				"system:serviceaccount:kube-service-catalog:service-catalog-apiserver",
			},
		},
		"hostnetwork": {
			Priority:                 nil,
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"KILL", "MKNOD", "SETUID", "SETGID"},
			AllowedCapabilities:      nil,
			Volumes: []security.FSType{
				security.FSTypeConfigMap,
				security.FSTypeDownwardAPI,
				security.FSTypeEmptyDir,
				security.FSTypePersistentVolumeClaim,
				security.FSProjected,
				security.FSTypeSecret,
			},
			AllowHostNetwork:         true,
			AllowHostPorts:           true,
			AllowHostPID:             false,
			AllowHostIPC:             false,
			AllowPrivilegeEscalation: toBoolPtr(true),
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyMustRunAs,
			},
			Groups: []string{},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyMustRunAsRange,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyMustRunAs,
			},
		},
		"nonroot": {
			Priority:                 nil,
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"KILL", "MKNOD", "SETUID", "SETGID"},
			AllowedCapabilities:      nil,
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
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyRunAsAny,
			},
			Groups: []string{},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyMustRunAsNonRoot,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
		},
		"privileged": {
			Priority:                 nil,
			AllowPrivilegedContainer: true,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: nil,
			AllowedCapabilities:      []core.Capability{"*"},
			Volumes: []security.FSType{
				security.FSTypeAll,
			},
			AllowHostNetwork:         true,
			AllowHostPorts:           true,
			AllowHostPID:             true,
			AllowHostIPC:             true,
			AllowPrivilegeEscalation: toBoolPtr(true),
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyRunAsAny,
			},
			Groups: []string{
				"system:cluster-admins",
				"system:nodes",
				"system:masters",
			},
			Users: []string{
				"system:admin",
				"system:serviceaccount:openshift-infra:build-controller",
				"system:serviceaccount:openshift-etcd:etcd-backup",
				"system:serviceaccount:openshift-azure-logging:log-analytics-agent",
				"system:serviceaccount:kube-system:sync",
			},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyRunAsAny,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyRunAsAny,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
			SeccompProfiles: []string{
				"*",
			},
			AllowedUnsafeSysctls: []string{
				"*",
			},
		},
		"restricted": {
			Priority:                 nil,
			AllowPrivilegedContainer: false,
			DefaultAddCapabilities:   nil,
			RequiredDropCapabilities: []core.Capability{"KILL", "MKNOD", "SETUID", "SETGID"},
			AllowedCapabilities:      nil,
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
			TypeMeta:                 metav1.TypeMeta{},
			FSGroup: security.FSGroupStrategyOptions{
				Type: security.FSGroupStrategyMustRunAs,
			},
			Groups: []string{
				"system:authenticated",
			},
			Users: []string{},
			RunAsUser: security.RunAsUserStrategyOptions{
				Type: security.RunAsUserStrategyMustRunAsRange,
			},
			SELinuxContext: security.SELinuxContextStrategyOptions{
				Type: security.SELinuxStrategyMustRunAs,
			},
			SupplementalGroups: security.SupplementalGroupsStrategyOptions{
				Type: security.SupplementalGroupsStrategyRunAsAny,
			},
		},
	}
	return result
}
