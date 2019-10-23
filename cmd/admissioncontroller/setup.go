package main

import (
	"log"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	authorizationapiv1 "github.com/openshift/api/authorization/v1"
	authorizationv1 "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1"
	securityv1 "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregistration "k8s.io/kubernetes/pkg/apis/admissionregistration"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

func toStringPtr(s string) *string {
	return &s
}

func initializeValidatingWebhookConfiguration() *admissionregistration.ValidatingWebhookConfiguration {
	hookconfig := []struct {
		ServicePath *string
		Name        string
		Operations  []admissionregistration.OperationType
		APIGroups   []string
		APIVersions []string
		Resources   []string
	}{
		{
			ServicePath: toStringPtr("/pods"),
			Name:        "pods.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{""},
			APIVersions: []string{"v1"},
			Resources:   []string{"pods"},
		},
		{
			ServicePath: toStringPtr("/daemonsets"),
			Name:        "daemonsets.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"daemonsets"},
		},
		{
			ServicePath: toStringPtr("/replicasets"),
			Name:        "replicasets.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"replicasets"},
		},
		{
			ServicePath: toStringPtr("/statefulsets"),
			Name:        "statefulsets.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"statefulsets"},
		},
		{
			ServicePath: toStringPtr("/jobs"),
			Name:        "jobs.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"batch"},
			APIVersions: []string{"v1"},
			Resources:   []string{"jobs"},
		},
		{
			ServicePath: toStringPtr("/cronjobs"),
			Name:        "cronjobs.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"batch"},
			APIVersions: []string{"v1beta1"},
			Resources:   []string{"cronjobs"},
		},
		{
			ServicePath: toStringPtr("/deploymentconfigs"),
			Name:        "deploymentconfigs.aro-admission-controller.redhat.com",
			Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
			APIGroups:   []string{"apps"},
			APIVersions: []string{"v1"},
			Resources:   []string{"deploymentconfigs"},
		},
		/*		{ //TODO
				ServicePath: "/deployments",
				Name:        "deployments.aro-admission-controller",
				Operations:  []admissionregistration.OperationType{admissionregistration.Create, admissionregistration.Update},
				APIGroups:   []string{"?"},
				APIVersions: []string{"?"},
				Resources:   []string{"deployments"},
			},*/
	}
	failurePolicy := admissionregistration.FailurePolicyType("Fail")
	vwc := admissionregistration.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aro-admission-controller.redhat.com",
		},
		Webhooks: []admissionregistration.Webhook{},
	}

	for _, h := range hookconfig {
		vwc.Webhooks = append(vwc.Webhooks, admissionregistration.Webhook{
			ClientConfig: admissionregistration.WebhookClientConfig{
				Service: &admissionregistration.ServiceReference{
					Name:      "aro-admission-controller",
					Namespace: "kube-system",
					Path:      h.ServicePath,
				},
			},
			FailurePolicy: &failurePolicy,
			Name:          h.Name,
			Rules: []admissionregistration.RuleWithOperations{
				{
					Operations: h.Operations,
					Rule: admissionregistration.Rule{
						APIGroups:   h.APIGroups,
						APIVersions: h.APIVersions,
						Resources:   h.Resources,
					},
				},
			},
		})
	}
	return &vwc
}

func initializeClusterRoleBinding() *authorizationapiv1.ClusterRoleBinding {
	crb := authorizationapiv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aro-admission-controller",
		},
		GroupNames: authorizationapiv1.OptionalNames{"osa-customer-admins"},
		RoleRef: corev1.ObjectReference{
			Kind:       "ClusterRole",
			Name:       "privileged-creator",
			APIVersion: "authorization.openshift.io/v1",
		},
		Subjects: []corev1.ObjectReference{
			{
				Kind: "Group",
				Name: "osacustomer-admins",
			},
		},
	}
	return &crb
}

func setupAdmissionController(client internalclientset.Interface, secclient *securityv1.SecurityV1Client, authclient *authorizationv1.AuthorizationV1Client) {
	//check if 3 admission controller pods are up
	opts := metav1.ListOptions{
		LabelSelector: "openshift.io/component=aro-admission-controller",
	}

	var err error
	var stopCh chan struct{}
	log.Printf("Setup: Waiting until there are 3 aro-admission-controller pods")
	wait.Until(func() {
		{
			var pods *core.PodList
			pods, err = client.Core().Pods("kube-system").List(opts)
			if err != nil {
				log.Fatalf("Setup: Error while listing pods %s", err)
			}
			if len(pods.Items) == 3 {
				allReady := true
				for _, pod := range pods.Items {
					for _, c := range pod.Status.Conditions {
						if c.Type == "Ready" && c.Status != "True" {
							allReady = false
						}
					}
				}
				if allReady {
					log.Printf("Setup: Found 3 aro-admission-controller pods in Ready state, setup continues")
					stopCh <- struct{}{}
				}
			}
		}
	}, 5, stopCh)
	//wait for aro-admission-controller service
	log.Printf("Setup: Waiting for aro-admission-controller service")
	wait.Until(func() {
		time.Sleep(2)
		services, err := client.Core().Services("kube-system").List(opts)
		if err != nil {
			log.Fatalf("Setup: Error while listing services %s", err)
		}
		if len(services.Items) == 1 {
			log.Printf("Setup: Found aro-admission-controller service")
			stopCh <- struct{}{}
		}
	}, 5, stopCh)
	//add validation webhook config
	_, err = client.Admissionregistration().ValidatingWebhookConfigurations().Create(initializeValidatingWebhookConfiguration())
	//TODO verify that if VWC exists, it matches what we're creating
	if err != nil && err.Error() != "validatingwebhookconfigurations.admissionregistration.k8s.io \"aro-admission-controller.redhat.com\" already exists" {
		log.Fatalf("Setup: Error while creating ValidatingWebhookConfiguration: %s", err)
	}

	//remove sync pod ownership from SCCs
	log.Print("Setup: Removing sync pod ownership from SCCs")
	sccs, err := secclient.SecurityContextConstraints().List(metav1.ListOptions{})
	for _, scc := range sccs.Items {
		l := scc.GetLabels()
		if l == nil {
			l = map[string]string{}
		}
		l["azure.openshift.io/owned-by-sync-pod"] = "false"
		scc.SetLabels(l)
	}

	//allow SCC modification
	log.Print("Setup: Adding privileged-creator cluster role to osa-customer-admins")
	_, err = authclient.ClusterRoleBindings().Create(initializeClusterRoleBinding())
	//TODO verify that if CRB exists, it matches what we're creating
	if err != nil && err.Error() != "clusterrolebindings.authorization.openshift.io \"aro-admission-controller\" already exists" {
		log.Fatalf("Error while creating CRB: %s", err)
	}
	log.Print("Setup: done.")
}
