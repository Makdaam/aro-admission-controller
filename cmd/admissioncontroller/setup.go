package main

import (
	"log"
	"time"

	securityv1 "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	admissionregistration "k8s.io/kubernetes/pkg/apis/admissionregistration"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
)

func toStringPtr(s string) *string {
	return &s
}

func initializeValidatingWebhookConfiguration() *admissionregistration.ValidatingWebhookConfiguration {
	//TODO add full configuration
	failurePolicy := admissionregistration.FailurePolicyType("Fail")
	vwc := admissionregistration.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aro-admission-controller",
		},
		Webhooks: []admissionregistration.Webhook{
			{ClientConfig: admissionregistration.WebhookClientConfig{
				Service: &admissionregistration.ServiceReference{
					Name:      "aro-admission-controller",
					Namespace: "kube-system",
					Path:      toStringPtr("/cronjobs"),
				},
			},
				FailurePolicy: &failurePolicy,
				Name:          "cronjobs.aro-admission-controller",
				Rules: []admissionregistration.RuleWithOperations{
					{
						Operations: []admissionregistration.OperationType{"CREATE", "UPDATE"},
						Rule: admissionregistration.Rule{
							APIGroups:   []string{"batch"},
							APIVersions: []string{"v1beta1"},
							Resources:   []string{"cronjobs"},
						},
					},
				},
			},
		},
	}
	return &vwc
}

func setupAdmissionController(client internalclientset.Interface, secclient *securityv1.SecurityV1Client) {
	//check if 3 admission controller pods are up
	opts := metav1.ListOptions{
		LabelSelector: "openshift.io/component=aro-admission-controller",
	}
	var pods *core.PodList
	var err error
	log.Printf("Setup: Waiting until there are 3 aro-admission-controller pods")
	for {
		//give some time to other pods
		time.Sleep(2)
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
				break
			}
		}
	}
	//add validation webhook config
	_, err = client.Admissionregistration().ValidatingWebhookConfigurations().Create(initializeValidatingWebhookConfiguration())
	if err != nil {
		log.Fatalf("Setup: Error while creating ValidatingWebhookConfiguration: %s", err)
	}

	//remove sync pod ownership from SCCs
	log.Print("Setup: Removing sync pod ownership from SCCs", err)
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
	log.Print("Setup: Removing sync pod ownership from SCCs", err)
	log.Print("Setup: done.")
}
