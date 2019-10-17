package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	appsv1 "github.com/openshift/api/apps/v1"
	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
	"github.com/openshift/origin/pkg/security/apis/security"
	"github.com/openshift/origin/pkg/security/apiserver/securitycontextconstraints"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	//"k8s.io/kubernetes/pkg/apis/apps"
	//"k8s.io/kubernetes/pkg/apis/batch"
	//"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"

	"github.com/davecgh/go-spew/spew"
)

/*
Overview:

Until now, ARO customers have not been able to modify SecurityContextConstraints
(SCCs), and as with out-of-the-box OpenShift, customer workload executes under
the `restricted` SCC, enforcing that it cannot run as privileged, etc.

There is demand for enabling 3rd party workloads to run as privileged
containers.  This POC attempts a whitelisting approach via a new admission
controller.  The idea is that customer admins will be able to run privileged
workloads, as long as those workloads exclusively use whitelisted images.  The
intended mechanics are as follows:

* All customer workload will continue to be bound to compute nodes via the
  `openshift.io/node-selector` namespace annotation mechanism.  As today, no
  customer workload will run on infra or master nodes, whether privileged or
  not.

* (TBD:) customer admins will become able to modify SCCs in a way that does not
  prejudice the ARO service.  RBAC or an(other) admission controller are two
  possible approaches to lock this down.  At a minimum, a customer needs to be
  able to add service accounts of their choice to the privileged SCC.

* Customer workload with whitelisted images will run with whichever SCC the
  customer assigns, matching regular OpenShift behaviour.  For all other
  (non-whitelisted) workload, this admission controller will manually validate
  that it conforms with the *bootstrap* `restricted` SCC, rejecting a pod if
  not.
*/
/*
Current status:

Compiles, unit test passes.

For now, checkout github.com/openshift/origin on the release-3.11 branch and put
these files in a newly created package somewhere under there.
*/
/*
TODOs:

* required to prove the concept:
  * listen on TLS
  * set up manually on a FakeRP ARO cluster and test

* required to ship:
  * determine and implement mechanism to allow customers to modify SCCs without
    prejudicing the service
  * work out where to host the code.  The azure image/entrypoint?  Might depend
    on revendor complexity
  * automate generation of TLS client and server certificates in ARO (add new
    CA-signed ones in generate.go?)
  * update cluster create/upgrade procedures to add admission controller via
    sync pod.  Must the admission controller run directly as a process on the
    masters (i.e. outside of OpenShift)?
  * implement unit and e2e tests
  * add suitable logging and metrics
  * make whitelisted images configurable
*/

var (
	serializer = kjson.NewSerializer(kjson.DefaultMetaFactory, legacyscheme.Scheme, legacyscheme.Scheme, false)
	codec      = legacyscheme.Codecs.CodecForVersions(nil, serializer, nil, runtime.InternalGroupVersioner)
)

// TODO: populate from config file
var whitelistedImages = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^whitelistedimage1$`),
	regexp.MustCompile(`(?i)^whitelistedimage2$`),
	//regexp.MustCompile(`.+prometheus-example.+`),
}

// imageIsWhitelisted returns true if the image matches any whitelistedImages
// regular expression
func imageIsWhitelisted(image string) bool {
	for _, rx := range whitelistedImages {
		if rx.MatchString(image) {
			return true
		}
	}
	return false
}

// podIsWhitelisted returns true if all images of all containers are whitelisted
func podSpecIsWhitelisted(spec *core.PodSpec) bool {
	containers := append([]core.Container{}, spec.Containers...)
	containers = append(containers, spec.InitContainers...)

	for _, c := range containers {
		if !imageIsWhitelisted(c.Image) {
			return false
		}
	}

	return true
}

type admissionController struct {
	client     internalclientset.Interface
	restricted *security.SecurityContextConstraints
}

func (ac *admissionController) run() error {
	mux := &http.ServeMux{}
	mux.HandleFunc("/pods", ac.handlePod)
	mux.HandleFunc("/daemonsets", ac.handleDaemonSet)
	mux.HandleFunc("/replicasets", ac.handleReplicaSet)
	mux.HandleFunc("/statefulsets", ac.handleStatefulSet)
	mux.HandleFunc("/jobs", ac.handleJob)
	mux.HandleFunc("/cronjobs", ac.handleCronJob)
	mux.HandleFunc("/deploymentconfigs", ac.handleCronJob)

	//TODO generate proper separate certs
	err := http.ListenAndServeTLS(":443", "/home/cloud-user/adc.crt", "/home/cloud-user/adc.key", mux)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}

func getAdmissionReviewRequest(r *http.Request) (req *admissionv1beta1.AdmissionRequest, errorcode int) {
	log.Printf("New review request")
	if r.Method != http.MethodPost {
		return nil, http.StatusMethodNotAllowed
	}
	if r.Header.Get("Content-Type") != "application/json" {

		return nil, http.StatusUnsupportedMediaType
	}
	var reviewIncoming *admissionv1beta1.AdmissionReview
	err := json.NewDecoder(r.Body).Decode(&reviewIncoming)
	req = reviewIncoming.Request
	if err != nil {
		return nil, http.StatusBadRequest
	}
	return req, 0
}

func (ac *admissionController) handlePod(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "" || req.Kind.Version != "v1" || req.Kind.Kind != "Pod" ||
		req.Resource.Group != "" || req.Resource.Version != "v1" || req.Resource.Resource != "pods" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = ""
	podschema.Version = "v1"
	podschema.Kind = "Pod"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pod := o.(*core.Pod)
	spew.Dump(pod)
	ac.checkPodSpec(pod, pod.Namespace, w, req.UID)
}

func (ac *admissionController) handleDaemonSet(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "DaemonSet" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "daemonsets" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "DaemonSet"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*extensions.DaemonSet)

	pod := new(core.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleReplicaSet(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "ReplicaSet" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "replicasets" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "ReplicaSet"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*extensions.ReplicaSet)

	pod := new(core.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleStatefulSet(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "StatefulSet" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "statefulsets" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "StatefulSet"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*apps.StatefulSet)

	pod := new(core.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleJob(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "batch" || req.Kind.Version != "v1" || req.Kind.Kind != "Job" ||
		req.Resource.Group != "batch" || req.Resource.Version != "v1" || req.Resource.Resource != "jobs" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "batch"
	podschema.Version = "v1"
	podschema.Kind = "Job"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*batch.Job)

	pod := new(core.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleCronJob(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "batch" || req.Kind.Version != "v1beta1" || req.Kind.Kind != "CronJob" ||
		req.Resource.Group != "batch" || req.Resource.Version != "v1beta1" || req.Resource.Resource != "cronjobs" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "batch"
	podschema.Version = "v1beta1"
	podschema.Kind = "CronJob"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*batch.CronJob)

	pod := new(core.Pod)
	ds.Spec.JobTemplate.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.JobTemplate.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleDeploymentConfig(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "DeploymentConfig" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "deploymentconfigs" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "DeploymentConfig"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*appsv1.DeploymentConfig)

	pod := new(corev1.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

func (ac *admissionController) handleDeployment(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "DeploymentConfig" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "deploymentconfigs" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "DeploymentConfig"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*appsv1.DeploymentConfig)

	pod := new(corev1.Pod)
	ds.Spec.Template.Spec.DeepCopyInto(&pod.Spec)
	ds.Spec.Template.ObjectMeta.DeepCopyInto(&pod.ObjectMeta)
	ac.checkPodSpec(pod, ds.Namespace, w, req.UID)
}

//checkPodSpec checks if the Pod spec is either whitelisted or will match the restricted scc, then prepares an HTTP response
// interface{} is used to allow core.Pod from both the Openshift and Kubernetes APIs
func (ac *admissionController) checkPodSpec(podi interface{}, namespace string, w http.ResponseWriter, uid types.UID) {
	pod := podi.(*core.Pod)
	spew.Dump(pod)
	errs, err := ac.validatePodAgainstSCC(pod, namespace)
	if err != nil {
		log.Printf("Validation error: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result := &metav1.Status{
		Status: metav1.StatusSuccess,
	}
	if len(errs) > 0 {
		log.Printf("Found %d errs when validating", len(errs))
		result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: errs.ToAggregate().Error(),
		}
	}
	rev := &admissionv1beta1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: admissionv1beta1.SchemeGroupVersion.String(),
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1beta1.AdmissionResponse{
			UID:     uid,
			Allowed: result.Status == metav1.StatusSuccess,
			Result:  result,
		},
	}
	log.Printf("Review complete")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rev)
}

func (ac *admissionController) validatePodAgainstSCC(pod *core.Pod, namespace string) (field.ErrorList, error) {
	if podSpecIsWhitelisted(&pod.Spec) {
		log.Printf("Pod is whitelisted")
		return nil, nil
	}
	log.Printf("Pod is not whitelisted")
	provider, _, err := securitycontextconstraints.CreateProviderFromConstraint(namespace, nil, ac.restricted, ac.client)
	if err != nil {
		return nil, err
	}

	return securitycontextconstraints.AssignSecurityContext(provider, pod, field.NewPath(fmt.Sprintf("provider %s: ", provider.GetSCCName()))), nil
}

func getRestrictedSCC() (*security.SecurityContextConstraints, error) {
	var restricted *security.SecurityContextConstraints

	groups, users := bootstrappolicy.GetBoostrapSCCAccess(bootstrappolicy.DefaultOpenShiftInfraNamespace)
	for _, scc := range bootstrappolicy.GetBootstrapSecurityContextConstraints(groups, users) {
		if scc.Name == bootstrappolicy.SecurityContextConstraintRestricted {
			restricted = scc
		}
	}
	if restricted == nil {
		return nil, fmt.Errorf("couldn't find restricted SCC in bootstrappolicy")
	}

	return restricted, nil
}

func run() error {
	// TODO: read TLS certificates and whitelist from a config file

	restricted, err := getRestrictedSCC()
	if err != nil {
		return err
	}

	kubeconfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{},
	)

	restconfig, err := kubeconfig.ClientConfig()
	if err != nil {
		return err
	}

	client, err := internalclientset.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	ac := &admissionController{
		client:     client,
		restricted: restricted,
	}

	return ac.run()
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
