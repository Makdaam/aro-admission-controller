package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"

	appsv1 "github.com/openshift/api/apps/v1"
	"github.com/openshift/origin/pkg/security/apiserver/securitycontextconstraints"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func imageIsWhitelisted(image string, whitelistedImages []*regexp.Regexp) bool {
	for _, rx := range whitelistedImages {
		if rx.MatchString(image) {
			return true
		}
	}
	return false
}

// podIsWhitelisted returns true if all images of all containers are whitelisted
func podSpecIsWhitelisted(spec *core.PodSpec, whitelistedImages []*regexp.Regexp) bool {
	containers := append([]core.Container{}, spec.Containers...)
	containers = append(containers, spec.InitContainers...)

	for _, c := range containers {
		log.Printf("Image %s", c.Image)
		if !imageIsWhitelisted(c.Image, whitelistedImages) {
			return false
		}
	}

	return true
}

func (ac *admissionController) validatePodAgainstSCC(pod *core.Pod, namespace string) (field.ErrorList, error) {
	if podSpecIsWhitelisted(&pod.Spec, ac.whitelistedImages) {
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

func getAdmissionReviewRequest(r *http.Request) (req *admissionv1beta1.AdmissionRequest, errorcode int) {
	log.Printf("New review request %s", r.RequestURI)
	if r.Method != http.MethodPost {
		return nil, http.StatusMethodNotAllowed
	}
	if r.Header.Get("Content-Type") != "application/json" {

		return nil, http.StatusUnsupportedMediaType
	}
	var reviewIncoming *admissionv1beta1.AdmissionReview
	err := json.NewDecoder(r.Body).Decode(&reviewIncoming)
	if err != nil {
		return nil, http.StatusBadRequest
	}
	req = reviewIncoming.Request
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
	log.Printf("K %s %s %s", req.Kind.Group, req.Kind.Version, req.Kind.Kind)
	log.Printf("R %s %s %s", req.Resource.Group, req.Resource.Version, req.Resource.Resource)
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
	//TODO finish and test
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.UID == "" ||
		req.Kind.Group != "apps" || req.Kind.Version != "v1" || req.Kind.Kind != "Deployment" ||
		req.Resource.Group != "apps" || req.Resource.Version != "v1" || req.Resource.Resource != "deployments" ||
		req.SubResource != "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		log.Printf("Field mismatch")
		return
	}

	var podschema schema.GroupVersionKind
	podschema.Group = "apps"
	podschema.Version = "v1"
	podschema.Kind = "Deployment"
	o, _, err := codec.Decode(req.Object.Raw, &podschema, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	//TODO correct this
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
	err = json.NewEncoder(w).Encode(rev)
	if err != nil {
		log.Fatalf("Error encoding json: %s", err)
	}
}

func (ac *admissionController) handleSCC(w http.ResponseWriter, r *http.Request) {
	//TODO
}
