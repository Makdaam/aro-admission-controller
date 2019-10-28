package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"

	_ "github.com/openshift/origin/pkg/api/install"
	oapps "github.com/openshift/origin/pkg/apps/apis/apps"
	"github.com/openshift/origin/pkg/security/apis/security"
	"github.com/openshift/origin/pkg/security/apiserver/securitycontextconstraints"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// verifySCC makes sure that nothing besides additional users or groups are
// different between and SCC and an SCCTemplate.
func verifySCC(scc security.SecurityContextConstraints, sccTemplate security.SecurityContextConstraints) errors.Aggregate {
	var errs []error
	// TODO compare ObjectMeta

	//Allow only if the new Groups are a superset of the template Groups
	for _, templateGroup := range sccTemplate.Groups {
		found := false
		for _, sccGroup := range scc.Groups {
			if templateGroup == sccGroup {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Removal of Group %s from SCC is not allowed", templateGroup))
			break
		}
	}
	//Allow only if the new Users are a superset of the template Groups
	for _, templateUser := range sccTemplate.Users {
		found := false
		for _, sccUser := range scc.Users {
			if templateUser == sccUser {
				found = true
				break
			}
		}
		if !found {
			errs = append(errs, fmt.Errorf("Removal of User %s from SCC is not allowed", templateUser))
			break
		}
	}
	//ignore Users and Groups in further comparison
	localSccTemplate := sccTemplate.DeepCopy()
	localSccTemplate.Users = []string{}
	localSccTemplate.Groups = []string{}
	//added only to remove function side effects
	localScc := scc.DeepCopy()
	//ignore ObjectMeta
	localSccTemplate.ObjectMeta = metav1.ObjectMeta{}
	localSccTemplate.Users = []string{}
	localSccTemplate.Groups = []string{}

	if !reflect.DeepEqual(localScc, localSccTemplate) {
		errs = append(errs, fmt.Errorf("Modification of fields other than Users and Groups in the SCC is not allowed"))
	}
	return errors.NewAggregate(errs)
}

func (ac *admissionController) handleSCC(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scc := o.(*security.SecurityContextConstraints)
	sccTemplate, protected := ac.protectedSCCs[scc.Name]
	if protected {
		//SCC in the set of protected SCCs
		//only allow additional users and groups
		errs := verifySCC(*scc, sccTemplate)
		sendResult(errs, w, req.UID)
	} else {
		//SCC not in the set of protected SCCs
		//allow operation
		sendResult(nil, w, req.UID)
	}
}

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
	if spec.NodeSelector != nil {
		log.Printf("NodeSelector not nil: %v", spec.NodeSelector)
		if spec.NodeSelector["node-role.kubernetes.io/master"] == "true" || spec.NodeSelector["node-role.kubernetes.io/infra"] == "true" {
			return true
		}
	}
	//nodeSelector is not sent in the static Pod review request, but the Node is available
	if strings.HasPrefix(spec.NodeName, "master-") || strings.HasPrefix(spec.NodeName, "infra-") {
		//if it's a pod assigned to a master or infra node it should be able to run
		return true
	}
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	pod := o.(*core.Pod)
	ac.checkPodSpec(pod.Spec, pod.ObjectMeta, pod.Namespace, w, req.UID)
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ds := o.(*extensions.DaemonSet)
	ac.checkPodSpec(ds.Spec.Template.Spec, ds.Spec.Template.ObjectMeta, ds.Namespace, w, req.UID)
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rs := o.(*extensions.ReplicaSet)
	ac.checkPodSpec(rs.Spec.Template.Spec, rs.Spec.Template.ObjectMeta, rs.Namespace, w, req.UID)
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ss := o.(*apps.StatefulSet)
	ac.checkPodSpec(ss.Spec.Template.Spec, ss.Spec.Template.ObjectMeta, ss.Namespace, w, req.UID)
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	job := o.(*batch.Job)
	ac.checkPodSpec(job.Spec.Template.Spec, job.Spec.Template.ObjectMeta, job.Namespace, w, req.UID)
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

	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cj := o.(*batch.CronJob)
	ac.checkPodSpec(cj.Spec.JobTemplate.Spec.Template.Spec, cj.Spec.JobTemplate.Spec.Template.ObjectMeta, cj.Namespace, w, req.UID)
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
	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, _, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	dc := o.(*oapps.DeploymentConfig)
	ac.checkPodSpec(dc.Spec.Template.Spec, dc.Spec.Template.ObjectMeta, dc.Namespace, w, req.UID)
}

func (ac *admissionController) handleDeployment(w http.ResponseWriter, r *http.Request) {
	//TODO finish and test

}

//checkPodSpec checks if the Pod spec is either whitelisted or will match the restricted scc, then prepares an HTTP response
// interface{} is used to allow core.Pod from both the Openshift and Kubernetes APIs
func (ac *admissionController) checkPodSpec(podSpec core.PodSpec, oMeta metav1.ObjectMeta, namespace string, w http.ResponseWriter, uid types.UID) {
	pod := new(core.Pod)
	podSpec.DeepCopyInto(&pod.Spec)
	oMeta.DeepCopyInto(&pod.ObjectMeta)
	errs, err := ac.validatePodAgainstSCC(pod, namespace)
	if err != nil {
		log.Printf("Validation error: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("Review complete")
	sendResult(errs.ToAggregate(), w, uid)
}

func sendResult(errs errors.Aggregate, w http.ResponseWriter, uid types.UID) {
	result := &metav1.Status{
		Status: metav1.StatusSuccess,
	}
	if errs != nil && len(errs.Errors()) > 0 {
		log.Printf("Found %d errs when validating", len(errs.Errors()))
		result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: errs.Error(),
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
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(rev)
	if err != nil {
		log.Fatalf("Error encoding json: %s", err)
	}
}
