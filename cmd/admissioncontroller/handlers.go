package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/apps"
	"k8s.io/kubernetes/pkg/apis/batch"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/extensions"

	"github.com/davecgh/go-spew/spew"
	oapps "github.com/openshift/origin/pkg/apps/apis/apps"
	"github.com/openshift/origin/pkg/security/apis/security"
	"github.com/openshift/origin/pkg/security/apiserver/securitycontextconstraints"

	//installing decoders for openshift resources
	_ "github.com/openshift/origin/pkg/api/install"
)

// verifySCC makes sure that nothing besides additional users or groups are
// different between the SCC and an SCCTemplate.
func verifySCC(scc security.SecurityContextConstraints, sccTemplate security.SecurityContextConstraints) errors.Aggregate {
	var errs []error
	//checking ObjectMeta
	labels := scc.ObjectMeta.GetLabels()
	if labels["azure.openshift.io/owned-by-sync-pod"] != "true" {
		errs = append(errs, fmt.Errorf("Protected SCC has to have the \"azure.openshift.io/owned-by-sync-pod\" label set to true"))
	}

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
	//ignore ObjectMeta in further comparisons
	localScc.ObjectMeta = metav1.ObjectMeta{}
	localScc.Users = []string{}
	localScc.Groups = []string{}
	if !reflect.DeepEqual(localScc, localSccTemplate) {
		errs = append(errs, fmt.Errorf("Modification of fields other than Users and Groups in the SCC is not allowed"))
	}
	return errors.NewAggregate(errs)
}

func (ac *admissionController) handleSCC(w http.ResponseWriter, r *http.Request) {
	req, errcode := getAdmissionReviewRequest(r)
	log.Print("New SCC validation request")
	if errcode != 0 {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}
	if req.Operation == admissionv1beta1.Delete {
		//allow Delete only on SCC which are not in the protected map
		_, protected := ac.protectedSCCs[req.Name]
		if protected {
			errs := []error{fmt.Errorf("Deleting of this SCC is not allowed")}
			sendResult(errors.NewAggregate(errs), w, req.UID)
		} else {
			sendResult(nil, w, req.UID)
		}
		return
	}
	//if Operation is Create,Update (Connect not configured in ValidatingWebhookConfiguration)
	//gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	log.Printf("TODO B %#v", string(req.Object.Raw))
	o, _, err := codec.Decode(req.Object.Raw, nil, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	scc := o.(*security.SecurityContextConstraints)
	spew.Dump(scc)
	sccTemplate, protected := ac.protectedSCCs[scc.Name]
	log.Printf("TODO C %s", scc.ObjectMeta.Name)
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

func (ac *admissionController) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	unpackers := map[string]func(runtime.Object) (core.PodSpec, metav1.ObjectMeta, string){
		"Pod": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			pod := o.(*core.Pod)
			return pod.Spec, pod.ObjectMeta, pod.Namespace
		},
		"DaemonSet": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			ds := o.(*extensions.DaemonSet)
			return ds.Spec.Template.Spec, ds.Spec.Template.ObjectMeta, ds.Namespace
		},
		"ReplicaSet": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			rs := o.(*extensions.ReplicaSet)
			return rs.Spec.Template.Spec, rs.Spec.Template.ObjectMeta, rs.Namespace
		},
		"StatefulSet": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			ss := o.(*apps.StatefulSet)
			return ss.Spec.Template.Spec, ss.Spec.Template.ObjectMeta, ss.Namespace
		},
		"Job": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			job := o.(*batch.Job)
			return job.Spec.Template.Spec, job.Spec.Template.ObjectMeta, job.Namespace
		},
		"CronJob": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			cj := o.(*batch.CronJob)
			return cj.Spec.JobTemplate.Spec.Template.Spec, cj.Spec.JobTemplate.Spec.Template.ObjectMeta, cj.Namespace
		},
		"DeploymentConfig": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			dc := o.(*oapps.DeploymentConfig)
			return dc.Spec.Template.Spec, dc.Spec.Template.ObjectMeta, dc.Namespace
		},
		"Deployment": func(o runtime.Object) (core.PodSpec, metav1.ObjectMeta, string) {
			dp := o.(*extensions.Deployment)
			return dp.Spec.Template.Spec, dp.Spec.Template.ObjectMeta, dp.Namespace
		},
	}
	req, errcode := getAdmissionReviewRequest(r)
	if errcode != 0 {
		http.Error(w, http.StatusText(errcode), errcode)
		return
	}
	log.Printf("TODO A %s", req.Name)
	if req.UID == "" || req.Kind.Version == "" || req.Kind.Kind == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	gvk := schema.GroupVersionKind{Group: req.Kind.Group, Version: req.Kind.Version, Kind: req.Kind.Kind}
	o, gvkDecoded, err := codec.Decode(req.Object.Raw, &gvk, nil)
	if err != nil {
		log.Printf("Decode error:  %s", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	unpackingFunc, found := unpackers[gvkDecoded.Kind]
	if !found {
		http.Error(w, http.StatusText(http.StatusNotImplemented), http.StatusNotImplemented)
	}
	spec, meta, namespace := unpackingFunc(o)

	ac.checkPodSpec(spec, meta, namespace, w, req.UID)
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
		log.Printf("Error:%s", errs.Error())
		result = &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: errs.Error(),
		}
	} else {
		log.Print("No errors found, approved")
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
