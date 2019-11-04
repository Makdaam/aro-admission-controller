package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"testing"

	_ "github.com/openshift/origin/pkg/api/install"
	"github.com/openshift/origin/pkg/security/apis/security"
	_ "github.com/openshift/origin/pkg/security/apis/security/install"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset/fake"
)

type fakeResponseWriter struct {
	statusCode int
	h          http.Header
	bytes.Buffer
}

func newFakeResponseWriter() *fakeResponseWriter {
	return &fakeResponseWriter{
		h:          map[string][]string{},
		statusCode: http.StatusOK,
	}
}

func (w *fakeResponseWriter) Header() http.Header {
	return w.h
}

func (w *fakeResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}

func (w *fakeResponseWriter) Dump() {
	fmt.Printf("HTTP %d %s\r\n", w.statusCode, http.StatusText(w.statusCode))
	w.h.Write(os.Stdout)
	fmt.Print("\r\n")
	os.Stdout.Write(w.Bytes())
}

func TestHandleMalformedRequests(t *testing.T) {
	client := fake.NewSimpleClientset(&core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				"openshift.io/sa.scc.uid-range": "1000/10",
				"openshift.io/sa.scc.mcs":       "mcs",
			},
		},
	})

	restricted, err := getRestrictedSCC()
	if err != nil {
		t.Fatal(err)
	}

	ac := &admissionController{
		client:     client,
		restricted: restricted,
	}

	pod, err := json.Marshal(&corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Image: "regularimage",
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	req, err := json.Marshal(&admissionv1beta1.AdmissionReview{
		Request: &admissionv1beta1.AdmissionRequest{
			UID:      "uid",
			Kind:     metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			Object: runtime.RawExtension{
				Raw: pod,
			},
		}})
	if err != nil {
		t.Fatal(err)
	}

	reqNoUID, err := json.Marshal(&admissionv1beta1.AdmissionReview{
		Request: &admissionv1beta1.AdmissionRequest{
			UID:      "",
			Kind:     metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
			Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			Object: runtime.RawExtension{
				Raw: pod,
			},
		}})
	if err != nil {
		t.Fatal(err)
	}

	reqNoVersionKind, err := json.Marshal(&admissionv1beta1.AdmissionReview{
		Request: &admissionv1beta1.AdmissionRequest{
			UID:      "uid",
			Kind:     metav1.GroupVersionKind{},
			Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
			Object: runtime.RawExtension{
				Raw: pod,
			},
		}})
	if err != nil {
		t.Fatal(err)
	}
	reqWrongContent, err := json.Marshal(&admissionv1beta1.AdmissionReview{
		Request: &admissionv1beta1.AdmissionRequest{
			UID:      "uid",
			Kind:     metav1.GroupVersionKind{Group: "apps", Version: "v1", Kind: "DaemonSet"},
			Resource: metav1.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"},
			Object: runtime.RawExtension{
				Raw: []byte("{\"wrong\":true}"),
			},
		}})
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name     string
		request  *http.Request
		response *fakeResponseWriter
	}{
		{
			name: "bad request method",
			request: &http.Request{
				Method: http.MethodGet,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(req)),
			},
			response: &fakeResponseWriter{
				statusCode: 405,
				h: http.Header{
					"X-Content-Type-Options": []string{"nosniff"},
					"Content-Type":           []string{"text/plain; charset=utf-8"},
				},
			},
		},
		{
			name: "bad Content-Type",
			request: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/pdf"}},
				Body:   ioutil.NopCloser(bytes.NewReader(req)),
			},
			response: &fakeResponseWriter{
				statusCode: 415,
				h: http.Header{
					"X-Content-Type-Options": []string{"nosniff"},
					"Content-Type":           []string{"text/plain; charset=utf-8"},
				},
			},
		},
		{
			name: "bad content",
			request: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader([]byte("this is not JSON"))),
			},
			response: &fakeResponseWriter{
				statusCode: 400,
				h: http.Header{
					"X-Content-Type-Options": []string{"nosniff"},
					"Content-Type":           []string{"text/plain; charset=utf-8"},
				},
			},
		},
		{
			name: "no UID",
			request: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(reqNoUID)),
			},
			response: &fakeResponseWriter{
				statusCode: 400,
				h: http.Header{
					"X-Content-Type-Options": []string{"nosniff"},
					"Content-Type":           []string{"text/plain; charset=utf-8"},
				},
			},
		},
		{
			name: "no version, kind",
			request: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(reqNoVersionKind)),
			},
			response: &fakeResponseWriter{
				statusCode: 400,
				h: http.Header{
					"X-Content-Type-Options": []string{"nosniff"},
					"Content-Type":           []string{"text/plain; charset=utf-8"},
				},
			},
		},
		{
			name: "wrong version, kind, good content",
			request: &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(reqWrongContent)),
			},
			response: &fakeResponseWriter{
				statusCode: 200,
				h: http.Header{
					"Content-Type": []string{"application/json"},
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			w := newFakeResponseWriter()

			ac.handleWhitelist(w, test.request)
			if w.statusCode != test.response.statusCode {
				t.Errorf("handleWhitelist bad status code %d, expected %d", w.statusCode, test.response.statusCode)
			}
			if !reflect.DeepEqual(w.h, test.response.h) {
				t.Errorf("handleWhitelist got response headers %#v, expected %#v", w.h, test.response.h)
			}
		})
	}
}

func TestHandleWhitelistHappyPath(t *testing.T) {
	client := fake.NewSimpleClientset(&core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				"openshift.io/sa.scc.uid-range": "1000/10",
				"openshift.io/sa.scc.mcs":       "mcs",
			},
		},
	})

	restricted, err := getRestrictedSCC()
	if err != nil {
		t.Fatal(err)
	}

	var whitelistedImages = []*regexp.Regexp{
		regexp.MustCompile("^whitelistedimage1$"),
		regexp.MustCompile("^whitelistedimage2$"),
	}
	ac := &admissionController{
		client:            client,
		restricted:        restricted,
		whitelistedImages: whitelistedImages,
	}

	for _, test := range []struct {
		name     string
		podSpec  corev1.PodSpec
		response *admissionv1beta1.AdmissionResponse
	}{
		{
			name: "regular non-privileged image, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regularimage",
					},
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
		{
			name: "regular privileged image, don't allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regularimage",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: false,
				Result: &metav1.Status{
					Status:  metav1.StatusFailure,
					Message: "spec.containers[0].securityContext.privileged: Invalid value: true: Privileged containers are not allowed",
				},
			},
		},
		{
			name: "whitelisted non-privileged image, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "whitelistedimage1",
					},
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
		{
			name: "whitelisted privileged image, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "whitelistedimage1",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
		{
			name: "regular privileged image, annotated with master node selector, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regulardimage",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
				NodeSelector: map[string]string{
					"node-role.kubernetes.io/master": "true",
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
		{
			name: "regular privileged image, annotated with infra node selector, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regulardimage",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
				NodeSelector: map[string]string{
					"node-role.kubernetes.io/infra": "true",
				},
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},

		{
			name: "regular privileged image, assigned to master node, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regulardimage",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
				NodeName: "master-000000",
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
		{
			name: "regular privileged image, assigned to infra node, allow",
			podSpec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Image: "regulardimage",
						SecurityContext: &corev1.SecurityContext{
							Privileged: &[]bool{true}[0],
						},
					},
				},
				NodeName: "infra-123456-000002",
			},
			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: true,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			pod, err := json.Marshal(&corev1.Pod{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "default",
				},
				Spec: test.podSpec,
			})
			if err != nil {
				t.Fatal(err)
			}

			req, err := json.Marshal(&admissionv1beta1.AdmissionReview{
				Request: &admissionv1beta1.AdmissionRequest{
					UID:      "uid",
					Kind:     metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
					Resource: metav1.GroupVersionResource{Version: "v1", Resource: "pods"},
					Object: runtime.RawExtension{
						Raw: pod,
					},
				}})
			if err != nil {
				t.Fatal(err)
			}

			//log.Printf("%s", string(req))

			r := &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(req)),
			}

			w := newFakeResponseWriter()

			ac.handleWhitelist(w, r)

			if w.statusCode != 200 {
				t.Errorf("got status code %d, %s", w.statusCode, w.Buffer.String())
			}
			if !reflect.DeepEqual(w.Header(), http.Header{"Content-Type": []string{"application/json"}}) {
				t.Errorf("got header %#v", w.Header())
			}

			var rev *admissionv1beta1.AdmissionReview
			err = json.NewDecoder(w).Decode(&rev)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(rev.Response, test.response) {
				t.Errorf("got respose %#v", rev.Response)
			}
		})
	}
}

func TestHandleSCCHappyPath(t *testing.T) {
	client := fake.NewSimpleClientset(&core.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Annotations: map[string]string{
				"openshift.io/sa.scc.uid-range": "1000/10",
				"openshift.io/sa.scc.mcs":       "mcs",
			},
		},
	})

	ac := &admissionController{
		client: client,
	}
	ac.protectedSCCs = ac.InitProtectedSCCs()

	for _, test := range []struct {
		name     string
		scc      security.SecurityContextConstraints
		response *admissionv1beta1.AdmissionResponse
	}{
		{
			name: "protected SCC, changed allowprivilegedcontainer, forbid",
			scc: security.SecurityContextConstraints{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anyuid",
				},
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.openshift.io/v1",
					Kind:       "SecurityContextConstraints",
				},
				Priority:                 toInt32Ptr(10),
				AllowPrivilegedContainer: true, //changed vs template
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

			response: &admissionv1beta1.AdmissionResponse{
				UID:     "uid",
				Allowed: false,
				Result: &metav1.Status{
					Status: metav1.StatusSuccess,
				},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var scc bytes.Buffer
			err := codec.Encode(&test.scc, &scc)
			if err != nil {
				t.Fatal(err)
			}
			req, err := json.Marshal(&admissionv1beta1.AdmissionReview{
				Request: &admissionv1beta1.AdmissionRequest{
					UID:       "uid",
					Operation: admissionv1beta1.Update,
					Kind:      metav1.GroupVersionKind{Group: "security.openshift.io", Version: "v1", Kind: "SecurityContextConstraints"},
					Resource:  metav1.GroupVersionResource{Group: "security.openshift.io", Version: "v1", Resource: "securitycontextconstraints"},
					Name:      test.scc.ObjectMeta.Name,
					Object: runtime.RawExtension{
						Raw: scc.Bytes(),
					},
				}})
			if err != nil {
				t.Fatal(err)
			}

			//log.Printf("%s", string(req))

			r := &http.Request{
				Method: http.MethodPost,
				Header: http.Header{"Content-Type": []string{"application/json"}},
				Body:   ioutil.NopCloser(bytes.NewReader(req)),
			}

			w := newFakeResponseWriter()

			ac.handleSCC(w, r)

			if w.statusCode != 200 {
				t.Errorf("got status code %d, %s", w.statusCode, w.Buffer.String())
			}
			if !reflect.DeepEqual(w.Header(), http.Header{"Content-Type": []string{"application/json"}}) {
				t.Errorf("got header %#v", w.Header())
			}

			var rev *admissionv1beta1.AdmissionReview
			err = json.NewDecoder(w).Decode(&rev)
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(rev.Response, test.response) {
				t.Errorf("got respose %#v", rev.Response)
			}
		})
	}
}
