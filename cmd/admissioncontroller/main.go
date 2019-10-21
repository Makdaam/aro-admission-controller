package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"

	"github.com/openshift/origin/pkg/cmd/server/bootstrappolicy"
	"github.com/openshift/origin/pkg/security/apis/security"
	"gopkg.in/yaml.v2"

	"k8s.io/apimachinery/pkg/runtime"
	kjson "k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubernetes/pkg/api/legacyscheme"

	//"k8s.io/kubernetes/pkg/apis/apps"
	//"k8s.io/kubernetes/pkg/apis/batch"
	//"k8s.io/kubernetes/pkg/apis/core"

	authorizationv1 "github.com/openshift/client-go/authorization/clientset/versioned/typed/authorization/v1"
	securityv1 "github.com/openshift/client-go/security/clientset/versioned/typed/security/v1"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
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

type config struct {
	Whitelist []string `json:"whitelist"`
}

func (c *config) loadConfig() *config {
	configFile, err := ioutil.ReadFile("/etc/aro-admission-controller/aro-admission-controller.yaml")
	if err != nil {
		log.Printf("Error reading config file %s", err)
	}
	err = yaml.Unmarshal(configFile, c)
	if err != nil {
		log.Fatalf("Error unmarshalling config file %s", err)
	}

	return c
}

func (c *config) validate() error {
	var err error
	for _, w := range c.Whitelist {
		_, err = regexp.Compile(w)
	}
	return err
}

// imageIsWhitelisted returns true if the image matches any whitelistedImages
// regular expression

type admissionController struct {
	client            internalclientset.Interface
	restricted        *security.SecurityContextConstraints
	whitelistedImages []*regexp.Regexp
}

func (ac *admissionController) run() error {
	mux := &http.ServeMux{}
	mux.HandleFunc("/pods", ac.handlePod)
	mux.HandleFunc("/daemonsets", ac.handleDaemonSet)
	mux.HandleFunc("/replicasets", ac.handleReplicaSet)
	mux.HandleFunc("/statefulsets", ac.handleStatefulSet)
	mux.HandleFunc("/jobs", ac.handleJob)
	mux.HandleFunc("/cronjobs", ac.handleCronJob)
	mux.HandleFunc("/deploymentconfigs", ac.handleDeploymentConfig)
	// TODO
	//mux.HandleFunc("/deployments", ac.handleDeployment)
	mux.HandleFunc("/healthz", ac.handleHealthz)
	mux.HandleFunc("/healthz/ready", ac.handleHealthz)

	log.Print("Aro Admission Controller starting.")
	err := http.ListenAndServeTLS(":8443", "/etc/aro-admission-controller/aro-admission-controller.crt", "/etc/aro-admission-controller/aro-admission-controller.key", mux)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
	return err
}

func (ac *admissionController) handleHealthz(w http.ResponseWriter, r *http.Request) {
	return
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
	var c config
	var whitelistedImages = []*regexp.Regexp{}
	c.loadConfig()
	for _, w := range c.Whitelist {
		whitelistedImages = append(whitelistedImages, regexp.MustCompile(w))
	}
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
		restconfig, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	}

	client, err := internalclientset.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	secclient, err := securityv1.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	authclient, err := authorizationv1.NewForConfig(restconfig)
	if err != nil {
		return err
	}

	ac := &admissionController{
		client:            client,
		restricted:        restricted,
		whitelistedImages: whitelistedImages,
	}

	go setupAdmissionController(client, secclient, authclient)
	return ac.run()
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
