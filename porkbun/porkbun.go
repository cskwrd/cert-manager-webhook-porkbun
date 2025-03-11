package porkbun

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	klog "k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"

	porkbunapi "github.com/nrdcg/porkbun"
)

// porkbunSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type porkbunSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// ~~1. uncomment the additional `client` field in this structure below~~
	// ~~2. add the "k8s.io/client-go/kubernetes" import at the top of the file~~
	// ~~3. uncomment the relevant code in the Initialize method below~~
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	kubernetesClientset kubernetes.Interface
	isUnitTest          bool
	pbClient            *porkbunapi.Client
}

// porkbunSolverConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type porkbunSolverConfig struct {
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	ApiKeySecretRef    corev1.SecretKeySelector `json:"apiKeySecretRef"`
	SecretKeySecretRef corev1.SecretKeySelector `json:"secretKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be uniqup **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (p *porkbunSolver) Name() string {
	return "porkbun"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (p *porkbunSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Handling present request for %q %q", ch.ResolvedFQDN, ch.Key)

	cfg, err := unmarshalConfig(ch.Config)
	if err != nil {
		return err
	}

	apiClient, err := p.createPorkbunApiClient(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	entity := strings.TrimSuffix(ch.ResolvedFQDN, "."+ch.ResolvedZone)
	name := strings.TrimSuffix(ch.ResolvedFQDN, ".")

	records, err := apiClient.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return err
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			klog.Infof("Record exists: %s", record.ID)
			return nil
		}
	}

	id, err := apiClient.CreateRecord(context.Background(), domain, porkbunapi.Record{
		Name:    entity,
		Type:    "TXT",
		Content: ch.Key,
		TTL:     "60",
	})
	if err != nil {
		return err
	}

	klog.Infof("Created record %v", id)
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (p *porkbunSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.Infof("Handling cleanup request for %q %q", ch.ResolvedFQDN, ch.Key)

	cfg, err := unmarshalConfig(ch.Config)
	if err != nil {
		return err
	}

	apiClient, err := p.createPorkbunApiClient(cfg, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	name := strings.TrimSuffix(ch.ResolvedFQDN, ".")
	records, err := apiClient.RetrieveRecords(context.Background(), domain)
	if err != nil {
		return err
	}

	for _, record := range records {
		if record.Type == "TXT" && record.Name == name && record.Content == ch.Key {
			id, err := strconv.ParseInt(record.ID, 10, 32)
			if err != nil {
				return err
			}

			record.Content = ch.Key
			err = apiClient.DeleteRecord(context.Background(), domain, int(id))
			if err != nil {
				return err
			}

			klog.Infof("Deleted record %v", id)
			return nil
		}
	}

	klog.Info("No matching record to delete")

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (p *porkbunSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	klog.Info("Initializing")

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	p.kubernetesClientset = cl

	return nil
}

func New() webhook.Solver {
	return &porkbunSolver{
		isUnitTest: false,
	}
}

func NewFromFakeObjects(kubeClient kubernetes.Interface, porkbunApiClient *porkbunapi.Client) webhook.Solver {
	return &porkbunSolver{
		kubernetesClientset: kubeClient,
		isUnitTest:          true,
		pbClient:            porkbunApiClient,
	}
}

func (p *porkbunSolver) createPorkbunApiClient(cfg porkbunSolverConfig, resourceNamespace string) (*porkbunapi.Client, error) {
	apiKey, err := p.fromSecretRef(cfg.ApiKeySecretRef, resourceNamespace)
	if err != nil {
		return nil, err
	}

	secretKey, err := p.fromSecretRef(cfg.SecretKeySecretRef, resourceNamespace)
	if err != nil {
		return nil, err
	}

	if !p.isUnitTest {
		return porkbunapi.New(apiKey, secretKey), nil
	}
	return p.pbClient, nil
}

func (p *porkbunSolver) fromSecretRef(secretKeySelector corev1.SecretKeySelector, resourceNamespace string) (string, error) {
	secretName := secretKeySelector.Name

	secret, err := p.kubernetesClientset.CoreV1().Secrets(resourceNamespace).Get(context.Background(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	keyInSecret := secretKeySelector.Key

	bytes, ok := secret.Data[keyInSecret]
	if !ok {
		return "", err
	}

	return string(bytes), nil
}

// unmarshalConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func unmarshalConfig(cfgJSON *extapi.JSON) (porkbunSolverConfig, error) {
	cfg := porkbunSolverConfig{}

	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding webhook solver config: %v", err)
	}

	return cfg, nil
}
