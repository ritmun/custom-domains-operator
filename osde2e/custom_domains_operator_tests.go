// DO NOT REMOVE TAGS BELOW. IF ANY NEW TEST FILES ARE CREATED UNDER /osde2e, PLEASE ADD THESE TAGS TO THEM IN ORDER TO BE EXCLUDED FROM UNIT TESTS.
//go:build osde2e
// +build osde2e

package osde2etests

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	routev1 "github.com/openshift/api/route/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net"
	"net/http"

	"time"

	"crypto/rand"

	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	customdomainv1alpha1 "github.com/openshift/custom-domains-operator/api/v1alpha1"
	"github.com/openshift/osde2e-common/pkg/clients/openshift"
	"github.com/openshift/osde2e-common/pkg/gomega/assertions"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strconv"
)

const (
	pollInterval                 = 10 * time.Second
	defaultTimeout               = 5 * time.Minute
	endpointReadyTimeout         = 5 * time.Minute
	dnsResolverTimeout           = 10 * time.Second
	ingressNamespace             = "openshift-ingress"
	testCustomDomainInstanceName = "test-customdomain-instance"
	testSecretName               = testCustomDomainInstanceName + "-secret"
	testAppName                  = "hello-openshift"
	testServiceName              = testAppName + "-service"
	testRouteHostname            = testAppName + "-route"
)

var (
	k8s                        *openshift.Client
	impersonatedResourceClient *openshift.Client
	testCustomDomain           *customdomainv1alpha1.CustomDomain
	testCustomDomainSecret     *corev1.Secret
	testDomainName             string
	testDnsNames               []string
	testNamespace              *corev1.Namespace
	testNamespaceName          string
	testService                *corev1.Service
	testDeployment             *appsv1.Deployment
	err                        error
	dialer                     *net.Dialer
	routeToEndpoint            string
)

var _ = ginkgo.Describe("custom-domains-operator", ginkgo.Ordered, func() {
	ginkgo.BeforeAll(func(ctx context.Context) {
		dialer = getDialer()
		log.SetLogger(ginkgo.GinkgoLogr)
		var err error
		k8s, err = openshift.New(ginkgo.GinkgoLogr)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")
		Expect(customdomainv1alpha1.AddToScheme(k8s.GetScheme())).Should(BeNil(), "Unable to register customdomainv1alpha1 api scheme")
		impersonatedResourceClient, err = k8s.Impersonate("test-user@redhat.com", "dedicated-admins")
		Expect(err).ShouldNot(HaveOccurred(), "Unable to setup k8s client")
		Expect(customdomainv1alpha1.AddToScheme(impersonatedResourceClient.GetScheme())).Should(BeNil(), "Unable to register customdomainv1alpha1 api scheme")

	})

	// BeforeEach initializes a CustomDomain for testing
	ginkgo.BeforeEach(func(ctx context.Context) {
		testNamespaceName = "test-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
		ginkgo.By("Create test project " + testNamespaceName)
		testNamespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name: testNamespaceName,
		}}
		err = k8s.WithNamespace(testNamespaceName).Create(ctx, testNamespace)
		Expect(err).ShouldNot(HaveOccurred(), "Unable to create namespace")

		ginkgo.By("Creating a ssl certificate and tls secret in 'openshift-ingress'")
		testDnsNames := []string{fmt.Sprintf("*.%s", testDomainName)}
		testCustomDomainSecret = makeTlsSecret(ctx, testSecretName, testNamespaceName, testDnsNames)
		err = k8s.WithNamespace(testNamespaceName).Create(ctx, testCustomDomainSecret)
		Expect(err).ShouldNot(HaveOccurred(), "Failed to create secret")

		ginkgo.By("Creating a CustomDomain CR from the tls secret")
		testDomainName := fmt.Sprintf("%s.io", testCustomDomainInstanceName)
		testCustomDomain = makeCustomDomain(testCustomDomainInstanceName, testNamespaceName, testDomainName)
		err = k8s.WithNamespace(testNamespaceName).Create(ctx, testCustomDomain)
		Expect(err).ToNot(HaveOccurred(), "Error creating custom domain")

		ginkgo.By("Wait for test-instance CustomDomain Endpoint to be ready")
		Eventually(func() bool {
			err = k8s.Get(ctx, testCustomDomainInstanceName, testNamespaceName, testCustomDomain)
			Expect(err).NotTo(HaveOccurred(), "Failed to retrieve customdomains from namespace %s", testNamespaceName)
			if testCustomDomain.Status.State == "Ready" && testCustomDomain.Status.Endpoint != "" {
				return true
			}
			return false
		}).WithTimeout((endpointReadyTimeout)).WithPolling(pollInterval).Should(BeTrue(), "Endpoint never became ready ")
	})

	ginkgo.It("Create and expose app as dedicated admin", func(ctx context.Context) {
		ginkgo.By("Create deployment")
		testDeployment = makeDeployment(testNamespaceName)
		err := impersonatedResourceClient.WithNamespace(testNamespaceName).Create(ctx, testDeployment)
		Expect(err).ToNot(HaveOccurred())

		ginkgo.By("Ensure deployment is up")
		assertions.EventuallyDeployment(ctx, impersonatedResourceClient, testDeployment.Name, testDeployment.Namespace)

		ginkgo.By("Expose service")
		testService = makeService(testNamespaceName)
		err = impersonatedResourceClient.WithNamespace(testNamespaceName).Create(ctx, testService)
		Expect(err).Should(BeNil(), "Unable to get service %s/%s", testNamespaceName, testService.Name)

		ginkgo.By("Create route")
		testRoute := makeRoute(testNamespaceName)
		err = impersonatedResourceClient.WithNamespace(testNamespaceName).Create(ctx, testRoute)
		Expect(err).ToNot(HaveOccurred())

		ginkgo.By("Request the app using the custom domain")
		err = k8s.Get(ctx, testCustomDomainInstanceName, testNamespaceName, testCustomDomain)
		Expect(err).ToNot(HaveOccurred(), "Could not get custom domain instance")
		// dialContext customized for http client to simulate DNS lookup. Redirects requests to canonical hostname instead of custom dns, since it requires CNAME record setup in DNS server.
		dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr == testRoute.Spec.Host+":443" {
				addr = testCustomDomain.Status.Endpoint + ":443"
				log.Log.Info("routing " + testRoute.Spec.Host + " requests to " + testCustomDomain.Status.Endpoint)
			}
			return dialer.DialContext(ctx, network, addr)
		}
		http.DefaultTransport.(*http.Transport).DialContext = dialContext
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
				DialContext: dialContext,
			},
		}
		var response *http.Response
		Eventually(func() bool {
			response, err = client.Get("https://" + testRoute.Spec.Host)
			if err == nil && response != nil && response.StatusCode == http.StatusOK {
				return true
			}
			return false
		}).WithTimeout(defaultTimeout).WithPolling(pollInterval).Should(BeTrue(), "Test app route never responded")
	})

	ginkgo.It("Replace certificates as dedicated admin", func(ctx context.Context) {
		origIngressSecret := &corev1.Secret{}
		err = k8s.Get(ctx, testCustomDomainInstanceName, ingressNamespace, origIngressSecret)
		Expect(err).ToNot(HaveOccurred())
		err = impersonatedResourceClient.Get(ctx, testCustomDomainInstanceName, testNamespaceName, testCustomDomain)
		Expect(err).ToNot(HaveOccurred(), "Could not get custom domain instance")

		ginkgo.By("Generate a new certificate")
		newSecretName := fmt.Sprintf("%s-new-secret", testCustomDomainInstanceName)
		newSecret := makeTlsSecret(ctx, newSecretName, testNamespaceName, testDnsNames)
		err = k8s.WithNamespace(testNamespaceName).Create(ctx, newSecret)
		Expect(err).ShouldNot(HaveOccurred(), "Could not create new secret")

		ginkgo.By("Replace the certificate in the customdomain CR")
		testCustomDomain.Spec.Certificate.Name = newSecret.Name
		testCustomDomain.Spec.Certificate.Namespace = newSecret.Namespace
		err = impersonatedResourceClient.Update(ctx, testCustomDomain)
		Expect(err).ToNot(HaveOccurred(), "Could not update custom domain with new secret")

		ginkgo.By("Verify CD ingress secret matches the new tls secret")
		currentIngressSecret := &corev1.Secret{}
		Eventually(func() bool {
			err = k8s.Get(ctx, testCustomDomainInstanceName, ingressNamespace, currentIngressSecret)
			if err != nil || bytes.Equal(currentIngressSecret.Data["tls.crt"], origIngressSecret.Data["tls.crt"]) {
				return false
			}
			return true
		}).WithTimeout(defaultTimeout).WithPolling(pollInterval).Should(BeTrue(), "TLS cert change never took effect")
	})

	// AfterEach deletes resources created by BeforeEach
	ginkgo.AfterEach(func(ctx context.Context) {
		ginkgo.By("Clean up setup")
		err = k8s.Delete(ctx, testCustomDomain)
		err = k8s.Delete(ctx, testCustomDomainSecret)
		err = k8s.Delete(ctx, testNamespace)
	})
})

func makeCustomDomain(testInstanceName string, testNamespaceName string, testDomainName string) *customdomainv1alpha1.CustomDomain {
	return &customdomainv1alpha1.CustomDomain{
		TypeMeta: metav1.TypeMeta{
			Kind:       "CustomDomain",
			APIVersion: "managed.openshift.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: testCustomDomainInstanceName,
		},
		Spec: customdomainv1alpha1.CustomDomainSpec{
			Domain: testDomainName,
			Certificate: corev1.SecretReference{
				Name:      testSecretName,
				Namespace: testNamespaceName,
			},
		},
	}
}

func makeTlsSecret(ctx context.Context, secretName string, testNamespaceName string, dnsNames []string) *corev1.Secret {
	customDomainRSAKey, err := rsa.GenerateKey(rand.Reader, 4096)
	Expect(err).ShouldNot(HaveOccurred(), "failed to generate key")
	customDomainX509Template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:       []string{"Red Hat, Inc"},
			OrganizationalUnit: []string{"Openshift Dedicated End-to-End Testing"},
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	customDomainX509, err := x509.CreateCertificate(rand.Reader, customDomainX509Template, customDomainX509Template, &customDomainRSAKey.PublicKey, customDomainRSAKey)
	Expect(err).ShouldNot(HaveOccurred(), "failed to create cert")
	secretData := make(map[string][]byte)
	secretData["tls.key"] = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(customDomainRSAKey),
	})
	secretData["tls.crt"] = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: customDomainX509,
	})
	return &corev1.Secret{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Secret",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: testNamespaceName,
		},
		Type: corev1.SecretTypeTLS,
		Data: secretData,
	}
}

func makeDeployment(testNamespaceName string) *appsv1.Deployment {

	replicas := int32(1)
	falseval := false
	tueval := true
	return &appsv1.Deployment{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Deployment",
			APIVersion: "apps/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      testAppName,
			Namespace: testNamespaceName,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"deployment": testAppName},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"deployment": testAppName},
				}, Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  testAppName,
							Image: "docker.io/openshift/" + testAppName,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: 8080,
								},
								{
									ContainerPort: 8888,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: &falseval,
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: &tueval,
								SeccompProfile: &corev1.SeccompProfile{
									Type: corev1.SeccompProfileTypeRuntimeDefault,
								},
							},
						},
					},
				},
			},
		},
	}
}

func makeService(testNamespaceName string) *corev1.Service {
	return &corev1.Service{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Service",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      testServiceName,
			Namespace: testNamespaceName,
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Name:     "8080-tcp",
					Protocol: corev1.ProtocolTCP,
					Port:     8080,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8080,
					},
				},
				{
					Name:     "8888-tcp",
					Protocol: corev1.ProtocolTCP,
					Port:     8888,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 8888,
					},
				},
			},
			Selector: map[string]string{"deployment": testAppName},
			Type:     corev1.ServiceTypeClusterIP,
		},
	}

}

func makeRoute(testNamespaceName string) *routev1.Route {
	return &routev1.Route{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Route",
			APIVersion: "route.openshift.io/v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      testRouteHostname,
			Namespace: testNamespaceName,
		},
		Spec: routev1.RouteSpec{
			Host: testRouteHostname + "." + testCustomDomain.Spec.Domain,
			Port: &routev1.RoutePort{
				TargetPort: intstr.IntOrString{
					Type:   intstr.String,
					StrVal: "8080-tcp",
				},
			},
			TLS: &routev1.TLSConfig{
				Termination: routev1.TLSTerminationEdge,
			},
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: testServiceName,
			},
		},
	}
}

func getDialer() *net.Dialer {
	return &net.Dialer{
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: dnsResolverTimeout,
				}
				return d.DialContext(ctx, network, address)
			},
		},
	}
}
