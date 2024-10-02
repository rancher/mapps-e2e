package istio_debug

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var (
	clusterName     string
	skipCleanup     bool
	logLevel        string
	logFile         *os.File
)

func TestIstioDebug(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Istio Debug Suite")
}

var _ = BeforeSuite(func() {
	var err error
	clusterName = fmt.Sprintf("test-cluster-%d", time.Now().Unix())
	skipCleanup = os.Getenv("SKIP_CLEANUP") == "true"
	logLevel = os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	logFile, err = os.Create(fmt.Sprintf("istio_debug_%s.log", time.Now().Format("20060102_150405")))
	Expect(err).NotTo(HaveOccurred())

	setupLogger(logFile, logLevel)

	createK3dCluster()
	installRancher()
	installMonitoring()
	installIstio()
})

var _ = AfterSuite(func() {
	if !skipCleanup {
		cleanupCluster()
	}
	logFile.Close()
})

var _ = Describe("Istio Debug Suite", func() {
	Describe("Istio Installation Check", func() {
		It("should have the istio-system namespace", func() {
			output := RunKubectlCommand("get", "namespace", "istio-system", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase", "--no-headers")
			Expect(output).To(ContainSubstring("istio-system"))
			Expect(output).To(ContainSubstring("Active"))
		})

		It("should have all Istio pods running", func() {
			CheckPodsRunning("istio-system", "")
		})

		It("should have Istio services", func() {
			output := RunKubectlCommand("get", "svc", "-n", "istio-system", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have Istio CRDs installed", func() {
			output := RunKubectlCommand("get", "crd", "-o", "name")
			crdCount := strings.Count(output, "istio")
			Expect(crdCount).To(BeNumerically(">", 0))
		})

		It("should have a valid Istio version", func() {
			cmd := exec.Command("istioctl", "version", "--short")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(MatchRegexp(`[0-9]+\.[0-9]+\.[0-9]+`))
		})

		It("should have Prometheus pods running", func() {
			CheckPodsRunning("cattle-monitoring-system", "app=prometheus")
		})

		It("should have Prometheus services", func() {
			output := RunKubectlCommand("get", "svc", "-n", "cattle-monitoring-system", "-l", "app=rancher-monitoring-prometheus", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have ServiceMonitors in istio-system namespace", func() {
			output := RunKubectlCommand("get", "servicemonitor", "-n", "istio-system", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have PrometheusRules in istio-system namespace", func() {
			output := RunKubectlCommand("get", "prometheusrule", "-n", "istio-system", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})
	})

	Describe("Kiali and Jaeger Check", func() {
		It("should have Kiali pod running", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=kiali", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Running"))
			Expect(string(output)).To(ContainSubstring("true"))
		})

		It("should have Kiali service", func() {
			cmd := exec.Command("kubectl", "get", "svc", "-n", "istio-system", "-l", "app=kiali", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})

		It("should have Jaeger pod running", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=jaeger", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Running"))
			Expect(string(output)).To(ContainSubstring("true"))
		})

		It("should have Jaeger service", func() {
			cmd := exec.Command("kubectl", "get", "svc", "-n", "istio-system", "-l", "app=jaeger", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})

		It("should have Prometheus endpoint in Kiali config", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "istio-system", "kiali", "-o", "jsonpath={.data.config\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus:"))
		})

		It("should have Prometheus-related logs in Kiali pod", func() {
			cmd := exec.Command("sh", "-c", "kubectl get pod -n istio-system -l app=kiali -o jsonpath='{.items[0].metadata.name}' | xargs -I {} kubectl logs {} -n istio-system | grep -i prometheus | tail -n 5")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			if string(output) == "" {
				Skip("No Prometheus-related logs found in Kiali pod")
			} else {
				Expect(string(output)).To(ContainSubstring("prometheus"))
			}
		})
	})

	Describe("Sample Application Check", func() {
		BeforeEach(func() {
			// Create istio-test namespace with Istio injection label
			cmd := exec.Command("kubectl", "create", "namespace", "istio-test")
			_, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "label", "namespace", "istio-test", "istio-injection=enabled", "--overwrite")
			_, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			// Apply the Bookinfo application to the istio-test namespace
			cmd = exec.Command("kubectl", "apply", "-n", "istio-test", "-f", "https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/platform/kube/bookinfo.yaml")
			_, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(30 * time.Second) // Increased wait time to ensure pods are ready
		})

		It("should have sample application pods running", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-n", "istio-test", "-l", "app in (productpage,reviews,ratings,details)", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready,ISTIO-PROXY:.spec.containers[*].name", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line != "" {
					Expect(line).To(ContainSubstring("Running"))
					Expect(line).To(ContainSubstring("true"))
					Expect(line).To(ContainSubstring("istio-proxy"))
				}
			}
		})

		It("should have Istio sidecars injected", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-n", "istio-test", "-l", "app in (productpage,reviews,ratings,details)", "-o", "jsonpath={range .items[*]}{.metadata.name}{'\t'}{.spec.containers[*].name}{'\n'}{end}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio-proxy"))
		})

		It("should have correct namespace injection label", func() {
			cmd := exec.Command("kubectl", "get", "namespace", "default", "-o", "jsonpath={.metadata.labels.istio-injection}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("enabled"))
		})

		It("should have correct global injection settings", func() {
			cmd := exec.Command("kubectl", "-n", "istio-system", "get", "configmap", "istio-sidecar-injector", "-o", "jsonpath={.data.config}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("policy: enabled"))
		})

		It("should have MutatingWebhookConfiguration for sidecar injection", func() {
			cmd := exec.Command("kubectl", "get", "mutatingwebhookconfiguration", "istio-sidecar-injector", "-o", "yaml")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("namespaceSelector:"))
		})

		It("should have webhook service running", func() {
			cmd := exec.Command("kubectl", "get", "mutatingwebhookconfiguration", "istio-sidecar-injector", "-o", "jsonpath={.webhooks[0].clientConfig.service.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			webhookService := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "get", "service", webhookService, "-n", "istio-system")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(webhookService))
		})

		It("should generate traffic and collect traces", func() {
			// Apply default destination rules
			cmd := exec.Command("kubectl", "apply", "-f", "https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/networking/destination-rule-all.yaml")
			_, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			// Generate traffic
			cmd = exec.Command("kubectl", "get", "svc", "-n", "istio-test", "productpage", "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpageIP := strings.TrimSpace(string(output))

			productpageURL := fmt.Sprintf("http://%s:9080/productpage", productpageIP)
			for i := 0; i < 100; i++ {
				cmd = exec.Command("curl", "-s", "-o", "/dev/null", productpageURL)
				_, err = cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(100 * time.Millisecond)
			}

			// Wait for traces to be collected
			time.Sleep(30 * time.Second)

			// Check for traces
			cmd = exec.Command("kubectl", "get", "pod", "-l", "app=jaeger", "-n", "istio-system", "-o", "jsonpath={.items[*].metadata.name}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			jaegerPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "exec", jaegerPod, "-n", "istio-system", "--", "wget", "-qO-", "http://localhost:16686/api/traces?service=productpage")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data, ok := result["data"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(len(data)).To(BeNumerically(">", 0))
		})

		It("should have Istio metrics in Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "cattle-monitoring-system", "-l", "app=prometheus", "-o", "jsonpath={.items[*].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			prometheusPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "exec", prometheusPod, "-n", "cattle-monitoring-system", "--", "wget", "-qO-", "http://localhost:9090/api/v1/query?query=istio_requests_total{destination_service=\"productpage.default.svc.cluster.local\"}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data, ok := result["data"].(map[string]interface{})
			Expect(ok).To(BeTrue())
			
			resultArray, ok := data["result"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(len(resultArray)).To(BeNumerically(">", 0))
		})
	})

	Describe("Istio Configuration Check", func() {
		It("should pass istioctl analyze", func() {
			cmd := exec.Command("istioctl", "analyze", "--output-threshold=warn")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("No validation issues found"))
		})

		It("should have healthy proxy status", func() {
			cmd := exec.Command("istioctl", "proxy-status")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("SYNCED"))
		})

		It("should have correct Envoy configuration for Productpage Pod", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-test", "-l", "app=productpage", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpagePod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "get", "pod", productpagePod, "-o", "jsonpath={.spec.containers[*].name}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio-proxy"))

			checkEnvoyConfig := func(configType string) {
				cmd := exec.Command("kubectl", "exec", productpagePod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", configType)
				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())

				var result []interface{}
				err = json.Unmarshal(output, &result)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(result)).To(BeNumerically(">", 0))
			}

			checkEnvoyConfig("listeners")
			checkEnvoyConfig("routes")
			checkEnvoyConfig("clusters")
			checkEnvoyConfig("endpoints")
		})
	})

	Describe("Log Collection Check", func() {
		var logDir string

		BeforeEach(func() {
			var err error
			logDir, err = os.MkdirTemp("", "istio_logs")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			os.RemoveAll(logDir)
		})

		collectLogs := func(app, namespace string) {
			It("should collect logs for "+app, func() {
				logFile := filepath.Join(logDir, app+".log")
				cmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "app="+app, "--tail=100")
				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())
				err = os.WriteFile(logFile, output, 0644)
				Expect(err).NotTo(HaveOccurred())
				
				fileInfo, err := os.Stat(logFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(fileInfo.Size()).To(BeNumerically(">", 0))
			})
		}

		collectLogs("istiod", "istio-system")
		collectLogs("kiali", "istio-system")
		collectLogs("jaeger", "istio-system")

		It("should collect logs for productpage", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-l", "app=productpage", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpagePod := string(output)

			logFile := filepath.Join(logDir, "productpage.log")
			cmd = exec.Command("kubectl", "logs", productpagePod, "--tail=100")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			err = os.WriteFile(logFile, output, 0644)
			Expect(err).NotTo(HaveOccurred())
			
			fileInfo, err := os.Stat(logFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(fileInfo.Size()).To(BeNumerically(">", 0))
		})

		It("should have collected all log files", func() {
			files, err := os.ReadDir(logDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(files)).To(Equal(4))
		})
	})

	Describe("Monitoring Integration Check", func() {
		It("should have Prometheus targets for Istio", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-prometheus", "9090:9090")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://localhost:9090/api/v1/targets")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data := result["data"].(map[string]interface{})
			activeTargets := data["activeTargets"].([]interface{})

			istioTargets := 0
			for _, target := range activeTargets {
				targetMap := target.(map[string]interface{})
				labels := targetMap["labels"].(map[string]interface{})
				job := labels["job"].(string)
				if job == "istio-mesh" || job == "istio-telemetry" {
					istioTargets++
				}
			}

			Expect(istioTargets).To(BeNumerically(">", 0))
		})

		It("should have Prometheus scrape configs for Istio", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "cattle-monitoring-system", "rancher-monitoring-prometheus", "-o", "jsonpath={.data.prometheus\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Or(ContainSubstring("job_name: istio-mesh"), ContainSubstring("job_name: istio-telemetry")))
		})

		It("should have Istio metrics in Prometheus", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-prometheus", "9090:9090")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://localhost:9090/api/v1/query?query=istio_requests_total")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data := result["data"].(map[string]interface{})
			resultArray := data["result"].([]interface{})
			Expect(len(resultArray)).To(BeNumerically(">", 0))
		})

		It("should have Grafana dashboards for Istio", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "cattle-monitoring-system", "-l", "grafana_dashboard=1")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio"))
		})

		It("should have Grafana access to Prometheus", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-grafana", "3000:80")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://admin:prom-operator@localhost:3000/api/datasources")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var datasources []map[string]interface{}
			err = json.Unmarshal(output, &datasources)
			Expect(err).NotTo(HaveOccurred())

			prometheusDatasource := false
			for _, ds := range datasources {
				if ds["name"] == "Prometheus" {
					prometheusDatasource = true
					break
				}
			}
			Expect(prometheusDatasource).To(BeTrue())
		})

		It("should have Kiali access to Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=kiali", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			kialiPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "logs", kialiPod, "-n", "istio-system")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus"))
		})

		It("should have correct Kiali configuration for Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "istio-system", "kiali", "-o", "jsonpath={.data.config\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus:"))
		})

		It("should have Rancher Monitoring components running", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-n", "cattle-monitoring-system", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line != "" {
					Expect(line).To(ContainSubstring("Running"))
					Expect(line).To(ContainSubstring("true"))
				}
			}
		})
	})
	Describe("Istio Installation Check", func() {
		It("should have the istio-system namespace", func() {
			output := RunKubectlCommand("get", "namespace", "istio-system", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase", "--no-headers")
			Expect(output).To(ContainSubstring("istio-system"))
			Expect(output).To(ContainSubstring("Active"))
		})

		It("should have all Istio pods running", func() {
			CheckPodsRunning("istio-system", "")
		})

		It("should have Istio services", func() {
			output := RunKubectlCommand("get", "svc", "-n", "istio-system", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have Istio CRDs installed", func() {
			output := RunKubectlCommand("get", "crd", "-o", "name")
			crdCount := strings.Count(output, "istio")
			Expect(crdCount).To(BeNumerically(">", 0))
		})

		It("should have a valid Istio version", func() {
			cmd := exec.Command("istioctl", "version", "--short")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(MatchRegexp(`[0-9]+\.[0-9]+\.[0-9]+`))
		})

		It("should have Prometheus pods running", func() {
			CheckPodsRunning("cattle-monitoring-system", "app=prometheus")
		})

		It("should have Prometheus services", func() {
			output := RunKubectlCommand("get", "svc", "-n", "cattle-monitoring-system", "-l", "app=prometheus", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have ServiceMonitors in istio-system namespace", func() {
			output := RunKubectlCommand("get", "servicemonitor", "-n", "istio-system", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})

		It("should have PrometheusRules in istio-system namespace", func() {
			output := RunKubectlCommand("get", "prometheusrule", "-n", "istio-system", "--no-headers")
			Expect(output).NotTo(BeEmpty())
		})
	})

	Describe("Kiali and Jaeger Check", func() {
		It("should have Kiali pod running", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=kiali", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Running"))
			Expect(string(output)).To(ContainSubstring("true"))
		})

		It("should have Kiali service", func() {
			cmd := exec.Command("kubectl", "get", "svc", "-n", "istio-system", "-l", "app=kiali", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})

		It("should have Jaeger pod running", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=jaeger", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("Running"))
			Expect(string(output)).To(ContainSubstring("true"))
		})

		It("should have Jaeger service", func() {
			cmd := exec.Command("kubectl", "get", "svc", "-n", "istio-system", "-l", "app=jaeger-collector", "-o", "custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,EXTERNAL-IP:.status.loadBalancer.ingress[0].ip", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(BeEmpty())
		})

		It("should have Prometheus endpoint in Kiali config", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "istio-system", "kiali", "-o", "jsonpath={.data.config\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus:"))
		})

		It("should have Prometheus-related logs in Kiali pod", func() {
			cmd := exec.Command("sh", "-c", "kubectl get pod -n istio-system -l app=kiali -o jsonpath='{.items[0].metadata.name}' | xargs -I {} kubectl logs {} -n istio-system | grep -i prometheus | tail -n 5")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			if string(output) == "" {
				Skip("No Prometheus-related logs found in Kiali pod")
			} else {
				Expect(string(output)).To(ContainSubstring("prometheus"))
			}
		})
	})

	Describe("Sample Application Check", func() {
		BeforeEach(func() {
			cmd := exec.Command("kubectl", "apply", "-f", "https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/platform/kube/bookinfo.yaml")
			_, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(10 * time.Second)
		})

		It("should have sample application pods running", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "app in (productpage,reviews,ratings,details)", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready,ISTIO-PROXY:.spec.containers[*].name", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line != "" {
					Expect(line).To(ContainSubstring("Running"))
					Expect(line).To(ContainSubstring("true"))
					Expect(line).To(ContainSubstring("istio-proxy"))
				}
			}
		})

		It("should have Istio sidecars injected", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-l", "app in (productpage,reviews,ratings,details)", "-o", "jsonpath={range .items[*]}{.metadata.name}{'\t'}{.spec.containers[*].name}{'\n'}{end}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio-proxy"))
		})

		It("should have correct namespace injection label", func() {
			cmd := exec.Command("kubectl", "get", "namespace", "istio-test", "-o", "jsonpath={.metadata.labels.istio-injection}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("enabled"))
		})

		It("should have correct global injection settings", func() {
			cmd := exec.Command("kubectl", "-n", "istio-system", "get", "configmap", "istio-sidecar-injector", "-o", "jsonpath={.data.config}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("policy: enabled"))
		})

		It("should have MutatingWebhookConfiguration for sidecar injection", func() {
			cmd := exec.Command("kubectl", "get", "mutatingwebhookconfiguration", "istio-sidecar-injector", "-o", "yaml")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("namespaceSelector:"))
		})

		It("should have webhook service running", func() {
			cmd := exec.Command("kubectl", "get", "mutatingwebhookconfiguration", "istio-sidecar-injector", "-o", "jsonpath={.webhooks[0].clientConfig.service.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			webhookService := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "get", "service", webhookService, "-n", "istio-system")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring(webhookService))
		})

		It("should generate traffic and collect traces", func() {
			// Apply default destination rules
			cmd := exec.Command("kubectl", "apply", "-f", "https://raw.githubusercontent.com/istio/istio/release-1.22/samples/bookinfo/networking/destination-rule-all.yaml")
			_, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			// Generate traffic
			cmd = exec.Command("kubectl", "get", "svc", "productpage", "-o", "jsonpath={.status.loadBalancer.ingress[0].ip}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpageIP := strings.TrimSpace(string(output))

			productpageURL := fmt.Sprintf("http://%s:9080/productpage", productpageIP)
			for i := 0; i < 100; i++ {
				cmd = exec.Command("curl", "-s", "-o", "/dev/null", productpageURL)
				_, err = cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(100 * time.Millisecond)
			}

			// Wait for traces to be collected
			time.Sleep(30 * time.Second)

			// Check for traces
			cmd = exec.Command("kubectl", "get", "pod", "-l", "app=jaeger", "-n", "istio-system", "-o", "jsonpath={.items[*].metadata.name}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			jaegerPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "exec", jaegerPod, "-n", "istio-system", "--", "wget", "-qO-", "http://localhost:16686/api/traces?service=productpage")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data, ok := result["data"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(len(data)).To(BeNumerically(">", 0))
		})

		It("should have Istio metrics in Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "cattle-monitoring-system", "-l", "app=prometheus", "-o", "jsonpath={.items[*].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			prometheusPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "exec", prometheusPod, "-n", "cattle-monitoring-system", "--", "wget", "-qO-", "http://localhost:9090/api/v1/query?query=istio_requests_total{destination_service=\"productpage.default.svc.cluster.local\"}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data, ok := result["data"].(map[string]interface{})
			Expect(ok).To(BeTrue())
			
			resultArray, ok := data["result"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(len(resultArray)).To(BeNumerically(">", 0))
		})
	})

	Describe("Istio Configuration Check", func() {
		It("should pass istioctl analyze", func() {
			cmd := exec.Command("istioctl", "analyze", "--output-threshold=warn")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("No validation issues found"))
		})

		It("should have healthy proxy status", func() {
			cmd := exec.Command("istioctl", "proxy-status")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("SYNCED"))
		})

		It("should have correct Envoy configuration for Productpage Pod", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-l", "app=productpage", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpagePod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "get", "pod", productpagePod, "-o", "jsonpath={.spec.containers[*].name}")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio-proxy"))

			checkEnvoyConfig := func(configType string) {
				cmd := exec.Command("kubectl", "exec", productpagePod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", configType)
				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())

				var result []interface{}
				err = json.Unmarshal(output, &result)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(result)).To(BeNumerically(">", 0))
			}

			checkEnvoyConfig("listeners")
			checkEnvoyConfig("routes")
			checkEnvoyConfig("clusters")
			checkEnvoyConfig("endpoints")
		})
	})

	Describe("Log Collection Check", func() {
		var logDir string

		BeforeEach(func() {
			var err error
			logDir, err = os.MkdirTemp("", "istio_logs")
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			os.RemoveAll(logDir)
		})

		collectLogs := func(app, namespace string) {
			It("should collect logs for "+app, func() {
				logFile := filepath.Join(logDir, app+".log")
				cmd := exec.Command("kubectl", "logs", "-n", namespace, "-l", "app="+app, "--tail=100")
				output, err := cmd.CombinedOutput()
				Expect(err).NotTo(HaveOccurred())
				err = os.WriteFile(logFile, output, 0644)
				Expect(err).NotTo(HaveOccurred())
				
				fileInfo, err := os.Stat(logFile)
				Expect(err).NotTo(HaveOccurred())
				Expect(fileInfo.Size()).To(BeNumerically(">", 0))
			})
		}

		collectLogs("istiod", "istio-system")
		collectLogs("kiali", "istio-system")
		collectLogs("jaeger", "istio-system")

		It("should collect logs for productpage", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-l", "app=productpage", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			productpagePod := string(output)

			logFile := filepath.Join(logDir, "productpage.log")
			cmd = exec.Command("kubectl", "logs", productpagePod, "--tail=100")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			err = os.WriteFile(logFile, output, 0644)
			Expect(err).NotTo(HaveOccurred())
			
			fileInfo, err := os.Stat(logFile)
			Expect(err).NotTo(HaveOccurred())
			Expect(fileInfo.Size()).To(BeNumerically(">", 0))
		})

		It("should have collected all log files", func() {
			files, err := os.ReadDir(logDir)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(files)).To(Equal(4))
		})
	})

	Describe("Monitoring Integration Check", func() {
		It("should have Prometheus targets for Istio", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-prometheus", "9090:9090")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://localhost:9090/api/v1/targets")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data := result["data"].(map[string]interface{})
			activeTargets := data["activeTargets"].([]interface{})

			istioTargets := 0
			for _, target := range activeTargets {
				targetMap := target.(map[string]interface{})
				labels := targetMap["labels"].(map[string]interface{})
				job := labels["job"].(string)
				if job == "istio-mesh" || job == "istio-telemetry" {
					istioTargets++
				}
			}

			Expect(istioTargets).To(BeNumerically(">", 0))
		})

		It("should have Prometheus scrape configs for Istio", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "cattle-monitoring-system", "rancher-monitoring-prometheus", "-o", "jsonpath={.data.prometheus\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Or(ContainSubstring("job_name: istio-mesh"), ContainSubstring("job_name: istio-telemetry")))
		})

		It("should have Istio metrics in Prometheus", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-prometheus", "9090:9090")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://localhost:9090/api/v1/query?query=istio_requests_total")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var result map[string]interface{}
			err = json.Unmarshal(output, &result)
			Expect(err).NotTo(HaveOccurred())

			data := result["data"].(map[string]interface{})
			resultArray := data["result"].([]interface{})
			Expect(len(resultArray)).To(BeNumerically(">", 0))
		})

		It("should have Grafana dashboards for Istio", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "cattle-monitoring-system", "-l", "grafana_dashboard=1")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio"))
		})

		It("should have Grafana access to Prometheus", func() {
			cmd := exec.Command("kubectl", "port-forward", "-n", "cattle-monitoring-system", "svc/rancher-monitoring-grafana", "3000:80")
			err := cmd.Start()
			Expect(err).NotTo(HaveOccurred())
			defer cmd.Process.Kill()

			time.Sleep(5 * time.Second)

			curlCmd := exec.Command("curl", "-s", "http://admin:prom-operator@localhost:3000/api/datasources")
			output, err := curlCmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())

			var datasources []map[string]interface{}
			err = json.Unmarshal(output, &datasources)
			Expect(err).NotTo(HaveOccurred())

			prometheusDatasource := false
			for _, ds := range datasources {
				if ds["name"] == "Prometheus" {
					prometheusDatasource = true
					break
				}
			}
			Expect(prometheusDatasource).To(BeTrue())
		})

		It("should have Kiali access to Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "pod", "-n", "istio-system", "-l", "app=kiali", "-o", "jsonpath={.items[0].metadata.name}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			kialiPod := strings.TrimSpace(string(output))

			cmd = exec.Command("kubectl", "logs", kialiPod, "-n", "istio-system")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus"))
		})

		It("should have correct Kiali configuration for Prometheus", func() {
			cmd := exec.Command("kubectl", "get", "configmap", "-n", "istio-system", "kiali", "-o", "jsonpath={.data.config\\.yaml}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("prometheus:"))
		})

		It("should have Rancher Monitoring components running", func() {
			cmd := exec.Command("kubectl", "get", "pods", "-n", "cattle-monitoring-system", "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				if line != "" {
					Expect(line).To(ContainSubstring("Running"))
					Expect(line).To(ContainSubstring("true"))
				}
			}
		})
	})

	Describe("Advanced Istio Configuration Check", func() {
		It("should verify Envoy configuration (config_dump)", func() {
			productpagePod := GetPodName("default", "app=productpage")
			cmd := exec.Command("kubectl", "exec", "-n", "default", productpagePod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "config_dump")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			
			var configDump map[string]interface{}
			err = json.Unmarshal(output, &configDump)
			Expect(err).NotTo(HaveOccurred())
			
			configs, ok := configDump["configs"].([]interface{})
			Expect(ok).To(BeTrue())
			Expect(len(configs)).To(BeNumerically(">", 0))
		})

		It("should ensure necessary environment variables are set", func() {
			productpagePod := GetPodName("default", "app=productpage")
			cmd := exec.Command("kubectl", "exec", "-n", "default", productpagePod, "-c", "istio-proxy", "--", "env")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("ISTIO_PROMETHEUS=true"))
		})

		It("should verify the correct metrics filter (istio-stats-filter)", func() {
			productpagePod := GetPodName("default", "app=productpage")
			cmd := exec.Command("kubectl", "exec", "-n", "default", productpagePod, "-c", "istio-proxy", "--", "pilot-agent", "request", "GET", "config_dump")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("istio-stats-filter"))
		})

		It("should check Telemetry V2 configuration", func() {
			cmd := exec.Command("kubectl", "get", "cm", "istio", "-n", "istio-system", "-o", "jsonpath={.data.mesh}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("disableMixerHttpReports: true"))
		})

		It("should verify resource limits", func() {
			productpagePod := GetPodName("default", "app=productpage")
			cmd := exec.Command("kubectl", "get", "pod", "-n", "default", productpagePod, "-o", "jsonpath={.spec.containers[?(@.name=='istio-proxy')].resources}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Or(ContainSubstring("limits"), ContainSubstring("requests")))
		})

		It("should ensure proper sidecar injection with telemetry enabled", func() {
			cmd := exec.Command("kubectl", "get", "namespace", "default", "-o", "jsonpath={.metadata.labels.istio-injection}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(Equal("enabled"))
		})

		It("should confirm enablePrometheusMerge: true in meshConfig", func() {
			cmd := exec.Command("kubectl", "get", "cm", "istio", "-n", "istio-system", "-o", "jsonpath={.data.mesh}")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).To(ContainSubstring("enablePrometheusMerge: true"))
		})

		It("should check Istio and proxy logs for insights", func() {
			istiodPod := GetPodName("istio-system", "app=istiod")
			cmd := exec.Command("kubectl", "logs", "-n", "istio-system", istiodPod, "--tail=100")
			output, err := cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(ContainSubstring("error"))

			productpagePod := GetPodName("default", "app=productpage")
			cmd = exec.Command("kubectl", "logs", "-n", "default", productpagePod, "-c", "istio-proxy", "--tail=100")
			output, err = cmd.CombinedOutput()
			Expect(err).NotTo(HaveOccurred())
			Expect(string(output)).NotTo(ContainSubstring("error"))
		})
	})
})
