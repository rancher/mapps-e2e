package istio_debug

import (
	"fmt"
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestRancher(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Rancher Suite")
}

func installRancher() {
	// Install cert-manager
	cmd := exec.Command("kubectl", "apply", "-f", "https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml")
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred(), "Failed to install cert-manager")

	// Wait for cert-manager to be ready
	Eventually(func() error {
		cmd := exec.Command("kubectl", "wait", "--for=condition=Available", "deployment", "--all", "-n", "cert-manager", "--timeout=300s")
		return cmd.Run()
	}, "5m", "10s").Should(Succeed())

	logInfo("Cert-manager installed successfully")

	cmd = exec.Command("helm", "repo", "add", "rancher-stable", "https://releases.rancher.com/server-charts/stable")
	err = cmd.Run()
	Expect(err).NotTo(HaveOccurred(), "Failed to add Rancher Helm repo")

	cmd = exec.Command("helm", "repo", "update")
	err = cmd.Run()
	Expect(err).NotTo(HaveOccurred(), "Failed to update Helm repos")

	cmd = exec.Command("helm", "install", "rancher", "rancher-stable/rancher",
		"--namespace", "cattle-system",
		"--create-namespace",
		"--set", fmt.Sprintf("hostname=%s.localhost", clusterName),
		"--set", "bootstrapPassword=admin")
	output, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Failed to install Rancher: %v\nOutput: %s", err, output)

	// Wait for Rancher to be ready
	Eventually(func() error {
		cmd := exec.Command("kubectl", "wait", "--for=condition=Available", "deployment", "rancher", "-n", "cattle-system", "--timeout=300s")
		return cmd.Run()
	}, "5m", "10s").Should(Succeed())

	logInfo("Rancher installed successfully")
}

func installMonitoring() {
	cmd := exec.Command("helm", "repo", "add", "rancher-charts", "https://charts.rancher.io")
	err := cmd.Run()
	Expect(err).NotTo(HaveOccurred(), "Failed to add Rancher Charts repo")

	cmd = exec.Command("helm", "repo", "update")
	err = cmd.Run()
	Expect(err).NotTo(HaveOccurred(), "Failed to update Helm repos")

	// Install CRDs first
	cmd = exec.Command("helm", "install", "rancher-monitoring-crd", "rancher-charts/rancher-monitoring-crd",
		"--namespace", "cattle-monitoring-system",
		"--create-namespace")
	output, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Failed to install rancher-monitoring CRDs: %v\nOutput: %s", err, output)

	// Wait for CRDs to be ready
	Eventually(func() error {
		cmd := exec.Command("kubectl", "get", "crd", "prometheuses.monitoring.coreos.com", "alertmanagers.monitoring.coreos.com", "servicemonitors.monitoring.coreos.com")
		return cmd.Run()
	}, "2m", "10s").Should(Succeed())

	// Install rancher-monitoring
	cmd = exec.Command("helm", "install", "rancher-monitoring", "rancher-charts/rancher-monitoring",
		"--namespace", "cattle-monitoring-system")
	output, err = cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Failed to install rancher-monitoring: %v\nOutput: %s", err, output)

	// Wait for rancher-monitoring to be ready
	Eventually(func() error {
		cmd := exec.Command("kubectl", "wait", "--for=condition=Available", "deployment", "--all", "-n", "cattle-monitoring-system", "--timeout=300s")
		return cmd.Run()
	}, "5m", "10s").Should(Succeed())

	logInfo("Monitoring installed successfully")
}

func installIstio() {
	cmd := exec.Command("helm", "install", "rancher-istio", "rancher-charts/rancher-istio",
		"--namespace", "istio-system",
		"--create-namespace")
	output, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Failed to install rancher-istio: %v\nOutput: %s", err, output)

	// Wait for rancher-istio to be ready
	Eventually(func() error {
		cmd := exec.Command("kubectl", "wait", "--for=condition=Available", "deployment", "--all", "-n", "istio-system", "--timeout=300s")
		return cmd.Run()
	}, "5m", "10s").Should(Succeed())

	logInfo("Istio installed successfully")
}

var _ = Describe("Rancher Tests", func() {
	It("should verify Rancher installation", func() {
		cmd := exec.Command("kubectl", "get", "pods", "-n", "cattle-system", "-l", "app=rancher", "-o", "jsonpath={.items[*].status.phase}")
		output, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(Equal("Running Running Running"))
		logInfo("Rancher installation verified successfully")
	})

	It("should verify Monitoring installation", func() {
		cmd := exec.Command("kubectl", "get", "pods", "-n", "cattle-monitoring-system", "-o", "jsonpath={.items[*].status.phase}")
		output, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("Running"))
		logInfo("Monitoring installation verified successfully")
	})

	It("should verify Istio installation", func() {
		cmd := exec.Command("kubectl", "get", "pods", "-n", "istio-system", "-o", "jsonpath={.items[*].status.phase}")
		output, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring("Running"))
		logInfo("Istio installation verified successfully")
	})
})
