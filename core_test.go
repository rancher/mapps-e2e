package istio_debug

import (
	"os/exec"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestCore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Core Suite")
}

var _ = Describe("Core Tests", func() {
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
})
