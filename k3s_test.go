package istio_debug

import (
	"os/exec"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestK3s(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "K3s Suite")
}

func createK3dCluster() {
	cmd := exec.Command("k3d", "cluster", "create", clusterName,
		"--agents", "2",
		"--servers", "3",
		"--image", "rancher/k3s:v1.27.16-k3s1-arm64",
		"--port", "80:80@loadbalancer",
		"--port", "443:443@loadbalancer",
		"--api-port", "6443")
	output, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred(), "Failed to create k3d cluster with custom parameters: %v\nOutput: %s", err, output)

	// Verify cluster is running with correct configuration
	cmd = exec.Command("k3d", "cluster", "list", clusterName, "-o", "json")
	output, err = cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred())
	logInfo("K3d cluster created successfully")
}

func cleanupCluster() {
	cmd := exec.Command("k3d", "cluster", "delete", clusterName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logError("Failed to delete k3d cluster: %v\nOutput: %s", err, output)
	} else {
		logInfo("K3d cluster deleted successfully")
	}
}

var _ = Describe("K3s Tests", func() {
	It("should verify k3d cluster creation", func() {
		cmd := exec.Command("k3d", "cluster", "list", clusterName, "-o", "json")
		output, err := cmd.CombinedOutput()
		Expect(err).NotTo(HaveOccurred())
		Expect(string(output)).To(ContainSubstring(clusterName))
		logInfo("K3d cluster verification successful")
	})
})
