package istio_debug

import (
	"fmt"
	"os/exec"
	"strings"

	. "github.com/onsi/gomega"
)

func debugLog(format string, args ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", args...)
}

// RunKubectlCommand executes a kubectl command and returns the output
func RunKubectlCommand(args ...string) string {
	debugLog("Running kubectl command: %v", args)
	cmd := exec.Command("kubectl", args...)
	output, err := cmd.CombinedOutput()
	Expect(err).NotTo(HaveOccurred())
	debugLog("kubectl command output: %s", strings.TrimSpace(string(output)))
	return strings.TrimSpace(string(output))
}

// CheckPodsRunning checks if all pods in a given namespace with a given label are running
func CheckPodsRunning(namespace string, label string) {
	debugLog("Checking pods running in namespace: %s with label: %s", namespace, label)
	output := RunKubectlCommand("get", "pods", "-n", namespace, "-l", label, "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.phase,READY:.status.containerStatuses[0].ready", "--no-headers")
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if line != "" {
			debugLog("Checking pod: %s", line)
			Expect(line).To(ContainSubstring("Running"))
			Expect(line).To(ContainSubstring("true"))
		}
	}
	debugLog("All pods are running and ready")
}

// CheckServiceExists checks if a service exists in a given namespace
func CheckServiceExists(namespace string, serviceName string) {
	output := RunKubectlCommand("get", "svc", "-n", namespace, serviceName, "-o", "custom-columns=NAME:.metadata.name", "--no-headers")
	Expect(output).To(ContainSubstring(serviceName))
}

// GetPodName returns the name of the first pod matching the given label in the given namespace
func GetPodName(namespace string, label string) string {
	output := RunKubectlCommand("get", "pod", "-n", namespace, "-l", label, "-o", "jsonpath={.items[0].metadata.name}")
	return output
}
