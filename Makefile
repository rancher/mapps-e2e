.PHONY: test clean install-deps

test:
	SKIP_CLEANUP=false LOG_LEVEL=info ginkgo -v ./...

test-no-cleanup:
	SKIP_CLEANUP=true LOG_LEVEL=info ginkgo -v ./...

test-debug:
	SKIP_CLEANUP=false LOG_LEVEL=debug ginkgo -v ./...

test-k3s:
	SKIP_CLEANUP=false LOG_LEVEL=info ginkgo -v -focus="K3s" ./...

test-rancher:
	SKIP_CLEANUP=false LOG_LEVEL=info ginkgo -v -focus="Rancher" ./...

test-core:
	SKIP_CLEANUP=false LOG_LEVEL=info ginkgo -v -focus="Core" ./...

test-istio:
	SKIP_CLEANUP=false LOG_LEVEL=info ginkgo -v -focus="Istio Debug" ./...

clean:
	rm -rf ./tmp
	rm -f istio_debug_*.log

install-deps:
	go mod tidy
	go install github.com/onsi/ginkgo/v2/ginkgo@latest
