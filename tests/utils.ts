import { execSync, spawn } from 'child_process'
import * as fs from 'fs'
import * as path from 'path'
import * as http from 'http'
import { v4 as uuidv4 } from 'uuid'
import { expect, Page } from '@playwright/test'

// // Function to create a Helm chart
// export const createChart = (chartName: string, chartPath: string) => {
// 	const fullChartPath = `${chartPath}/${chartName}`
// 	if (!fs.existsSync(fullChartPath)) {
// 		console.log(`Creating Helm chart: ${chartName}`)
// 		execSync(`helm create ${fullChartPath}`, { stdio: 'inherit' })
// 	}
// }

// Function to install a Helm chart in a namespace
export const installLocalChart = (
	chartName: string,
	chartPath: string,
	namespacePrefix: string
): string => {
	// Generate a namespace with the prefix and a random sequence
	const randomSuffix = uuidv4().slice(0, 8)
	const namespace = `${namespacePrefix}_${randomSuffix}`

	// Create the namespace
	console.log(`Creating namespace: ${namespace}`)
	execSync(`kubectl create namespace ${namespace}`, { stdio: 'inherit' })

	// Install the Helm chart in the random namespace
	const fullChartPath = `${chartPath}/${chartName}`
	console.log(
		`Installing Helm chart: ${chartName} in namespace: ${namespace}`
	)
	execSync(
		`helm install ${chartName} ${fullChartPath} --namespace ${namespace}`,
		{ stdio: 'inherit' }
	)

	// Return the namespace
	return namespace
}

/**
 * Pushes a Helm chart to an insecure Helm repository.
 * @param chartName - The name of the Helm chart.
 * @param chartPath - The directory where the Helm chart is stored.
 * @param repoUrl - The URL of the Helm repository.
 * @param version - The version of the Helm chart (default is "0.1.0").
 */
export const pushChartToRepo = (
	chartName: string,
	chartPath: string,
	repoUrl: string,
	repoName: string = 'testrepo',
	version: string = '0.1.0'
): string => {
	const fullChartPath = `${chartPath}/${chartName}`
	const chartPackage = `${chartName}-${version}.tgz`

	console.log(
		`Pushing Helm chart: ${chartName} to repository: ${repoUrl}/${repoName}`
	)

	console.log(
		`helm push ${chartPackage} ${repoUrl}/${repoName} --insecure-skip-tls-verify`
	)

	// Push the Helm chart to the repository
	execSync(
		`helm push ${chartPackage} ${repoUrl}/${repoName} --insecure-skip-tls-verify`,
		{
			cwd: chartPath,
			stdio: 'inherit',
		}
	)

	console.log(`Helm chart pushed successfully to: ${repoUrl}`)
	return `${repoUrl}/${repoName}`
}

/**
 * Sets up and serves an HTTPS repository for Helm charts.
 * @param repoPath - The directory to create the repository.
 * @param port - The port to host the repository.
 * @returns The HTTPS repository URL.
 */
export function setupHttpsRepoServer(repoPath: string, port: number): string {
	execSync(`helm repo index ${repoPath}`, { stdio: 'inherit' })

	// Start an HTTP server to serve the repository
	const server = http.createServer((req, res) => {
		const filePath = path.join(repoPath, req.url || '')
		if (fs.existsSync(filePath)) {
			res.writeHead(200, { 'Content-Type': 'application/octet-stream' })
			fs.createReadStream(filePath).pipe(res)
		} else {
			res.writeHead(404)
			res.end()
		}
	})
	server.listen(port, () => {
		console.log(
			`HTTPS repository server running at http://localhost:${port}`
		)
	})

	return `http://localhost:${port}`
}

/**
 * Sets up and starts a Git repository server using `git daemon`.
 * @param repoPath - The directory to create the Git repository.
 * @param port - The port to host the Git repository.
 * @returns The Git repository URL (git://).
 */
export function setupGitRepoServer(repoPath: string, port: number): string {
	// Ensure the directory exists
	if (!fs.existsSync(repoPath)) {
		fs.mkdirSync(repoPath, { recursive: true })
	}

	// Initialize a bare Git repository
	execSync('git init --bare', { cwd: repoPath, stdio: 'inherit' })

	// Start the Git daemon as a separate process
	const daemonProcess = spawn('git', [
		'daemon',
		'--export-all',
		`--base-path=${path.dirname(repoPath)}`,
		`--port=${port}`,
		'--reuseaddr',
		'--informative-errors',
	])

	// Log output for debugging
	daemonProcess.stdout.on('data', data => {
		console.log(`[git-daemon]: ${data}`)
	})

	daemonProcess.stderr.on('data', data => {
		console.error(`[git-daemon-error]: ${data}`)
	})

	// Handle process exit
	daemonProcess.on('exit', code => {
		console.log(`[git-daemon]: Process exited with code ${code}`)
	})

	const repoUrl = `https://localhost:${port}/${path.basename(repoPath)}`
	console.log(`Git repository server running at ${repoUrl}`)

	// Return the repository URL
	return repoUrl
}

/**
 * Sets up and runs an OCI repository server (Docker registry).
 * @param port - The port for the Docker registry.
 * @returns The URL of the running OCI repository server.
 */
export function setupOciRepoServer(port: number, network: string): string {
	// Start the Docker registry as a separate process
	let registryProcess
	try {
		// Check if a running registry container exists
		execSync('docker ps | grep registry', { stdio: 'inherit' })
		console.log('Docker registry is already running.')
	} catch {
		try {
			// Check if a stopped registry container exists
			execSync('docker ps -a | grep registry', { stdio: 'inherit' })
			console.log(
				'Registry container found but not running. Starting it...'
			)
			execSync('docker start registry', { stdio: 'inherit' })
		} catch {
			// If no container exists, create and run a new one
			console.log(
				'No registry container found. Creating and starting a new one...'
			)
			execSync(
				`docker run -d -p 5000:5000 --name registry registry:2 --network ${network}`,
				{
					stdio: 'inherit',
				}
			)
		}
	}

	// Return the repository URL
	const repoUrl = `oci://localhost:${port}`
	console.log(`OCI repository server running at ${repoUrl}`)
	return repoUrl
}

export const teardownOCIRepoServer = (port: number) => {
	execSync('docker stop registry && docker rm registry', { stdio: 'inherit' })
	console.log('Stopped local Docker registry')
}

export const verifyRegexDoesExist = (name, page) => {
	expect(page.locator(`text=/Active.*${name}/`)).toBeVisible({
		timeout: 15000,
	})
}

/**
 * Creates a k3d cluster with specified parameters.
 * @param clusterName - Name of the k3d cluster.
 * @param k3sImage - Rancher K3s image version.
 * @param ports - Port mappings for the cluster.
 */
export function createK3dCluster(
	clusterName: string,
	k3sImage: string,
	ports: string[],
	network: string = 'k3d'
) {
	console.log(`Creating k3d cluster: ${clusterName}...`)
	const portMappings = ports.map(port => `-p ${port}`).join(' ')
	execSync(
		`k3d cluster create ${clusterName} ${portMappings} --servers 1 --image ${k3sImage} --network ${network}`,
		{ stdio: 'inherit' }
	)
	console.log(`k3d cluster ${clusterName} created successfully.`)
}

/**
 * Adds necessary Helm repositories for Rancher and cert-manager.
 */
export function addHelmRepositories() {
	console.log('Adding Helm repositories...')
	execSync('helm repo add jetstack https://charts.jetstack.io', {
		stdio: 'inherit',
	})
	execSync(
		'helm repo add rancher-latest https://releases.rancher.com/server-charts/latest',
		{
			stdio: 'inherit',
		}
	)
	execSync('helm repo update', { stdio: 'inherit' })
	console.log('Helm repositories added and updated successfully.')
}

/**
 * Installs cert-manager in the k3d cluster.
 * @param version - Cert-manager version to install.
 */
export function installCertManager(version: string) {
	console.log(`Installing cert-manager version ${version}...`)
	execSync(
		`helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --version ${version} --set crds.enabled=true`,
		{ stdio: 'inherit' }
	)
	console.log('cert-manager installed successfully.')
}

/**
 * Installs Rancher in the k3d cluster.
 * @param domain - Domain name for Rancher.
 * @param password - Bootstrap password for Rancher.
 * @param rancherVersion - Rancher version to install.
 */
export function installRancher(
	domain: string,
	password: string,
	rancherVersion: string
) {
	console.log(
		`Installing Rancher version ${rancherVersion} at domain ${domain}...`
	)
	execSync(
		`helm upgrade --install rancher rancher-latest/rancher --namespace cattle-system --set hostname=${domain} --set bootstrapPassword=${password} --create-namespace --devel --set rancherImageTag=${rancherVersion}`,
		{ stdio: 'inherit' }
	)
	console.log('Rancher installed successfully.')
}

/**
 * Waits for the Rancher deployment to become available.
 */
export function waitForRancherDeployment() {
	console.log('Waiting for Rancher deployment to become available...')
	execSync('kubectl -n cattle-system rollout status deploy/rancher', {
		stdio: 'inherit',
	})
	console.log('Rancher deployment is available.')
}

/**
 * Deletes the specified k3d cluster.
 * @param clusterName - Name of the k3d cluster to delete.
 */
export function deleteK3dCluster(clusterName: string) {
	console.log(`Deleting k3d cluster: ${clusterName}...`)
	execSync(`k3d cluster delete ${clusterName}`, { stdio: 'inherit' })
	console.log(`k3d cluster ${clusterName} deleted successfully.`)
}

/**
 * Runs the full setup process for k3d cluster, cert-manager, and Rancher.
 * @param clusterName - Name of the k3d cluster.
 * @param domain - Domain name for Rancher.
 * @param rancherPassword - Bootstrap password for Rancher.
 * @param k3sImage - Rancher K3s image version.
 * @param certManagerVersion - Cert-manager version to install.
 * @param rancherVersion - Rancher version to install.
 * @param ports - Port mappings for the cluster.
 */
export function setupK3dClusterAndRancher(
	clusterName: string,
	domain: string,
	rancherPassword: string,
	k3sImage: string,
	certManagerVersion: string,
	rancherVersion: string,
	ports: string[],
	network: string = 'k3d'
) {
	try {
		createK3dCluster(clusterName, k3sImage, ports)
		addHelmRepositories()
		installCertManager(certManagerVersion)
		installRancher(domain, rancherPassword, rancherVersion)
		waitForRancherDeployment()

		console.log(
			`Rancher is successfully installed and available at https://${domain}`
		)
	} catch (error) {
		console.error('An error occurred during the k3d setup:', error)
	}
}

export async function handleFirstLogin(
	page: Page,
	password: string
): Promise<void> {
	console.log('Handling first login...')
	// Input the password
	await page.getByRole('textbox').fill(password)

	// Click the button with text "Login with Local User"
	await page.getByTestId('login-submit').click()
	await page.getByTestId('setup-agreement').locator('label').click()
	await page.getByTestId('setup-submit').click()
	console.log('First login handled successfully.')
}
