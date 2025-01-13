import { test, expect } from '@playwright/test'
import { ChartsPage } from './po/charts.page'
import { LoginPage } from './po/login.page'
import { execSync } from 'child_process'
import {
	setupGitRepoServer,
	pushChartToRepo,
	setupOciRepoServer,
	setupK3dClusterAndRancher,
	deleteK3dCluster,
	handleFirstLogin,
} from './utils'
import { SideBar } from './po/sidebar.component'
import { addRepo } from './po/repositories.page'

test.describe('Charts Page Flows', () => {
	let chartsPage: ChartsPage
	let loginPage: LoginPage
	let sidebar: SideBar
	const chartName = 'example-chart'
	let namespace = ''
	const clusterName = 'test-cluster'
	const domain = 'rancher.localhost'
	const rancherPassword = 'admin'
	const k3sImage = 'rancher/k3s:v1.31.1-k3s1'
	const certManagerVersion = 'v1.15.3'
	const rancherVersion = 'v2.10.1'
	const ports = ['80:80@server:0', '443:443@server:0']
	const network = 'k3d'

	test.beforeAll(async ({ page }) => {
		setupK3dClusterAndRancher(
			clusterName,
			domain,
			rancherPassword,
			k3sImage,
			certManagerVersion,
			rancherVersion,
			ports,
			network
		)
		await page.goto('/')
		await handleFirstLogin(page, rancherPassword)
	})

	test.beforeEach(async ({ page }) => {
		chartsPage = new ChartsPage(page)
		loginPage = new LoginPage(page)
		sidebar = new SideBar(page)
		let repoUrl = setupOciRepoServer(9191, network)
		await page.goto('/')
		const username = process.env.RANCHER_USERNAME || 'admin'
		const password = process.env.RANCHER_PASSWORD || 'admin'
		await loginPage.login(username, password)
		repoUrl = await pushChartToRepo(chartName, '.', repoUrl)
		await addRepo('test-repo', repoUrl, 'oci', 'latest', page)
		await sidebar.navigateToChartsPage()
	})

	test.afterEach(async () => {
		// console.log(`Deleting namespace: ${namespace}`)
		// execSync(`kubectl delete namespace ${namespace}`, {
		// 	stdio: 'inherit',
		// })
	})

	test.afterAll(async () => {
		deleteK3dCluster(clusterName)
	})

	test('Search and Install Chart Flow', async ({ page }) => {
		await chartsPage.installChart(chartName)
		expect(page.getByTestId('action-button-async-button')).toBeVisible()
		await page.waitForSelector('text=SUCCESS', { state: 'visible' })
		expect(await page.isVisible('text=SUCCESS')).toBeTruthy()
	})

	test('Delete Chart Flow', async ({ page }) => {
		await chartsPage.deleteChart(chartName)
	})

	test('Download Chart Flow', async ({ page }) => {
		await chartsPage.downloadChart(chartName)
	})

	// test("Upgrade Installed Chart Flow", async ({ page }) => {
	//   // Upgrade the installed chart
	//   await chartsPage.upgradeChart(chartName);

	//   // Validate upgrade
	//   await page.waitForSelector("text=Upgrade Complete", { state: "visible" });
	//   expect(await page.isVisible("text=SUCCESS")).toBeTruthy();
	// });
})
