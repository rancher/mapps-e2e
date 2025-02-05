import { ChartsPage } from './po/charts.page';
import { LoginPage } from './po/login.page';
import { SideBar } from './po/sidebar.component';
import { RepositoriesPage } from './po/repositories.page';
import { generateName } from '../utils.js';

describe('Charts Page Flows', () => {
	let chartsPage;
	let loginPage;
	let sidebar;
    let repoPage;
	const chartName = 'example-chart';
	let namespace = '';
	let installName = '';
	const clusterName = 'test-cluster';
	const domain = 'rancher.local';
	const rancherPassword = 'admin';
	const k3sImage = 'rancher/k3s:v1.31.1-k3s1';
	const certManagerVersion = 'v1.15.3';
	const rancherVersion = 'v2.10.1';
	const ports = ['80:80@server:0', '443:443@server:0'];
	const network = 'k3d';

	before(() => {
		// Setup tasks can be done here if needed
		// setupK3dClusterAndRancher(clusterName, domain, rancherPassword, k3sImage, certManagerVersion, rancherVersion, ports, network)
		cy.visit('/');
		cy.handleFirstLogin('admin', 'mytestcluster');
	});

	beforeEach(() => {
		chartsPage = new ChartsPage();
		loginPage = new LoginPage();
		sidebar = new SideBar();
        repoPage = new RepositoriesPage();
		// let repoUrl = setupOciRepoServer(9191, network)
		cy.visit('/');
		const username = Cypress.env('RANCHER_USERNAME') || 'admin';
		const password = Cypress.env('RANCHER_PASSWORD') || 'mytestcluster';
		const repoUrl = 'oci://zot.zot.svc.cluster.local:5000';
		const repoName = generateName('test-repo');
		loginPage.login(username, password);
        sidebar.navigateToReposPage();
		repoPage.addRepo(repoName, repoUrl, 'oci', 'latest');
		sidebar.navigateToChartsPage();
		namespace = generateName('test-ns');
		cy.exec(`kubectl create namespace ${namespace}`)
		installName = generateName('example-chart');
	});

	afterEach(() => {
		// console.log(`Deleting namespace: ${namespace}`)
		cy.exec(`kubectl delete namespace ${namespace}`)
	});

	after(() => {
		// deleteK3dCluster(clusterName)
	});

	it('Search and Install Chart Flow', () => {
		chartsPage.installChart(chartName, '0.1.0', namespace, installName);
		cy.get('[data-testid="action-button-async-button"]').should('be.visible');
		cy.contains('SUCCESS: helm install').should('be.visible', { timeout: 120000 });
	});

	it('Download Chart Flow', () => {
		chartsPage.downloadChart(chartName);
	});
});
