import { LoginPage } from './po/login.page.js';
import { SideBar } from './po/sidebar.component.js';
import { ChartsPage } from './po/charts.page.js';
import { Terminal } from './po/terminal.component.js';
import { generateName } from '../utils.js';

describe('Helm Operations Management Flow', () => {
  let chartsPage;
  let loginPage;
  let sidebar;
  let repoPage;
  let terminal;
  let installedApps;
  const chartName = 'example-chart';
  let namespace = '';
  const repoName = generateName('test-repo');
  let installName = '';

  before(() => {
    cy.visit('/');
  });

  beforeEach(() => {
    loginPage = new LoginPage();
    sidebar = new SideBar();
    chartsPage = new ChartsPage();
    repoPage = new RepositoriesPage();
    terminal = new Terminal();
    cy.visit('/');
    const username = Cypress.env('RANCHER_USERNAME') || 'admin';
    const password = Cypress.env('RANCHER_PASSWORD') || 'mytestcluster';
    const repoUrl = 'oci://zot.zot.svc.cluster.local:5000';
    namespace = generateName('test-ns');
    installName = generateName('example-chart');

    cy.exec(`kubectl create namespace ${namespace}`);
    loginPage.login(username, password);
    sidebar.navigateToReposPage();
    repoPage.addRepo(repoName, repoUrl, 'oci', 'latest');
    // Install a chart to generate some operations
    sidebar.navigateToChartsPage();
    chartsPage.installChart(chartName, '0.1.0', namespace, installName);
    cy.contains('SUCCESS').should('be.visible');
  });

  afterEach(() => {
		sidebar.navigateToReposPage();
		repoPage.removeRepo(repoName);
		cy.exec(`kubectl delete namespace ${namespace} --ignore-not-found`);
		// terminal.closeAllTabs();
  });

  it('View Recent Operations Flow', () => {
    // Navigate to Recent Operations
    sidebar.navigateToRecentOperations();

    // Verify operations list is displayed
    cy.get('[data-testid="sortable-table"]').should('be.visible');
    cy.contains(installName).should('be.visible');
    cy.contains('SUCCESS').should('be.visible');
  });

  it('Filter Operations Flow', () => {
    sidebar.navigateToRecentOperations();

    // Test status filter
    cy.get('[data-testid="status-filter"]').click();
    cy.contains('Success').click();
    cy.contains('SUCCESS').should('be.visible');
    cy.contains('FAILED').should('not.exist');

    // Clear filter
    cy.get('[data-testid="status-filter"]').click();
    cy.contains('All').click();
  });

  it('View Operation Details Flow', () => {
    sidebar.navigateToRecentOperations();

    // Click on operation to view details
    cy.contains(installName).click();

    // Verify operation details
    cy.contains('Operation Details').should('be.visible');
    cy.contains('Logs').should('be.visible');
    cy.get('.log-container').should('be.visible');
  });

  it('View and Download YAML Flow', () => {
    sidebar.navigateToRecentOperations();

    // Open action menu and view YAML
    cy.contains(installName)
      .parents('tr')
      .find('[data-testid="action-menu"]')
      .click();
    cy.contains('View YAML').click();

    // Verify YAML content
    cy.get('.yaml-editor').should('be.visible');

    // Download YAML
    cy.contains('Download YAML').click();
    cy.readFile(`cypress/downloads/helm-operation-${installName}.yaml`, { timeout: 10000 }).should('exist');
  });

  it('Delete Operation Flow', () => {
    sidebar.navigateToRecentOperations();

    // Delete operation
    cy.contains(installName)
      .parents('tr')
      .find('[data-testid="action-menu"]')
      .click();
    cy.contains('Delete').click();

    // Confirm deletion
    cy.get('[data-testid="prompt-remove-confirm-button"]').click();
    cy.contains('SUCCESS').should('be.visible');

    // Verify operation is removed
    cy.contains(installName).should('not.exist');
  });
});