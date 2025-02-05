import { ChartsPage } from './po/charts.page';
import { LoginPage } from './po/login.page';
import { SideBar } from './po/sidebar.component';
import { RepositoriesPage } from './po/repositories.page';
import { generateName } from '../utils.js';
import { Terminal } from './po/terminal.component.js';
import { InstalledAppsPage } from './po/installed.apps.page';

describe.only('Installed Apps Page Flows', () => {
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
    chartsPage = new ChartsPage();
    loginPage = new LoginPage();
    sidebar = new SideBar();
    repoPage = new RepositoriesPage();
    terminal = new Terminal();
    installedApps = new InstalledAppsPage();
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
    sidebar.navigateToChartsPage();
    // Install a chart for testing
    chartsPage.installChart(chartName, '0.1.0', namespace, installName);
    cy.contains('SUCCESS').should('be.visible');
  });

  afterEach(() => {
    sidebar.navigateToReposPage();
    repoPage.removeRepo(repoName);
    cy.exec(`kubectl delete namespace ${namespace} --ignore-not-found`);
    // terminal.closeAllTabs();
  });

  it('View Installed Apps Flow', () => {
    sidebar.navigateToInstalledAppsPage();
    installedApps.searchByNamespace(namespace);
    
    // Verify chart information is displayed
    cy.contains(installName).should('be.visible');
    cy.contains('0.1.0').should('be.visible'); // Version check
    
    // Verify action menu functionality
    cy.contains(installName)
      .parents('tr')
      .find('[data-testid="sortable-table-0-action-button"]')
      .click();
    
    // Verify menu options
    cy.contains('View YAML').should('be.visible');
    cy.contains('Download YAML').should('be.visible');
    cy.contains('Edit/Upgrade').should('be.visible');
    cy.contains('Delete').should('be.visible');
  });

  it('Upgrade Installed Apps Flow', () => {
    sidebar.navigateToInstalledAppsPage();
    installedApps.upgradeChart(chartName, namespace);
    cy.contains('SUCCESS: helm upgrade').should('be.visible');
  });

  it.only('Delete Installed Apps Flow', () => {
    sidebar.navigateToInstalledAppsPage();
    installedApps.searchByNamespace(namespace);
    
    // Select and delete the app
    cy.contains(installName)
      .parents('tr')
      .find('[data-testid="sortable-table-0-action-button"]')
      .click();
    cy.get('[data-testid="action-menu-5-item"]').click();
    
    // Confirm deletion
    cy.get('[data-testid="prompt-remove-confirm-button"]').click();
    cy.contains('SUCCESS: helm uninstall').should('be.visible');
  });
});