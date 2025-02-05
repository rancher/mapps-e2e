import { RepositoriesPage } from './po/repositories.page';
import { SideBar } from './po/sidebar.component';
import { LoginPage } from './po/login.page';
import { generateName } from '../utils';

describe('Repository CRUD Operations', () => {
  let repoPage;
  let sidebar;
  let loginPage;
  let repoName = '';

  beforeEach(() => {
    cy.visit('http://rancher.local');
    loginPage = new LoginPage();
    sidebar = new SideBar();
    repoPage = new RepositoriesPage();
    const username = Cypress.env('RANCHER_USERNAME') || 'admin';
    const password = Cypress.env('RANCHER_PASSWORD') || 'mytestcluster';
    loginPage.login(username, password);
    sidebar.navigateToReposPage();
    repoName = generateName('test-repo');
    repoPage.addRepo(repoName, 'https://git.rancher.io/charts', 'git', 'release-v2.10');
  });

  it('User should not be able to edit the repo name after creation', () => {
    repoPage.searchRepo(repoName);
    repoPage.RepoNameLink.click();
    this.ActionMenu.click()
    cy.contains('Edit Config').click() 
    repoPage.RepoNameInput.should('be.disabled');
  });

  it('User should be able to clone the repo', () => {
    repoPage.searchRepo(repoName);
    repoPage.RepoNameLink.click();
    repoPage.ActionMenu.click()
    cy.contains('Clone').click() 
    cy.get('[placeholder="A unique name"]').type(repoName+'-clone')
    repoPage.CreateButton.click()
    repoPage.searchRepo(repoName+'-clone');
    cy.verifyRegexDoesExist(`Active.*${repoName+'-clone'}`);
  });

}); 