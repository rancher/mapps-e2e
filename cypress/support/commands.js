Cypress.Commands.add('installLocalChart', (chartName, chartPath, namespacePrefix) => {
  const randomSuffix = Cypress._.random(0, 1e6);
  const namespace = `${namespacePrefix}_${randomSuffix}`;

  cy.exec(`kubectl create namespace ${namespace}`);
  cy.exec(`helm install ${chartName} ${chartPath}/${chartName} --namespace ${namespace}`);

  return cy.wrap(namespace);
});

Cypress.Commands.add('pushChartToRepo', (chartName, chartPath, repoUrl, repoName = 'testrepo', version = '0.1.0') => {
  const chartPackage = `${chartName}-${version}.tgz`;
  cy.exec(`helm push ${chartPackage} ${repoUrl}/${repoName} --insecure-skip-tls-verify`, { cwd: chartPath });
  return cy.wrap(`${repoUrl}/${repoName}`);
});

Cypress.Commands.add('setupHttpsRepoServer', (repoPath, port) => {
  cy.exec(`helm repo index ${repoPath}`);
  cy.task('startHttpServer', { repoPath, port });
  return cy.wrap(`http://localhost:${port}`);
});

Cypress.Commands.add('setupGitRepoServer', (repoPath, port) => {
  cy.exec('git init --bare', { cwd: repoPath });
  cy.task('startGitDaemon', { repoPath, port });
  return cy.wrap(`https://localhost:${port}/${path.basename(repoPath)}`);
});

Cypress.Commands.add('setupOciRepoServer', (port, network) => {
  cy.exec(`docker ps | grep registry || docker run -d -p 5000:5000 --name registry registry:2 --network ${network}`);
  return cy.wrap(`oci://localhost:${port}`);
});

Cypress.Commands.add('teardownOCIRepoServer', () => {
  cy.exec('docker stop registry && docker rm registry');
});

Cypress.Commands.add('verifyRegexDoesExist', (name) => {
  cy.contains(new RegExp(`${name}`)).should('be.visible');
});

Cypress.Commands.add('verifyRegexDoesNotExist', (name) => {
  cy.contains(new RegExp(`${name}`)).should('not.exist');
});

Cypress.Commands.add('handleFirstLogin', (username, password) => {
  cy.visit('/login');

  cy.get('body').then(($body) => {
    // if cy.get('[data-testid="first-login-message"]' does not exist, then it is not the first login
    if ($body.find('[data-testid="first-login-message"]').length > 0) {
      // Handle first login
      cy.get('input').type(password);
      cy.get('[data-testid="login-submit"]').click();
      cy.get('[data-testid="setup-agreement"] >.checkbox-container >.checkbox-custom').click();
      // Handle first login
      cy.get('input').type(password);
      cy.get('[data-testid="login-submit"]').click();
      cy.get('[data-testid="setup-agreement"] > .checkbox-container > .checkbox-custom').click();
      cy.get('[data-testid="setup-submit"]').click();
    } else {
      // Fallback to normal login
      cy.get('[data-testid="local-login-username"]').type(username);
      cy.get('[data-testid="local-login-password"]').type(password);
      cy.get('[data-testid="login-submit"]').click();
    }
  });
});

Cypress.Commands.add('generateName', (prefix) => {
  const randomString = Math.random().toString(36).substring(2, 8);
  return `${prefix}-${randomString}`;
}); 