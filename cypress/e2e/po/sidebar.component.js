export class SideBar {
  navigateTabs(labels) {
    labels.forEach(label => {
      cy.get('nav').contains(label).click({ force: true })
    })
    cy.get('nav').contains(labels[labels.length - 1]).should('be.visible')
  }

  openTab(label) {
    cy.get('[data-testid="menu-cluster-local"]').click({ force: true })
    cy.get('nav').contains(label).should('be.visible')
  }

  navigateToChartsPage() {
    cy.get('[data-testid="menu-cluster-local"]').click({ force: true })
    this.navigateTabs(['Apps', 'Charts'])
  }

  navigateToInstalledAppsPage() {
    cy.get('[data-testid="menu-cluster-local"]').click({ force: true })
    this.navigateTabs(['Apps', 'Installed Apps'])
  }

  navigateToReposPage() {
    cy.get('[data-testid="menu-cluster-local"]').click({ force: true })
    this.navigateTabs(['Apps', 'Repositories'])
  }
  navigateToRecentOperations() {
    cy.get('[data-testid="menu-cluster-local"]').click({ force: true })
    this.navigateTabs(['Apps', 'Recent Operations'])
  }
}