import 'cypress-wait-until';

export class InstalledAppsPage {
  get actionMenuButton() {
    cy.get('[data-testid="sortable-table-0-action-button"]')
  }
  get NamespaceDropdown() {
    return cy.get('[data-testid="namespace-dropdown"]')
  }

  get FlatList() {
    return cy.get('[data-testid="button-group-child-0"]')
  }

  // Search input
  get SearchInput() {
    return cy.get('[data-testid="search-box-filter-row"] > .input-sm')
  }

  get UpgradeIcon() {
    return cy.get('.badge-state > .icon')
  }

  // Methods
  searchChart(chartName) {
    this.SearchInput.clear().type(`${chartName}`);
    cy.waitUntil(() =>
      cy.url().then(url => url.includes(`q=${chartName}`))
    );
  }

  searchByNamespace(namespace) {
    cy.get('[data-testid="search-box-filter-row"]').clear().type(`${namespace}{enter}`);
    this.FlatList.click();
    cy.waitUntil(() =>
      cy.url().then(url => url.includes(`q=${namespace}`))
    );
  }

  clickOnUpgradeIcon(chartName) {
    this.UpgradeIcon.click();
  }

  upgradeChart(chartName, namespace) {
    this.searchByNamespace(namespace);
    // wait for the table to be filtered
    this.clickOnUpgradeIcon(chartName);
    cy.contains('Upgrade').click();
    // this.NamespaceDropdown.type(`${namespace}{enter}`);
    cy.contains('button', 'Next').click({ multiple: true });
    cy.contains('button', 'Upgrade').click();
  }
}
