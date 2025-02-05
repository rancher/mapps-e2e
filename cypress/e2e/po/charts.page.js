import "cypress-wait-until"

export class ChartsPage {
  get ChartInstallButton() {
    return cy.get('[data-testid="btn-chart-install"]')
  }
  get DeleteButton() {
    return cy.get('[data-testid="sortable-table-promptRemove"]');
  }

  get ConfirmDeleteButton() {
    return cy.get('[data-testid="prompt-remove-confirm-button"]');
  }

  get NamespaceDropdown() {
    return cy.get('.vs__selected');
  }

  // Table and row selectors
  get Table() {
    return cy.get('[data-testid="sortable-table"]');
  }

  get TableRows() {
    return this.Table.find('tbody tr');
  }

  get TableRowNames() {
    return this.TableRows.find('td:nth-child(2)'); // Assuming "Name" is in the second column
  }

  // Checkbox selectors
  get SelectAllCheckbox() {
    return cy.get('[data-testid="sortable-table_check_select_all"] span');
  }

  get RowCheckboxes() {
    return this.TableRows.find('.checkbox-container input');
  }

  // Search input
  get SearchInput() {
    return cy.get('[placeholder="Filter"]');
  }

  // Status verification selectors
  get SuccessToast() {
    return cy.contains('SUCCESS').should('be.visible');
  }

  get DeletingSpinner() {
    return cy.contains('text=Deleting...');
  }

  get ChartNameTextBox() {
    return cy.get('[data-testid="name-ns-description-name"] > .labeled-input');
  }

  // Methods
  searchChart(chartName) {
    this.SearchInput.clear().type(`${chartName}{enter}`);
    cy.waitUntil(() =>
      cy.url().then(url => url.includes(`q=${chartName}`))
    );
  }

  clickCheckboxForChart(chartName) {
    this.searchChart(chartName);
    this.TableRows.contains(chartName).parents('tr').find('.checkbox-container input').click();
  }

  verifyChartStatus(chartName, expectedStatus) {
    this.searchChart(chartName);
    this.TableRows.contains(chartName)
      .parents('tr')
      .find('.badge-state')
      .should('contain.text', expectedStatus);
  }

  selectAllRows() {
    this.SelectAllCheckbox.click();
  }

  installChart(chartName, version, namespace, installName) {
    this.searchChart(chartName);
    cy.contains(chartName).click();
    cy.contains(version).click();
    this.ChartInstallButton.click({ force: true});
    this.NamespaceDropdown.type(`${namespace}{enter}`);
    this.ChartNameTextBox.type(`${installName}{enter}`);
    cy.contains('button', 'Next').click({ multiple: true });
    cy.contains('button', 'Install').click();
  }

  deleteChart(installName) {
    this.searchChart(installName);
    this.SelectAllCheckbox.click();
    this.DeleteButton.click();
    this.ConfirmDeleteButton.click();
    this.DeletingSpinner.should('not.exist');
    this.SuccessToast.should('be.visible');
  }

  downloadChart(chartName) {
    this.searchChart(chartName);
    cy.contains(chartName).click();
    cy.contains('Download').click();
  }

  verifyDownloadedChart(chartName) {
    cy.readFile(`cypress/downloads/${chartName}.tgz`, 'binary', { timeout: 10000 }).should('exist');
  }

  upgradeChart(chartName, namespace) {
    this.searchChart(chartName);
    cy.contains(chartName).click();
    cy.contains('Upgrade').click();
    this.NamespaceDropdown.type(`${namespace}{enter}`);
    cy.contains('button', 'Next').click({ multiple: true });
    cy.contains('button', 'Upgrade').click();
  }
}
