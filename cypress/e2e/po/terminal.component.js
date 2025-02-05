export class Terminal{
    get TerminalTabCloseButton() {
        return cy.get('[data-testid="wm-tab-close-button"]');
    }
    get TabLabel() {
        return cy.get('.tab-label');
    }
    // Close tab by label which is a sibling
    closeTabByLabel(label) {
        cy.get('.tab-label').contains(label).siblings('[data-testid="wm-tab-close-button"]').click();
    }
    closeAllTabs() {
        cy.get('[data-testid="wm-tab-close-button"]').each(($el, index, $list) => {
            cy.wrap($el).click();
        });
    }
}