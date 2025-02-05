export const openHamburger = () => {
  cy.get('[data-testid="menu-cluster-local"]').click()
}

export const openMenu = (menu) => {
  cy.contains(menu).click()
} 