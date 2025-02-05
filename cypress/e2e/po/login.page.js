export class LoginPage {
  login(username, password) {
    cy.get('[data-testid="local-login-username"]').type(username)
    cy.get('[data-testid="local-login-password"]').type(password)
    cy.get('[data-testid="login-submit"]').click()
  }
}