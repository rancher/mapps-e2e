import { Page } from '@playwright/test'

// Functional Utility
export const navigateTo = async (page: Page, url: string): Promise<void> => {
	await page.goto(url)
}

// POM Class
export class LoginPage {
	readonly page: Page

	constructor(page: Page) {
		this.page = page
	}

	async login(username: string, password: string): Promise<void> {
		await this.page.getByTestId('local-login-username').fill(username)
		await this.page
			.getByTestId('local-login-password')
			.getByRole('textbox')
			.fill(password)
		await this.page.getByTestId('login-submit').click()
	}
}
