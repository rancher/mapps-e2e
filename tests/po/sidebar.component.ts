import { expect, Page } from '@playwright/test'

// Page
export class SideBar {
	readonly page: Page

	constructor(page: Page) {
		this.page = page
	}

	// Navigate through multiple tabs
	async navigateTabs(labels: string[]): Promise<void> {
		for (const label of labels) {
			await clickTab(this.page, label)
		}
		await assertTabVisible(this.page, labels[labels.length - 1])
	}

	// Additional tab-specific methods can go here
	async openTab(label: string): Promise<void> {
		await clickTab(this.page, label)
		await assertTabVisible(this.page, label)
	}

	async navigateToChartsPage() {
		await this.page.click('text=local')
		await this.navigateTabs(['Apps', 'Charts'])
	}

	async navigateToInstalledAppsPage() {
		await this.page.click('text=local')
		await this.navigateTabs(['Apps', 'Installed Apps'])
	}

	async navigateToReposPage() {
		await this.page.click('text=local')
		await this.navigateTabs(['Apps', 'Repositories'])
	}
}

// Utils
// Click on a tab by its label
export const clickTab = async (page: Page, label: string): Promise<void> => {
	await page.locator('nav').getByText(label).click()
}

// Assert a tab is visible
export const assertTabVisible = async (
	page: Page,
	label: string
): Promise<void> => {
	await expect(page.locator('nav').getByText(label)).toBeVisible()
}
