import { expect, Page } from '@playwright/test'
import { SideBar } from './sidebar.component'
import { execSync } from 'child_process'
import { v4 as uuidv4 } from 'uuid'
import * as fs from 'fs'

export class ChartsPage {
	private sidebar: SideBar

	constructor(private page: Page) {
		this.sidebar = new SideBar(page)
	}

	async searchChart(chartName: string) {
		await this.page.fill('[placeholder="Filter"]', chartName)
		await this.page.press('[placeholder="Filter"]', 'Enter')
	}

	async installChart(chartName: string) {
		await this.searchChart(chartName)
		await this.page.click(`text=${chartName}`)
		// await this.page.click('button:has-text("Install")');
		await this.page.getByTestId('btn-chart-install').click()
		while (!(await this.page.isVisible('button:has-text("Install")'))) {
			await this.page.click('button:has-text("Next")')
		}

		// Click the "Install" button once it's visible
		await this.page.click('button:has-text("Install")')
	}

	async deleteChart(chartName: string) {
		await this.sidebar.navigateToInstalledAppsPage()
		await this.searchChart(chartName)
		await this.page
			.getByTestId('sortable-table_check_select_all')
			.locator('span')
			.click()
		await this.page.getByTestId('sortable-table-promptRemove').click()
		await this.page.getByTestId('prompt-remove-confirm-button').click()
		await this.page.waitForSelector('text=Deleting...', {
			state: 'hidden',
		})
		expect(
			await this.page.waitForSelector('text=SUCCESS', {
				state: 'visible',
			})
		).toBeTruthy()
	}

	async downloadChart(chartName: string) {
		await this.searchChart(chartName)
		await this.page.click(`text=${chartName}`)
		await Promise.all([
			this.page.waitForEvent('download'),
			this.page.click('link:has-text("Download")'),
		])
	}
}
