import { Page, Locator } from '@playwright/test'

let hamburgerMenu: Locator
;(page: Page) => {
	hamburgerMenu = page.getByTestId('menu-cluster-local')
}
export const openHamburger = async () => {
	await hamburgerMenu.click()
}

/**
 * Open the menu with the given name.
 * @param {string} menu - The name of the menu to open.
 */
async function openMenu(menu, page) {
	await page.getByText(menu).click()
}
