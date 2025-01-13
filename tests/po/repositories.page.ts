import { expect, Page } from '@playwright/test'
import { SideBar } from './sidebar.component'
import { verifyRegexDoesExist } from '../utils'
import { openHamburger } from './rancherhome.page'

// /**
//  * Add a Helm repository.
//  * @param {string} repositoryName - Name of the repository.
//  * @param {string} repositoryURL - URL of the repository.
//  * @param {string} repositoryType - Type of the repository ('git' or other).
//  * @param {string} repositoryBranch - Branch of the repository.
//  */
export async function addRepo(
	repositoryName,
	repositoryURL,
	repositoryType,
	repositoryBranch,
	page
) {
	const sidebar = new SideBar(page)
	await sidebar.navigateToReposPage()
	await expect(page.getByText('Loading...')).not.toBeVisible({
		timeout: 35000,
	})
	await expect(
		page.locator('header', { hasText: 'Repositories' })
	).toBeVisible()
	await expect(page.getByText('Create')).toBeVisible()

	await page.getByTestId('masthead-create').click()
	await expect(page.getByText('Repository: Create')).toBeVisible()

	await page.getByPlaceholder('A unique name').fill(repositoryName)

	if (repositoryType === 'git') {
		await page.getByText('Git repository').click()
		await page.getByTestId('clusterrepo-git-repo-input').fill(repositoryURL)
		await page
			.getByTestId('clusterrepo-git-branch-input')
			.fill(repositoryBranch)
	} else if (repositoryType === 'oci') {
		await page.getByText('OCI repository').click()
		await page.getByTestId('clusterrepo-oci-url-input').fill(repositoryURL)
		await page.getByText('Skip TLS Verifications').click()
		await page.getByText('Insecure Plain Http').click()
	} else {
		await page.getByLabel('Index URL').fill(repositoryURL)
	}

	await page.getByTestId('action-button-async-button').click()
	verifyRegexDoesExist(`Active.*${repositoryName}`, page)
	// await burgerMenuToggle(page);
}

// /**
//  * Edit a Helm repository.
//  * @param {string} repositoryName - Name of the repository to edit.
//  */
// async function editRepo(repositoryName, page) {
//     await page.locator(`text=/Active.*${repositoryName}/`).click();
//     await open3dotsMenu('ranchertest', 'Edit Config', false, page);
//     await page.getByLabel('Git Branch').fill('dev-v2.8');
//     await page.getByRole('button', { name: 'Save' }).click();
//   }

//   /**
//    * Delete a Helm repository.
//    * @param {string} repositoryName - Name of the repository to delete.
//    */
//   async function deleteRepo(repositoryName, page) {
//     // await page.goto('/');
//     // await burgerMenuToggle(page);
//     await page.getByText('local').click();
//     await clickNavMenu(['Apps', 'Repositories'], page);

//     await expect(page.locator('header', { hasText: 'Repositories' })).toBeVisible();
//     await expect(page.getByText('Create')).toBeVisible();

//     await page.locator(`text=/Active.*${repositoryName}/`).click();
//     await open3dotsMenu(repositoryName, 'Delete', false, page);
//     await confirmDelete(page);

//     // Ensure the repo is removed before leaving
//     await verifyRegexDoesNotExist(`Active.*${repositoryName}`, page);
//   }

export async function clickRadioWithLabel(label, page) {
	await page.getByRole('radio', { name: label }).click()
}
