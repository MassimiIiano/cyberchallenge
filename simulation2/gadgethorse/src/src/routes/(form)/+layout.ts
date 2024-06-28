import { redirect } from '@sveltejs/kit'
import type { LayoutLoad } from './$types'

export const load: LayoutLoad = async ({ parent }) => {
	const data = await parent()

	// If already logged hide these pages
	if (data.user) {
		throw redirect(302, '/user')
	}
}
