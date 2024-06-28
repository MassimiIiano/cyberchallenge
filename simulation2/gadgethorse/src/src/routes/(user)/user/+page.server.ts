import { redirect } from '@sveltejs/kit'
import type { PageServerLoad } from './$types'
import db from '$lib/_api/database'

export const load: PageServerLoad = async ({ parent }) => {
	const data = await parent()
	if (!data.user) {
		throw redirect(302, '/')
	}

	// Retrieve user's orders
	const orders = await db.selectFrom('order').selectAll().where('user', '=', data.user.id).execute()

	return {
		orders: orders
	}
}
