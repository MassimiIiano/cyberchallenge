import { error } from '@sveltejs/kit'
import { getSessionCookie } from '$lib/_api/utils'
import db from '$lib/_api/database'
import type { RequestHandler } from './$types'
import { readReceipt } from '$lib/_api/receipts'

export const GET: RequestHandler = async ({ cookies, params }) => {
	// Check user
	const user = getSessionCookie(cookies)
	if (!user) {
		throw error(404, 'Not found')
	}

	// Check order
	const order = await db
		.selectFrom('order')
		.selectAll()
		.where('id', '=', params.id)
		.executeTakeFirst()
	if (!order) {
		throw error(404, 'Not found')
	}

	// Check receipt existance and download
	const receipt = readReceipt(user, params.id)
	if (!receipt) {
		throw error(404, 'Not found')
	}
	return new Response(receipt, {
		headers: {
			'Content-Type': 'text/csv',
			'Content-Disposition': 'attachment; filename="receipt.csv"'
		}
	})
}
