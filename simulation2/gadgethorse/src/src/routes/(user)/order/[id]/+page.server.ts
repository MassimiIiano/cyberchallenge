import { error } from '@sveltejs/kit'
import db from '$lib/_api/database'
import type { PageServerLoad } from './$types'
import { getCartData } from '$lib/_api/utils'

export const load: PageServerLoad = async ({ params, parent }) => {
	const id = params.id
	const data = await parent()

	// Check order
	const orderInfo = await db.selectFrom('order').selectAll().where('id', '=', id).executeTakeFirst()

	if (!orderInfo) {
		throw error(404, 'Not found')
	}

	// Check order ownership
	if (data.user?.id !== orderInfo.user) {
		return {
			id: id,
			cart: [],
			orderInfo: orderInfo,
			forbidden: data.user?.id !== orderInfo.user
		}
	}

	// Retrieve order cart
	const cart = await db
		.selectFrom('order_items')
		.select(['item as id', 'qty'])
		.where('order', '=', id)
		.execute()
	const cartData = await getCartData(cart)

	return {
		id: id,
		cart: cartData,
		orderInfo: orderInfo,
		forbidden: data.user?.id !== orderInfo.user
	}
}
