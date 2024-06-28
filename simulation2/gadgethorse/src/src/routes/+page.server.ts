import db from '$lib/_api/database'
import type { PageServerLoad } from './$types'

export const load: PageServerLoad = async () => {
	const products = await db.selectFrom('products').selectAll().orderBy('order').execute()
	const customProducts = await db
		.selectFrom('base_custom_product')
		.selectAll()
		.orderBy('order')
		.execute()

	return {
		products,
		customProducts
	}
}
