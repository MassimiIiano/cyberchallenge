import { error, type Actions, fail, redirect } from '@sveltejs/kit'
import db from '$lib/_api/database'
import type { PageServerLoad } from './$types'
import { getCartCookie, getSessionCookie, setCartCookie } from '$lib/_api/utils'

export const load: PageServerLoad = async ({ params }) => {
	const id = params.id

	// Retrieve product info
	const product = await db
		.selectFrom('products')
		.selectAll()
		.where('id', '=', id)
		.executeTakeFirst()
	if (!product) {
		throw error(404, 'Not found')
	}

	return {
		id: product.id,
		name: product.name,
		description: JSON.parse(product.description),
		price: product.price,
		image: product.image
	}
}

export const actions: Actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validate
		const qty = parseInt(data.get('qty')?.toString() ?? '')
		const product = data.get('product')?.toString()

		if (qty !== qty || !product) {
			return fail(400, { invalid: true, qty })
		}

		const cart = getCartCookie(cookies)

		// Add to cart
		for (const element of cart) {
			if (element.id === product) {
				element.qty += qty
				await setCartCookie(cookies, cart, getSessionCookie(cookies) ?? null)
				throw redirect(302, '/cart')
			}
		}

		cart.push({
			qty: qty,
			id: product
		})

		await setCartCookie(cookies, cart, getSessionCookie(cookies) ?? null)

		throw redirect(302, '/cart')
	}
}
