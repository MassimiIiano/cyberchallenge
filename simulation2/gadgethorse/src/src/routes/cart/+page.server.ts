import { fail, redirect } from '@sveltejs/kit'
import db from '$lib/_api/database'
import type { Actions, PageServerLoad } from './$types'
import { getCartCookie, getCartData, getSessionCookie, setCartCookie } from '$lib/_api/utils'
import { createReceiptFile } from '$lib/_api/receipts'

export const load: PageServerLoad = async ({ parent }) => {
	const data = await parent()

	return {
		cart: await getCartData(data.cart)
	}
}

export const actions: Actions = {
	buy: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const name = data.get('name')?.toString()
		const surname = data.get('surname')?.toString()
		const address = data.get('address')?.toString()
		const city = data.get('city')?.toString()
		const country = data.get('country')?.toString()

		if (
			!name ||
			name.trim().length === 0 ||
			!surname ||
			surname.trim().length === 0 ||
			!address ||
			address.trim().length === 0 ||
			!city ||
			city.trim().length === 0 ||
			!country ||
			country.trim().length === 0
		) {
			return fail(400, { invalid: true, name, surname, address, city, country })
		}

		const cart = await getCartData(getCartCookie(cookies))

		if (cart.length === 0) {
			return fail(400, { invalid: true, name, surname, address, city, country })
		}

		const user = getSessionCookie(cookies)
		if (!user) {
			return fail(400, { invalid: true, name, surname, address, city, country })
		}

		// Create the order
		const orderId = await db.transaction().execute(async (trx) => {
			const orderId = crypto.randomUUID()

			await trx
				.insertInto('order')
				.values({
					id: orderId,
					user: user.id,
					name: name,
					surname: surname,
					address: address,
					city: city,
					country: country
				})
				.executeTakeFirstOrThrow()

			// Add all order items
			await trx
				.insertInto('order_items')
				.values(
					cart.map((item) => ({
						item: item.id,
						qty: item.qty,
						order: orderId
					}))
				)
				.executeTakeFirstOrThrow()

			return orderId
		})

		// Create receipt file
		createReceiptFile(user, { id: orderId, name, surname, address, city, country }, cart)

		// Empty cart
		await setCartCookie(cookies, [], user)

		throw redirect(302, `/order/${orderId}`)
	},

	delete: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const product = data.get('product')?.toString()

		if (!product) {
			return fail(400, { invalid: true })
		}

		// Remove from cart
		const cart = getCartCookie(cookies)
		await setCartCookie(
			cookies,
			cart.filter((el) => el.id !== product),
			getSessionCookie(cookies) ?? null
		)

		return { success: true }
	}
}
