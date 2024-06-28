import { error, fail, redirect } from '@sveltejs/kit'
import db from '$lib/_api/database'
import type { Actions, PageServerLoad } from './$types'
import { getCartCookie, getSessionCookie, parseCustomSVG, setCartCookie } from '$lib/_api/utils'

const fonts = ['inherit', '"Comic Sans MS", "Comic Neue"', 'Pacifico', '"Press Start 2P"']
const defaultFont = fonts[1]

export const load: PageServerLoad = async () => {
	// Retrieve product info
	const product = await db
		.selectFrom('base_custom_product')
		.selectAll()
		.where('id', '=', 'custom-sticker')
		.executeTakeFirst()
	if (!product) {
		throw error(404, 'Not found')
	}

	return {
		id: product.id,
		name: product.name,
		description: JSON.parse(product.description),
		price: product.price,
		image: product.image,
		fonts,
		defaultFont
	}
}

export const actions: Actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const qty = parseInt(data.get('qty')?.toString() ?? '')
		const svg = data.get('svg')?.toString()
		const { text, width, height, x, y, font } = parseCustomSVG(svg || '')

		if (
			qty !== qty ||
			width !== width ||
			height !== height ||
			x !== x ||
			y !== y ||
			!text ||
			text.trim().length === 0 ||
			!font ||
			fonts.findIndex((e) => e === font) === -1
		) {
			return fail(400, { invalid: true, qty })
		}

		const cart = getCartCookie(cookies)

		// Create new customization
		const newId = crypto.randomUUID()
		await db
			.insertInto('customizations')
			.values({
				id: newId,
				base_product: 'custom-sticker',
				color: null,
				font: font,
				text: text,
				width: width.toString(),
				height: height.toString(),
				x: x.toString(),
				y: y.toString()
			})
			.executeTakeFirstOrThrow()

		// Add to cart
		cart.push({
			qty: qty,
			id: newId
		})

		await setCartCookie(cookies, cart, getSessionCookie(cookies) ?? null)

		throw redirect(302, '/cart')
	}
}
