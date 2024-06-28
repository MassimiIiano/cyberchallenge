import { error, type Actions, fail, redirect } from '@sveltejs/kit'
import db from '$lib/_api/database'
import type { PageServerLoad } from './$types'
import { getCartCookie, getSessionCookie, parseCustomSVG, setCartCookie } from '$lib/_api/utils'

const fonts = ['inherit', '"Comic Sans MS", "Comic Neue"', 'Pacifico', '"Press Start 2P"']
const defaultFont = fonts[1]
const colors = [
	'bg-[#202020]',
	'bg-[#ffffff]',
	'bg-dark-green',
	'bg-neon',
	'bg-primary',
	'bg-salmon'
]
const defaultColor = colors[2]

export const load: PageServerLoad = async () => {
	// Retrieve product info
	const product = await db
		.selectFrom('base_custom_product')
		.selectAll()
		.where('id', '=', 'custom-shirt')
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
		defaultFont,
		colors,
		defaultColor
	}
}

export const actions: Actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const qty = parseInt(data.get('qty')?.toString() ?? '')
		const svg = data.get('svg')?.toString()
		const { text, width, color, x, y, height, font } = parseCustomSVG(svg || '')

		if (
			qty !== qty ||
			width !== width ||
			height !== height ||
			x !== x ||
			y !== y ||
			!text ||
			text.trim().length === 0 ||
			!font ||
			fonts.findIndex((e) => e === font) === -1 ||
			!color ||
			colors.findIndex((e) => e === color) === -1
		) {
			return fail(400, { invalid: true, qty })
		}

		const cart = getCartCookie(cookies)

		// Save new customization in db
		const newId = crypto.randomUUID()
		await db
			.insertInto('customizations')
			.values({
				id: newId,
				base_product: 'custom-shirt',
				color: color,
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
