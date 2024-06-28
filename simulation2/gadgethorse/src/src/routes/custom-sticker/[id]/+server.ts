import { error } from '@sveltejs/kit'
import type { RequestHandler } from './$types'
import { findUserProduct, generateSVGResponse } from '$lib/_api/svgUtils'

export const GET: RequestHandler = async ({ cookies, params }) => {
	const id = params.id
	const sticker = await findUserProduct(cookies, id, 'custom-sticker')

	if (!sticker) {
		throw error(404, 'not found')
	}

	return generateSVGResponse(sticker)
}
