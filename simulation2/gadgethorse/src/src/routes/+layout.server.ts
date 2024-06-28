import type { LayoutServerLoad } from './$types'
import { getCartCookie, getSessionCookie } from '$lib/_api/utils'

export const load: LayoutServerLoad = async ({ cookies }) => {
	const cart = getCartCookie(cookies)
	const user = getSessionCookie(cookies) ?? null

	return { cart, user }
}
