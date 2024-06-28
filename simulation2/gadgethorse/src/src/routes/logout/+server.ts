import { redirect, type RequestHandler } from '@sveltejs/kit'

export const GET: RequestHandler = async ({ cookies }) => {
	cookies.delete('session')
	cookies.delete('cart')

	throw redirect(302, '/')
}
