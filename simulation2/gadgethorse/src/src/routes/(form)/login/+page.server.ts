import { fail, redirect } from '@sveltejs/kit'
import type { Actions } from './$types'
import db from '$lib/_api/database'
import bcrypt from 'bcrypt'
import { setCartCookie, setSessionCookie } from '$lib/_api/utils'

export const actions: Actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const email = data.get('email')?.toString()
		const password = data.get('password')?.toString()

		if (!email || !password) {
			return fail(400, { email, wrongCredentials: true })
		}

		// Login
		const user = await db
			.selectFrom('users')
			.selectAll()
			.where('email', '=', email.toLowerCase())
			.executeTakeFirst()

		if (!user || !(await bcrypt.compare(password, user.password))) {
			return fail(401, { email, wrongCredentials: true })
		}

		setSessionCookie(cookies, user)

		// Recover cart
		const savedCart = await db
			.selectFrom('saved_cart')
			.selectAll()
			.where('user', '=', data.get('user')?.toString() ?? user.id)
			.executeTakeFirst()
		if (savedCart) {
			await setCartCookie(cookies, JSON.parse(savedCart.cart ?? '[]'), null)
		}

		throw redirect(302, '/user')
	}
}
