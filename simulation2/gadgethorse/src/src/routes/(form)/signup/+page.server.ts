import { fail, redirect } from '@sveltejs/kit'
import type { Actions } from './$types'
import db from '$lib/_api/database'
import bcrypt from 'bcrypt'
import { setSessionCookie } from '$lib/_api/utils'

export const actions: Actions = {
	default: async ({ request, cookies }) => {
		const data = await request.formData()

		// Validation
		const name = data.get('name')?.toString()
		const email = data.get('email')?.toString()
		const password = data.get('password')?.toString()

		if (!name || !email || !password) {
			return fail(400, { name, email, emailUsed: false })
		}

		if (name.trim().length === 0 || email.trim().length === 0) {
			return fail(400, { name, email, emailUsed: false })
		}

		if (password.length < 8) {
			return fail(400, { name, email, passwordTooShort: true })
		}

		// Registering user
		try {
			const userId = crypto.randomUUID()
			await db.transaction().execute(async (trx) => {
				await trx
					.insertInto('users')
					.values({
						id: userId,
						name: name.trim(),
						email: email.trim().toLowerCase(),
						password: await bcrypt.hash(password, 12)
					})
					.executeTakeFirstOrThrow()

				await trx
					.insertInto('saved_cart')
					.values({
						user: userId,
						cart: '[]'
					})
					.executeTakeFirstOrThrow()
			})

			setSessionCookie(cookies, {
				id: userId,
				name: name.trim(),
				email: email.trim().toLowerCase()
			})

			throw redirect(302, '/user')
		} catch (error) {
			// In case of duplicate email
			if (error instanceof Error) {
				if ((error as Error & Record<string, unknown>).code === 'ER_DUP_ENTRY') {
					return fail(409, { name, email, emailUsed: true })
				}
			}
			throw error
		}
	}
}
