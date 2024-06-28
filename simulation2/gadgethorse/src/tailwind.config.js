/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/**/*.{html,js,svelte,ts}'],
	theme: {
		extend: {
			colors: {
				'dark-green': '#254441',
				neon: '#43AA8B',
				primary: '#DB504A',
				salmon: '#FF6F59'
			}
		}
	},
	plugins: [require('@tailwindcss/forms')]
}
