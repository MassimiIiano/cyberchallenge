<script lang="ts">
	import LoadingForm from '$lib/LoadingForm.svelte'
	import type { ActionData } from './$types'

	export let form: ActionData
</script>

<svelte:head>
	<title>Gadget Horse | Log in</title>
</svelte:head>

<h1 class="mb-8 text-3xl font-bold">Log in</h1>
<LoadingForm class="relative flex flex-col gap-6">
	<div>
		<label class="mb-1.5 block text-left font-semibold" for="email">Email</label>
		<input
			class="w-full rounded-md focus:border-primary focus:ring-primary"
			class:border-red-700="{form?.wrongCredentials}"
			class:ring-red-700="{form?.wrongCredentials}"
			id="email"
			name="email"
			type="email"
			value="{form?.email ?? ''}"
			placeholder="Email"
			required />
	</div>

	<div>
		<label class="mb-1.5 block text-left font-semibold" for="password">Password</label>
		<input
			class="w-full rounded-md focus:border-primary focus:ring-primary"
			class:border-red-700="{form?.wrongCredentials}"
			class:ring-red-700="{form?.wrongCredentials}"
			id="password"
			name="password"
			type="password"
			placeholder="Password"
			required />
	</div>

	{#if form?.wrongCredentials}
		<div class="-my-4 text-red-600">Wrong email or password</div>
	{/if}

	<div class="mt-4">
		<button class="rounded-md bg-salmon px-10 py-4 font-semibold text-white hover:bg-[#F56B56]"
			>Log in</button>
		<div class="mt-3 text-sm">
			or <a class="text-primary underline hover:no-underline" href="/signup">create an account</a>.
		</div>
	</div>
</LoadingForm>
