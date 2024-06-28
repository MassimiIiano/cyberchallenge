<script lang="ts">
	import LoadingForm from '$lib/LoadingForm.svelte'
	import type { ActionData } from './$types'

	export let form: ActionData
</script>

<svelte:head>
	<title>Gadget Horse | Sign up</title>
</svelte:head>

<h1 class="mb-8 text-3xl font-bold">Sign up</h1>
<LoadingForm class="relative flex flex-col gap-6">
	<div>
		<label class="mb-1.5 block text-left font-semibold" for="name">Name</label>
		<input
			class="w-full rounded-md focus:border-primary focus:ring-primary"
			id="name"
			name="name"
			type="text"
			value="{form?.name ?? ''}"
			placeholder="Name"
			required />
	</div>
	<div>
		<label class="mb-1.5 block text-left font-semibold" for="">Email</label>
		<input
			class="w-full rounded-md focus:border-primary focus:ring-primary"
			class:border-red-700="{form?.emailUsed}"
			class:ring-red-700="{form?.emailUsed}"
			id="email"
			name="email"
			type="email"
			value="{form?.email ?? ''}"
			placeholder="Email"
			required />
	</div>

	{#if form?.emailUsed}
		<div class="-my-4 text-red-600">Email already in use</div>
	{/if}

	<div>
		<label class="mb-1.5 block text-left font-semibold" for="">Password</label>
		<input
			class="w-full rounded-md focus:border-primary focus:ring-primary"
			class:border-red-700="{form?.passwordTooShort}"
			class:ring-red-700="{form?.passwordTooShort}"
			id="password"
			name="password"
			type="password"
			placeholder="Password"
			required />
	</div>

	{#if form?.passwordTooShort}
		<div class="-my-4 text-red-600">Password must be at least 8 characters long</div>
	{/if}

	<div class="mt-4">
		<button class="rounded-md bg-salmon px-10 py-4 font-semibold text-white hover:bg-[#F56B56]"
			>Sign up</button>
		<div class="mt-3 text-sm">
			already have an account? <a class="text-primary underline hover:no-underline" href="/login"
				>Log in</a
			>.
		</div>
	</div>
</LoadingForm>
