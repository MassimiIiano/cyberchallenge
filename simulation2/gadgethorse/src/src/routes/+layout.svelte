<script lang="ts">
	import PageLoadingBar from '$lib/PageLoadingBar.svelte';
	import '../app.css';
	import type { PageData } from './$types';

	export let data: PageData;

	$: cartSize = data.cart.reduce((acc, el) => (acc += el.qty), 0);
</script>

<PageLoadingBar />

<header>
	<nav class="h-12 bg-dark-green">
		<div class="container flex h-full items-center justify-between !px-0">
			<div class="flex h-full items-center font-semibold text-white">
				<a href="/" class="nav-link gap-4">
					<img src="/white_logo.svg" alt="" class="w-8" />Gadget Horse
				</a>
			</div>
			<div class="flex h-full items-center font-semibold text-white">
				<a href="/cart" class="nav-link relative">
					<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="currentColor" class="h-5 w-5">
						<path
							d="M2.25 2.25a.75.75 0 000 1.5h1.386c.17 0 .318.114.362.278l2.558 9.592a3.752 3.752 0 00-2.806 3.63c0 .414.336.75.75.75h15.75a.75.75 0 000-1.5H5.378A2.25 2.25 0 017.5 15h11.218a.75.75 0 00.674-.421 60.358 60.358 0 002.96-7.228.75.75 0 00-.525-.965A60.864 60.864 0 005.68 4.509l-.232-.867A1.875 1.875 0 003.636 2.25H2.25zM3.75 20.25a1.5 1.5 0 113 0 1.5 1.5 0 01-3 0zM16.5 20.25a1.5 1.5 0 113 0 1.5 1.5 0 01-3 0z"
						/>
					</svg>
					{#if cartSize > 0}
						<div
							class="absolute flex h-4 min-w-[1rem] -translate-y-2 translate-x-3 items-center justify-center rounded-full bg-primary px-1 text-[0.6rem]"
						>
							{cartSize < 100 ? cartSize : '99+'}
						</div>
					{/if}
				</a>
				{#if !data.user}
					<a href="/login" class="nav-link"> Log in</a>
					<a href="/signup" class="nav-link"> Sign up</a>
				{:else}
					<a href="/user" class="nav-link"> Account</a>
					<a href="/logout" class="nav-link"> Logout</a>
				{/if}
			</div>
		</div>
	</nav>
</header>

<div class="flex-grow flex flex-col">
	<slot />
</div>

<footer class="bg-off py-8">
	<div class="container">
		<div class="text-sm">
			Yes, this is <em>heavily inspired</em> by
			<a class="text-primary underline hover:no-underline" href="https://stickermule.com" target="_blank"
				>Sticker Mule</a
			>. Please don't sue me ❤️. Go buy some real stickers!
		</div>
	</div>
</footer>
