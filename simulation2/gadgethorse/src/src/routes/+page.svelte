<script lang="ts">
	import type { PageData } from './$types'

	export let data: PageData
</script>

<svelte:head>
	<title>Gadget Horse</title>
</svelte:head>

<div class="overflow-hidden bg-neon">
	<div class="container relative isolate py-16 text-white">
		<h1 class="w-[18ch] text-5xl font-bold">Get gadgets from your favorite games</h1>
		<p class="my-5 w-[45ch]">
			Awesome gadgets, incredible quality, designed by our team, and customizable!
		</p>
		<div class="pt-4">
			<button class="rounded-md bg-salmon px-10 py-4 font-semibold hover:bg-[#F56B56]">
				Shop now
			</button>
		</div>
		<div class="absolute bottom-0 right-0 -z-50 hidden md:block" aria-hidden="true">
			<img src="/cover.png" class="drop-shadow-md" alt="" />
		</div>
	</div>
</div>

<div class="container grid grid-cols-1 gap-2 py-8 md:grid-cols-3 lg:grid-cols-4">
	{#each data.products as product}
		<a href="/sticker/{product.id}"
			><div class="cursor-pointer rounded-xl p-6 hover:bg-black hover:bg-opacity-5">
				<img class="mx-auto w-full max-w-[400px] drop-shadow-lg" src="{product.image}" alt="" />
				<div class="text-center">{product.name}</div>
			</div></a>
	{/each}

	{#each data.customProducts as product}
		<a href="/{product.id}"
			><div class="cursor-pointer rounded-xl p-6 hover:bg-black hover:bg-opacity-5">
				<img class="mx-auto w-full max-w-[400px] drop-shadow-lg" src="{product.image}" alt="" />
				<div class="text-center">{product.name}</div>
			</div></a>
	{/each}
</div>
