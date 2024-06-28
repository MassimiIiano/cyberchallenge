<script lang="ts">
	import StorePage from '$lib/StorePage.svelte'
	import type { PageData } from './$types'

	export let data: PageData
</script>

<StorePage data="{data}">
	<svelte:fragment slot="image">
		<img class="mx-auto w-full drop-shadow-lg md:w-7/12 lg:w-full" src="{data.image}" alt="" />
	</svelte:fragment>
	<input type="hidden" value="{data.id}" name="product" id="product" />
</StorePage>
