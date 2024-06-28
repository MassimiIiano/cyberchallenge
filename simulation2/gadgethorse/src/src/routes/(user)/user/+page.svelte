<script lang="ts">
	import type { PageData } from './$types'

	export let data: PageData
</script>

<div class="container py-16">
	<h1 class="text-5xl font-bold">
		Hey, {data.user.name}!
	</h1>

	<h2 class="mt-8 text-4xl font-bold">Your order history</h2>

	<div class="mt-8">
		<div>
			{#if data.orders.length === 0}
				<div class="py-12 text-center italic">You don't have any order</div>
			{:else}
				<table class="w-full border-separate border-spacing-2">
					<tbody>
						{#each data.orders as item, idx}
							<tr>
								<td class="flex items-center gap-8">
									<div>
										<a class="font-semibold text-dark-green hover:underline" href="/order/{item.id}"
											><span class="text-lg">Order</span> #{item.id}</a>
									</div>
								</td>
							</tr>
							{#if idx !== data.orders.length - 1}
								<tr>
									<td>
										<hr class="my-2" />
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			{/if}
		</div>
	</div>
</div>
