<script lang="ts">
	import OrderViewer from '$lib/OrderViewer.svelte'
	import type { PageData } from './$types'

	export let data: PageData
</script>

{#if !data.forbidden}
	<OrderViewer
		items="{data.cart}"
		orderId="{data.id}"
		isCart="{false}"
		orderInfo="{data.orderInfo}" />
{:else}
	<div class="container py-16">
		<h1 class="text-4xl font-bold">403 - Forbidden</h1>
	</div>
{/if}
