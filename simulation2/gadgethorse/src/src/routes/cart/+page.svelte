<script lang="ts">
	import LoadingForm from '$lib/LoadingForm.svelte'
	import OrderViewer from '$lib/OrderViewer.svelte'
	import type { ActionData, PageData } from './$types'

	export let data: PageData
	export let form: ActionData
</script>

<OrderViewer items="{data.cart}" isCart="{true}" />

{#if data.cart.length > 0}
	{#if data.user}
		<div class="flex-grow bg-off pb-16 pt-1">
			<div class="container">
				<h1 class="mt-12 text-3xl font-bold">Shipping information</h1>

				<LoadingForm class="relative mt-4 grid grid-cols-2 gap-12" action="/cart/?/buy">
					<div>
						<div class="mt-4">
							<label class="mb-2 block w-full font-semibold" for="">Name</label>
							<input
								class="z-10 m-0 w-full rounded-md border border-neutral-400 px-4 py-2 focus:border-primary focus:ring-primary"
								id="name"
								name="name"
								type="text"
								value="{form?.name ?? ''}" />
						</div>
						<div class="mt-4">
							<label class="mb-2 block w-full font-semibold" for="">Surname</label>
							<input
								class="z-10 m-0 w-full rounded-md border border-neutral-400 px-4 py-2 focus:border-primary focus:ring-primary"
								id="surname"
								name="surname"
								type="text"
								value="{form?.surname ?? ''}" />
						</div>
						<div class="mt-4">
							<label class="mb-2 block w-full font-semibold" for="">Address</label>
							<input
								class="z-10 m-0 w-full rounded-md border border-neutral-400 px-4 py-2 focus:border-primary focus:ring-primary"
								id="address"
								name="address"
								type="text"
								value="{form?.address ?? ''}" />
						</div>
					</div>
					<div>
						<div class="mt-4">
							<label class="mb-2 block w-full font-semibold" for="">City</label>
							<input
								class="z-10 m-0 w-full rounded-md border border-neutral-400 px-4 py-2 focus:border-primary focus:ring-primary"
								id="city"
								name="city"
								type="text"
								value="{form?.city ?? ''}" />
						</div>
						<div class="mt-4">
							<label class="mb-2 block w-full font-semibold" for="">Country</label>
							<input
								class="z-10 m-0 w-full rounded-md border border-neutral-400 px-4 py-2 focus:border-primary focus:ring-primary"
								id="country"
								name="country"
								type="text"
								value="{form?.country ?? ''}" />
						</div>
						<div class="mt-[34px]">
							<div class="text-center">
								<button
									class="w-full rounded-md bg-salmon px-10 py-4 font-semibold text-white hover:bg-[#F56B56]">
									Place order
								</button>
							</div>
						</div>
					</div>
				</LoadingForm>
			</div>
		</div>
	{:else}
		<div class="pb-16 pt-1">
			<div class="container text-center">
				<a
					href="/login"
					class="w-full rounded-md bg-salmon px-10 py-4 font-semibold text-white hover:bg-[#F56B56]">
					Login to place your order
				</a>
			</div>
		</div>
	{/if}
{/if}
