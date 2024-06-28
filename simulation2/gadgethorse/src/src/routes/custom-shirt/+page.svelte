<script lang="ts">
	import { browser } from '$app/environment'
	import OrderSelector from '$lib/OrderSelector.svelte'
	import { onMount } from 'svelte'
	import type { PageData } from './$types'
	import StorePage from '$lib/StorePage.svelte'

	export let data: PageData

	let svg: SVGElement
	let textElement: SVGTextElement
	let customText = 'GadgetHorse'

	$: width = 100
	$: height = 100

	$: svgSource = ''

	const colors = data.colors
	let shirtColor = data.defaultColor
	const fonts = data.fonts
	let fontFamily = data.defaultFont

	function resizeSvg(input: string) {
		if (!browser || !textElement) return
		textElement.innerHTML = input
		width = textElement.getBBox().width + 10
		if (width < 110) width = 110
		height = textElement.getBBox().height + 10
		svg.setAttribute('viewBox', `0 0 ${width * 2} ${(width * 2 * 548) / 452}`)
		textElement.setAttribute('x', `${width}`)
		textElement.setAttribute('y', `${((width * 2 * 548) / 452) * 0.2 + height / 2}`)

		svgSource = svg.outerHTML
	}

	onMount(() => resizeSvg(customText))

	$: if (customText) resizeSvg(customText)
</script>

<StorePage data="{data}">
	<div class="relative flex aspect-[226/192] items-center" slot="image">
		<svg
			class="{shirtColor}"
			viewBox="0 0 452 548"
			dominant-baseline="middle"
			text-anchor="middle"
			bind:this="{svg}"
			paint-order="stroke"
			stroke-linecap="butt"
			stroke-linejoin="round">
			<image href="/blank_shirt.png" x="0" y="0" class=" mx-auto w-full"></image>
			<text
				style="stroke: white; stroke-width: 3.5; font-weight: bold; fill: #222222; font-family: {fontFamily}"
				x="50"
				y="50"
				bind:this="{textElement}"></text>
		</svg>
	</div>

	<input type="hidden" name="svg" id="svg" bind:value="{svgSource}" />
	<div class="mt-8 font-semibold">Select shirt color:</div>
	<div class="mt-2 flex justify-between gap-8">
		<OrderSelector
			options="{colors}"
			bind:value="{shirtColor}"
			on:change="{() => {
				svgSource = svg.outerHTML
			}}"
			let:value>
			<div class="h-8 w-8 {value} mx-auto block rounded-lg border border-neutral-400"></div>
		</OrderSelector>
	</div>
	<div class="mt-4 font-semibold">Select font:</div>
	<div class="mt-2 flex justify-between gap-8">
		<OrderSelector
			options="{fonts}"
			bind:value="{fontFamily}"
			on:change="{() => resizeSvg(customText)}"
			let:value>
			<div style="font-family: {value}">Aa</div>
		</OrderSelector>
	</div>
	<div class="mt-4 font-semibold">Custom text:</div>
	<div class="mt-2 flex justify-between gap-8">
		<div class="w-full">
			<input
				class="z-10 m-0 w-full rounded-md border border-neutral-400 px-5 py-3 focus:border-primary focus:ring-primary"
				type="text"
				maxlength="32"
				bind:value="{customText}" />
		</div>
	</div>
</StorePage>
