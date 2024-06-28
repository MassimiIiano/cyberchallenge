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

	const fonts = data.fonts
	let fontFamily = data.defaultFont

	function resizeSvg(input: string) {
		if (!browser || !textElement) return
		textElement.innerHTML = input
		width = textElement.getBBox().width + 10
		height = textElement.getBBox().height + 10
		svg.setAttribute('viewBox', `0 0 ${width} ${height}`)
		textElement.setAttribute('x', `${width / 2}`)
		textElement.setAttribute('y', `${height / 2}`)

		svgSource = svg.outerHTML
	}

	onMount(() => resizeSvg(customText))

	$: if (customText) resizeSvg(customText)
</script>

<StorePage data="{data}">
	<div class="flex aspect-[226/192] items-center" slot="image">
		<svg
			viewBox="0 0 100 100"
			dominant-baseline="middle"
			text-anchor="middle"
			bind:this="{svg}"
			paint-order="stroke"
			stroke-linecap="butt"
			stroke-linejoin="round"
			style="filter: drop-shadow(0px 0px 3px #777);">
			<text
				style="stroke: white; stroke-width: 4; font-weight: bold; fill: #222222; font-family: {fontFamily}"
				x="50"
				y="50"
				bind:this="{textElement}"></text>
		</svg>
	</div>

	<input type="hidden" name="svg" id="svg" bind:value="{svgSource}" />
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
