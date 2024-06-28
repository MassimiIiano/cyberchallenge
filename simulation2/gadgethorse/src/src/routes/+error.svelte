<script lang="ts">
	import { page } from '$app/stores'
</script>

<div class="container py-16">
	<h1 class="text-4xl font-bold">{$page.status} - {$page.error?.message}</h1>
</div>
