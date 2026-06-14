<script setup lang="ts">
import { Button } from '@/components/ui/button'
</script>

<template>
  <main class="mx-auto flex min-h-screen max-w-3xl flex-col gap-8 px-6 py-16">
    <header class="space-y-2">
      <p class="text-sm font-medium text-muted-foreground">ARX DNS</p>
      <h1 class="text-3xl font-semibold tracking-tight">Management Console</h1>
      <p class="text-muted-foreground">
        Web interface scaffold for zone management, telemetry, and operational controls.
      </p>
    </header>

    <section class="rounded-lg border bg-card p-6 text-card-foreground shadow-sm">
      <h2 class="text-lg font-semibold">Getting started</h2>
      <p class="mt-2 text-sm text-muted-foreground">
        Configure your API bearer token and connect this UI to the management API listener.
      </p>
      <div class="mt-4 flex gap-3">
        <Button>View zones</Button>
        <Button variant="outline">Open API docs</Button>
      </div>
    </section>
  </main>
</template>
