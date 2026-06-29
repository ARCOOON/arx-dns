<script setup lang="ts">
import type { DropdownMenuTriggerProps } from 'radix-vue'
import { DropdownMenuTrigger } from 'radix-vue'

const props = defineProps<DropdownMenuTriggerProps>()
</script>

<template>
  <DropdownMenuTrigger v-bind="props">
    <slot />
  </DropdownMenuTrigger>
</template>
