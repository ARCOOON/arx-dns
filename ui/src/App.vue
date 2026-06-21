<script setup lang="ts">
import { RouterView } from 'vue-router'
import { Toaster } from 'vue-sonner'
import { useToastPosition } from '@/composables/useToastPosition'

const toastPosition = useToastPosition()
</script>

<template>
  <RouterView />
  <Toaster :position="toastPosition" rich-colors close-button />
</template>
