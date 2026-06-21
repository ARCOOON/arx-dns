<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { notify } from '@/composables/useNotifications'
import { setToken } from '@/api/client'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

const router = useRouter()
const token = ref(localStorage.getItem('arx_token') ?? '')

function onSubmit(): void {
  const trimmed = token.value.trim()
  if (!trimmed) {
    notify('Enter a valid API bearer token.', 'error')
    return
  }

  setToken(trimmed)
  const redirect = typeof router.currentRoute.value.query.redirect === 'string'
    ? router.currentRoute.value.query.redirect
    : '/'
  void router.push(redirect)
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background px-6">
    <Card class="w-full max-w-md">
      <CardHeader>
        <CardTitle class="text-xl">Sign in</CardTitle>
        <CardDescription>
          Enter the management API bearer token configured in
          <code class="text-foreground">config.toml</code>.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form class="space-y-4" @submit.prevent="onSubmit">
          <div class="space-y-2">
            <label class="text-sm font-medium" for="token">Bearer token</label>
            <input
              id="token"
              v-model="token"
              type="password"
              autocomplete="off"
              class="flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-none outline-none focus-visible:ring-1 focus-visible:ring-ring"
              placeholder="dev-token-change-me"
            />
          </div>

          <Button type="submit" class="w-full">
            Continue
          </Button>
        </form>
      </CardContent>
    </Card>
  </div>
</template>
