<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { ApiError } from '@/api/client'
import { fetchStats, type StatsSnapshot } from '@/api/stats'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

const POLL_INTERVAL_MS = 2000

const stats = ref<StatsSnapshot | null>(null)
const loading = ref(true)
const error = ref<string | null>(null)

let pollTimer: ReturnType<typeof setInterval> | null = null

const totalQueries = computed(() => {
  if (!stats.value) {
    return 0
  }
  return stats.value.udp_queries + stats.value.tcp_queries
})

const cacheHitRatio = computed(() => {
  if (!stats.value) {
    return null
  }
  const lookups = stats.value.cache_hits + stats.value.cache_misses
  if (lookups === 0) {
    return 0
  }
  return (stats.value.cache_hits / lookups) * 100
})

const droppedBlocked = computed(() => {
  if (!stats.value) {
    return 0
  }
  return stats.value.firewall_blocked + stats.value.rrl_dropped
})

const dnssecFailures = computed(() => stats.value?.dnssec_validations_failed ?? 0)

function formatNumber(value: number): string {
  return value.toLocaleString()
}

function formatPercent(value: number | null): string {
  if (value === null) {
    return '—'
  }
  return `${value.toFixed(1)}%`
}

async function loadStats(): Promise<void> {
  try {
    stats.value = await fetchStats()
    error.value = null
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return
    }
    error.value = err instanceof Error ? err.message : 'Failed to load telemetry'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void loadStats()
  pollTimer = setInterval(() => {
    void loadStats()
  }, POLL_INTERVAL_MS)
})

onUnmounted(() => {
  if (pollTimer !== null) {
    clearInterval(pollTimer)
    pollTimer = null
  }
})
</script>

<template>
  <div class="mx-auto flex max-w-6xl flex-col gap-8">
    <header class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Dashboard</h1>
      <p class="text-sm text-muted-foreground">
        Live telemetry from the DNS server. Metrics refresh every 2 seconds.
      </p>
    </header>

    <p
      v-if="error"
      class="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive"
      role="alert"
    >
      {{ error }}
    </p>

    <div class="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <Card>
        <CardHeader>
          <CardTitle>Total Queries</CardTitle>
          <CardDescription>UDP and TCP combined</CardDescription>
        </CardHeader>
        <CardContent>
          <p class="font-heading text-3xl font-semibold tabular-nums">
            {{ loading && !stats ? '—' : formatNumber(totalQueries) }}
          </p>
          <p
            v-if="stats"
            class="mt-2 text-xs text-muted-foreground tabular-nums"
          >
            UDP {{ formatNumber(stats.udp_queries) }} · TCP
            {{ formatNumber(stats.tcp_queries) }}
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Cache Hit Ratio</CardTitle>
          <CardDescription>Forwarded query cache efficiency</CardDescription>
        </CardHeader>
        <CardContent>
          <p class="font-heading text-3xl font-semibold tabular-nums">
            {{ loading && !stats ? '—' : formatPercent(cacheHitRatio) }}
          </p>
          <p
            v-if="stats"
            class="mt-2 text-xs text-muted-foreground tabular-nums"
          >
            {{ formatNumber(stats.cache_hits) }} hits ·
            {{ formatNumber(stats.cache_misses) }} misses
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Dropped / Blocked</CardTitle>
          <CardDescription>Firewall and rate limiting</CardDescription>
        </CardHeader>
        <CardContent>
          <p class="font-heading text-3xl font-semibold tabular-nums">
            {{ loading && !stats ? '—' : formatNumber(droppedBlocked) }}
          </p>
          <p
            v-if="stats"
            class="mt-2 text-xs text-muted-foreground tabular-nums"
          >
            {{ formatNumber(stats.firewall_blocked) }} blocked ·
            {{ formatNumber(stats.rrl_dropped) }} RRL dropped
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Security</CardTitle>
          <CardDescription>DNSSEC validation failures</CardDescription>
        </CardHeader>
        <CardContent>
          <p class="font-heading text-3xl font-semibold tabular-nums">
            {{ loading && !stats ? '—' : formatNumber(dnssecFailures) }}
          </p>
          <p
            v-if="stats"
            class="mt-2 text-xs text-muted-foreground tabular-nums"
          >
            {{ formatNumber(stats.dnssec_validations_passed) }} passed
          </p>
        </CardContent>
      </Card>
    </div>
  </div>
</template>
