<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import {
  CategoryScale,
  Chart as ChartJS,
  Filler,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
  type ChartData,
  type ChartOptions,
} from 'chart.js'
import { Line } from 'vue-chartjs'
import { toast } from 'vue-sonner'
import { ApiError } from '@/api/client'
import { fetchStats, getStatsHistory, type StatsSnapshot } from '@/api/stats'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Filler,
)

const POLL_INTERVAL_MS = 2000
const HISTORY_LENGTH = 60

type TimeWindow = 'live' | '5m' | '1h' | '30d'

const TIME_WINDOW_OPTIONS: { value: TimeWindow; label: string }[] = [
  { value: 'live', label: 'Live' },
  { value: '5m', label: 'Last 5 Minutes' },
  { value: '1h', label: 'Last 1 Hour' },
  { value: '30d', label: 'Last 30 Days' },
]

function formatLiveTimestamp(date: Date = new Date()): string {
  return date.toLocaleTimeString(navigator.language, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

function formatHistoryTimestamp(iso: string, window: TimeWindow): string {
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) {
    return iso
  }

  if (window === '30d') {
    const day = date.getDate().toString().padStart(2, '0')
    const month = (date.getMonth() + 1).toString().padStart(2, '0')
    return `${day}.${month}.`
  }

  if (window === '1h') {
    return date.toLocaleTimeString(navigator.language, {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })
  }

  return formatLiveTimestamp(date)
}

function bucketSeconds(granularity: string): number {
  if (granularity === 'day') {
    return 86400
  }
  return 60
}

function seedTimestampLabels(): string[] {
  const now = Date.now()
  const stepMs = POLL_INTERVAL_MS
  return Array.from({ length: HISTORY_LENGTH }, (_, index) => {
    const secondsAgo = (HISTORY_LENGTH - 1 - index) * (stepMs / 1000)
    return formatLiveTimestamp(new Date(now - secondsAgo * 1000))
  })
}

function appendRollingLabel(current: string[], label: string): string[] {
  const next = [...current, label]
  if (next.length > HISTORY_LENGTH) {
    return next.slice(next.length - HISTORY_LENGTH)
  }
  return next
}

const stats = ref<StatsSnapshot | null>(null)
const loading = ref(true)

const timeWindow = ref<TimeWindow>('live')
const isLiveMode = computed(() => timeWindow.value === 'live')

const qpsHistory = ref<number[]>(Array.from({ length: HISTORY_LENGTH }, () => 0))
const cacheHitsHistory = ref<number[]>(Array.from({ length: HISTORY_LENGTH }, () => 0))
const timestampHistory = ref<string[]>(seedTimestampLabels())

const qpsChartData = ref<ChartData<'line'>>({ labels: [], datasets: [] })
const cacheHitsChartData = ref<ChartData<'line'>>({ labels: [], datasets: [] })

const themeRevision = ref(0)

let pollTimer: ReturnType<typeof setInterval> | null = null
let themeObserver: MutationObserver | null = null
let previousTotalQueries: number | null = null
let previousCacheHits: number | null = null

const totalQueries = computed(() => {
  if (!stats.value) {
    return 0
  }
  return stats.value.udp_queries + stats.value.tcp_queries
})

const localQueries = computed(() => stats.value?.local_queries ?? 0)

const upstreamQueries = computed(() => stats.value?.upstream_queries ?? 0)

const localUpstreamTotal = computed(() => localQueries.value + upstreamQueries.value)

const localTrafficPercent = computed(() => {
  if (localUpstreamTotal.value === 0) {
    return 0
  }
  return (localQueries.value / localUpstreamTotal.value) * 100
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

const liveQps = computed(() => {
  const history = qpsHistory.value
  return history.length > 0 ? history[history.length - 1] : 0
})

const liveCacheHitRate = computed(() => {
  const history = cacheHitsHistory.value
  return history.length > 0 ? history[history.length - 1] : 0
})

const telemetryDescription = computed(() => {
  if (isLiveMode.value) {
    return 'Live telemetry from the DNS server. Metrics refresh every 2 seconds.'
  }
  const label =
    TIME_WINDOW_OPTIONS.find((option) => option.value === timeWindow.value)?.label ?? 'Historical'
  return `Historical telemetry (${label}) loaded from SQLite rollup storage.`
})

const chartWindowDescription = computed(() => {
  if (isLiveMode.value) {
    return 'Rolling 2-minute window'
  }
  const label =
    TIME_WINDOW_OPTIONS.find((option) => option.value === timeWindow.value)?.label ?? 'Historical'
  return `${label} · aggregated rates`
})

function readCssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim()
}

function chartThemeColors() {
  void themeRevision.value
  return {
    primary: readCssVar('--chart-1') || readCssVar('--primary'),
    secondary: readCssVar('--chart-2') || readCssVar('--primary'),
    muted: readCssVar('--muted-foreground'),
    border: readCssVar('--border'),
  }
}

function withAlpha(color: string, alpha: number): string {
  if (!color) {
    return `oklch(0.5 0 0 / ${alpha})`
  }
  if (color.includes('/')) {
    return color
  }
  return `color-mix(in oklch, ${color} ${Math.round(alpha * 100)}%, transparent)`
}

function buildLineChartData(
  label: string,
  labels: string[],
  values: number[],
  strokeColor: string,
): ChartData<'line'> {
  return {
    labels: [...labels],
    datasets: [
      {
        label,
        data: [...values],
        borderColor: strokeColor,
        backgroundColor: withAlpha(strokeColor, 0.08),
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 3,
        tension: 0.4,
        fill: true,
      },
    ],
  }
}

function refreshChartData(): void {
  const colors = chartThemeColors()
  qpsChartData.value = buildLineChartData(
    'Queries per second',
    timestampHistory.value,
    qpsHistory.value,
    colors.primary,
  )
  cacheHitsChartData.value = buildLineChartData(
    'Cache hits per second',
    timestampHistory.value,
    cacheHitsHistory.value,
    colors.secondary,
  )
}

function buildLineChartOptions(yAxisLabel: string): ChartOptions<'line'> {
  const colors = chartThemeColors()

  return {
    responsive: true,
    maintainAspectRatio: false,
    animation: {
      duration: 0,
    },
    transitions: {
      active: {
        animation: {
          duration: 0,
        },
      },
    },
    interaction: {
      intersect: false,
      mode: 'index',
    },
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        backgroundColor: colors.border,
        titleColor: colors.muted,
        bodyColor: colors.primary,
        borderColor: colors.border,
        borderWidth: 1,
        padding: 10,
        displayColors: false,
        callbacks: {
          title(context) {
            const label = context[0]?.label
            return typeof label === 'string' ? label : ''
          },
          label(context) {
            const value = context.parsed.y
            if (value === null || value === undefined) {
              return ''
            }
            return `${value.toFixed(2)}${yAxisLabel}`
          },
        },
      },
    },
    scales: {
      x: {
        display: true,
        grid: {
          display: false,
        },
        border: {
          display: false,
        },
        ticks: {
          color: colors.muted,
          maxTicksLimit: 6,
          maxRotation: 0,
        },
      },
      y: {
        display: true,
        beginAtZero: true,
        grid: {
          display: false,
        },
        border: {
          display: false,
        },
        ticks: {
          color: colors.muted,
          maxTicksLimit: 4,
          precision: 0,
        },
      },
    },
  }
}

const qpsChartOptions = computed(() => buildLineChartOptions('/s'))
const cacheHitsChartOptions = computed(() => buildLineChartOptions('/s'))

function formatNumber(value: number): string {
  return value.toLocaleString()
}

function formatRate(value: number): string {
  if (value >= 100) {
    return value.toFixed(0)
  }
  if (value >= 10) {
    return value.toFixed(1)
  }
  return value.toFixed(2)
}

function formatPercent(value: number | null): string {
  if (value === null) {
    return '—'
  }
  return `${value.toFixed(1)}%`
}

function appendRolling(current: number[], value: number): number[] {
  const next = [...current, value]
  if (next.length > HISTORY_LENGTH) {
    return next.slice(next.length - HISTORY_LENGTH)
  }
  return next
}

function resetLiveHistory(): void {
  previousTotalQueries = null
  previousCacheHits = null
  qpsHistory.value = Array.from({ length: HISTORY_LENGTH }, () => 0)
  cacheHitsHistory.value = Array.from({ length: HISTORY_LENGTH }, () => 0)
  timestampHistory.value = seedTimestampLabels()
  refreshChartData()
}

function recordMetricDeltas(snapshot: StatsSnapshot): void {
  if (!isLiveMode.value) {
    return
  }

  const currentQueries = snapshot.udp_queries + snapshot.tcp_queries
  const currentHits = snapshot.cache_hits
  const intervalSeconds = POLL_INTERVAL_MS / 1000

  if (previousTotalQueries !== null && previousCacheHits !== null) {
    const queryDelta = Math.max(0, currentQueries - previousTotalQueries)
    const hitsDelta = Math.max(0, currentHits - previousCacheHits)

    const timestamp = formatLiveTimestamp()

    qpsHistory.value = appendRolling(qpsHistory.value, queryDelta / intervalSeconds)
    cacheHitsHistory.value = appendRolling(cacheHitsHistory.value, hitsDelta / intervalSeconds)
    timestampHistory.value = appendRollingLabel(timestampHistory.value, timestamp)
    refreshChartData()
  }

  previousTotalQueries = currentQueries
  previousCacheHits = currentHits
}

async function loadHistory(): Promise<void> {
  if (isLiveMode.value) {
    return
  }

  try {
    const history = await getStatsHistory(timeWindow.value)
    const window = timeWindow.value
    const intervalSeconds = bucketSeconds(history.granularity)

    const labels = history.points.map((point) =>
      formatHistoryTimestamp(point.timestamp, window),
    )
    const qpsValues = history.points.map((point) => point.queries / intervalSeconds)
    const cacheValues = history.points.map((point) => point.cache_hits / intervalSeconds)

    timestampHistory.value = labels
    qpsHistory.value = qpsValues
    cacheHitsHistory.value = cacheValues
    refreshChartData()
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return
    }
    toast.error(err instanceof Error ? err.message : 'Failed to load historical telemetry')
  }
}

async function loadStats(): Promise<void> {
  try {
    const snapshot = await fetchStats()
    recordMetricDeltas(snapshot)
    stats.value = snapshot
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return
    }
    toast.error(err instanceof Error ? err.message : 'Failed to load telemetry')
  } finally {
    loading.value = false
  }
}

function stopPolling(): void {
  if (pollTimer !== null) {
    clearInterval(pollTimer)
    pollTimer = null
  }
}

function startPolling(): void {
  stopPolling()
  pollTimer = setInterval(() => {
    void loadStats()
  }, POLL_INTERVAL_MS)
}

function selectTimeWindow(window: TimeWindow): void {
  if (timeWindow.value === window) {
    return
  }

  timeWindow.value = window

  if (isLiveMode.value) {
    resetLiveHistory()
    void loadStats()
    startPolling()
    return
  }

  stopPolling()
  void Promise.all([loadStats(), loadHistory()])
}

function startThemeObserver(): void {
  themeObserver = new MutationObserver(() => {
    themeRevision.value += 1
  })
  themeObserver.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['class', 'data-theme'],
  })
}

watch(themeRevision, () => {
  refreshChartData()
})

onMounted(() => {
  refreshChartData()
  startThemeObserver()
  void loadStats()
  startPolling()
})

onUnmounted(() => {
  stopPolling()
  if (themeObserver !== null) {
    themeObserver.disconnect()
    themeObserver = null
  }
})
</script>

<template>
  <div class="mx-auto flex max-w-6xl flex-col gap-8">
    <header class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Dashboard</h1>
      <p class="text-sm text-muted-foreground">
        {{ telemetryDescription }}
      </p>
    </header>

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
          <p
            v-if="stats && localUpstreamTotal > 0"
            class="mt-1 text-xs text-muted-foreground tabular-nums"
          >
            {{ formatNumber(localQueries) }} Local · {{ formatNumber(upstreamQueries) }} Upstream
          </p>
          <div
            v-if="stats && localUpstreamTotal > 0"
            class="mt-3 flex h-1.5 w-full overflow-hidden rounded-full bg-muted"
            role="presentation"
            aria-hidden="true"
          >
            <div
              class="h-full bg-primary transition-[width] duration-300"
              :style="{ width: `${localTrafficPercent}%` }"
            />
            <div
              class="h-full bg-muted-foreground/35 transition-[width] duration-300"
              :style="{ width: `${100 - localTrafficPercent}%` }"
            />
          </div>
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

    <section class="space-y-4">
      <div class="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div class="space-y-1">
          <p class="text-sm font-medium text-foreground">Time Window</p>
          <p class="text-xs text-muted-foreground">
            {{
              isLiveMode
                ? 'Live mode polls every 2 seconds.'
                : 'Historical windows fetch once and pause auto-refresh.'
            }}
          </p>
        </div>

        <div
          class="inline-flex self-start rounded-lg border border-border bg-muted/40 p-0.5"
          role="group"
          aria-label="Time window"
        >
          <button
            v-for="option in TIME_WINDOW_OPTIONS"
            :key="option.value"
            type="button"
            class="rounded-md px-3 py-1.5 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            :class="
              timeWindow === option.value
                ? 'bg-background text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            "
            :aria-pressed="timeWindow === option.value"
            @click="selectTimeWindow(option.value)"
          >
            {{ option.label }}
            <span
              v-if="option.value === 'live'"
              class="sr-only"
            >
              (default)
            </span>
          </button>
        </div>
      </div>

      <div class="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Live Queries (QPS)</CardTitle>
            <CardDescription>
              {{ chartWindowDescription }} · current
              <span class="font-medium text-foreground tabular-nums">
                {{ formatRate(liveQps) }} /s
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div class="h-52 w-full">
              <Line
                :data="qpsChartData"
                :options="qpsChartOptions"
                update-mode="none"
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Cache Hits</CardTitle>
            <CardDescription>
              {{ chartWindowDescription }} · current
              <span class="font-medium text-foreground tabular-nums">
                {{ formatRate(liveCacheHitRate) }} /s
              </span>
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div class="h-52 w-full">
              <Line
                :data="cacheHitsChartData"
                :options="cacheHitsChartOptions"
                update-mode="none"
              />
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  </div>
</template>
