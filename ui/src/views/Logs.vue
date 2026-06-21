<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { Loader2, Settings, Trash2 } from 'lucide-vue-next'
import { notify } from '@/composables/useNotifications'
import {
  fetchLogsHistory,
  openLogsEventSource,
  parseLogLine,
  shouldDisplayLevel,
  type LogLevelFilter,
  type ParsedLogLine,
} from '@/api/logs'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { parseApiError } from '@/utils/apiError'

const lines = ref<ParsedLogLine[]>([])
const loading = ref(true)
const levelFilter = ref<LogLevelFilter>('ALL')
const autoScroll = ref(true)
const terminalRef = ref<HTMLElement | null>(null)

let eventSource: EventSource | null = null

function levelClass(level: string): string {
  switch (level.toUpperCase()) {
    case 'DEBUG':
      return 'text-sky-400'
    case 'WARN':
      return 'text-amber-400'
    case 'ERROR':
      return 'text-rose-400'
    case 'INFO':
      return 'text-cyan-400'
    default:
      return 'text-emerald-400'
  }
}

function appendLine(raw: string): void {
  const parsed = parseLogLine(raw)
  if (!shouldDisplayLevel(parsed.level, levelFilter.value)) {
    return
  }
  lines.value.push(parsed)
  if (autoScroll.value) {
    void scrollToBottom()
  }
}

async function scrollToBottom(): Promise<void> {
  await nextTick()
  const el = terminalRef.value
  if (el) {
    el.scrollTop = el.scrollHeight
  }
}

function clearView(): void {
  lines.value = []
}

function rebuildVisibleLines(allLines: string[]): void {
  lines.value = allLines
    .map(parseLogLine)
    .filter((line) => shouldDisplayLevel(line.level, levelFilter.value))
  if (autoScroll.value) {
    void scrollToBottom()
  }
}

async function loadHistory(): Promise<void> {
  const response = await fetchLogsHistory()
  rebuildVisibleLines(response.lines)
}

function connectStream(): void {
  eventSource?.close()
  eventSource = openLogsEventSource()
  eventSource.onmessage = (event) => {
    if (event.data) {
      appendLine(event.data)
    }
  }
  eventSource.onerror = () => {
    eventSource?.close()
    window.setTimeout(connectStream, 2000)
  }
}

onMounted(async () => {
  loading.value = true
  try {
    await loadHistory()
    connectStream()
  } catch (err) {
    notify(parseApiError(err, 'Failed to load logs'), 'error')
  } finally {
    loading.value = false
  }
})

onBeforeUnmount(() => {
  eventSource?.close()
  eventSource = null
})
</script>

<template>
  <div class="mx-auto flex h-[calc(100vh-4rem)] max-w-6xl flex-col gap-4">
    <div class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Logs</h1>
      <p class="text-sm text-muted-foreground">
        Live structured log stream with rotation settings and history replay.
      </p>
    </div>

    <div class="flex flex-wrap items-center gap-3 rounded-md border border-border bg-card px-4 py-3">
      <div class="flex items-center gap-2">
        <Label for="level-filter" class="text-sm text-muted-foreground">Level</Label>
        <Select :model-value="levelFilter" @update:model-value="
          (value) => {
            levelFilter = value as LogLevelFilter
            void loadHistory()
          }
        ">
          <SelectTrigger id="level-filter" class="w-36">
            <SelectValue placeholder="All levels" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All</SelectItem>
            <SelectItem value="DEBUG">Debug+</SelectItem>
            <SelectItem value="INFO">Info+</SelectItem>
            <SelectItem value="WARN">Warn+</SelectItem>
            <SelectItem value="ERROR">Error</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div class="flex items-center gap-2">
        <Switch id="auto-scroll" v-model:checked="autoScroll" />
        <Label for="auto-scroll" class="text-sm">Auto-scroll</Label>
      </div>

      <div class="ml-auto flex items-center gap-2">
        <Button variant="outline" size="sm" @click="clearView">
          <Trash2 class="mr-2 size-4" aria-hidden="true" />
          Clear
        </Button>
        <Button variant="outline" size="sm" as-child>
          <RouterLink to="/settings?tab=logging">
            <Settings class="mr-2 size-4" aria-hidden="true" />
            Settings
          </RouterLink>
        </Button>
      </div>
    </div>

    <div ref="terminalRef"
      class="min-h-0 flex-1 overflow-auto rounded-md border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs leading-5 text-zinc-100 shadow-inner"
      style="font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;">
      <div v-if="loading" class="flex items-center gap-2 text-zinc-400">
        <Loader2 class="size-4 animate-spin" aria-hidden="true" />
        Loading log history...
      </div>
      <template v-else>
        <div v-for="(line, index) in lines" :key="`${line.time}-${index}`" class="whitespace-pre-wrap break-all">
          <span v-if="line.time" class="text-zinc-500">[{{ line.time }}] </span>
          <span :class="levelClass(line.level)">[{{ line.level }}]</span>
          <span class="text-zinc-300"> {{ line.message }}</span>
          <span v-if="line.attrs" class="text-zinc-500"> ({{ line.attrs }})</span>
        </div>
        <p v-if="lines.length === 0" class="text-zinc-500">
          No log lines match the current filter.
        </p>
      </template>
    </div>
  </div>
</template>
