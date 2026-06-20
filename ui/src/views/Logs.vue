<script setup lang="ts">
import { nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { Loader2, Settings, Trash2 } from 'lucide-vue-next'
import { ApiError } from '@/api/client'
import {
  fetchLogsConfig,
  fetchLogsHistory,
  openLogsEventSource,
  parseLogLine,
  shouldDisplayLevel,
  updateLogsConfig,
  type LogLevelFilter,
  type LogsConfig,
  type ParsedLogLine,
} from '@/api/logs'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'

const lines = ref<ParsedLogLine[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const levelFilter = ref<LogLevelFilter>('ALL')
const autoScroll = ref(true)
const settingsOpen = ref(false)
const savingSettings = ref(false)
const terminalRef = ref<HTMLElement | null>(null)

const settings = ref<LogsConfig>({
  level: 'INFO',
  rotation: {
    file_path: './logs/arx-dns.log',
    max_size_mb: 50,
    max_backups: 3,
    max_age_days: 28,
  },
})

let eventSource: EventSource | null = null

function parseApiError(err: unknown, fallback: string): string {
  if (!(err instanceof ApiError)) {
    return fallback
  }
  try {
    const parsed = JSON.parse(err.message) as { error?: string }
    if (parsed.error) {
      return parsed.error
    }
  } catch {
    // Use raw message when the body is not JSON.
  }
  return err.message || fallback
}

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

async function loadSettings(): Promise<void> {
  settings.value = await fetchLogsConfig()
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

async function openSettings(): Promise<void> {
  error.value = null
  try {
    await loadSettings()
    settingsOpen.value = true
  } catch (err) {
    error.value = parseApiError(err, 'Failed to load log settings')
  }
}

async function saveSettings(): Promise<void> {
  savingSettings.value = true
  error.value = null
  try {
    settings.value = await updateLogsConfig(settings.value)
    settingsOpen.value = false
  } catch (err) {
    error.value = parseApiError(err, 'Failed to save log settings')
  } finally {
    savingSettings.value = false
  }
}

onMounted(async () => {
  loading.value = true
  error.value = null
  try {
    await loadHistory()
    connectStream()
  } catch (err) {
    error.value = parseApiError(err, 'Failed to load logs')
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
        <Button variant="outline" size="sm" @click="openSettings">
          <Settings class="mr-2 size-4" aria-hidden="true" />
          Settings
        </Button>
      </div>
    </div>

    <p v-if="error"
      class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      {{ error }}
    </p>

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

    <Dialog v-model:open="settingsOpen">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>Log Settings</DialogTitle>
          <DialogDescription>
            Update runtime log level and file rotation parameters. Changes persist in main.db.
          </DialogDescription>
        </DialogHeader>

        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="log-level">Log level</Label>
            <Select :model-value="settings.level" @update:model-value="(value) => { settings.level = String(value) }">
              <SelectTrigger id="log-level">
                <SelectValue placeholder="Select level" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="DEBUG">DEBUG</SelectItem>
                <SelectItem value="INFO">INFO</SelectItem>
                <SelectItem value="WARN">WARN</SelectItem>
                <SelectItem value="ERROR">ERROR</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div class="grid gap-2">
            <Label for="log-file">Log file path</Label>
            <Input id="log-file" v-model="settings.rotation.file_path" />
          </div>

          <div class="grid grid-cols-3 gap-3">
            <div class="grid gap-2">
              <Label for="max-size">Max size (MB)</Label>
              <Input id="max-size" v-model.number="settings.rotation.max_size_mb" type="number" min="1" />
            </div>
            <div class="grid gap-2">
              <Label for="max-backups">Max backups</Label>
              <Input id="max-backups" v-model.number="settings.rotation.max_backups" type="number" min="0" />
            </div>
            <div class="grid gap-2">
              <Label for="max-age">Max age (days)</Label>
              <Input id="max-age" v-model.number="settings.rotation.max_age_days" type="number" min="0" />
            </div>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" @click="settingsOpen = false">Cancel</Button>
          <Button :disabled="savingSettings" @click="saveSettings">
            <Loader2 v-if="savingSettings" class="mr-2 size-4 animate-spin" aria-hidden="true" />
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
