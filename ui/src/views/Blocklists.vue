<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { Loader2, Plus, RefreshCw, ShieldBan, Trash2 } from 'lucide-vue-next'
import { ApiError } from '@/api/client'
import {
  createBlocklistSource,
  deleteBlocklistSource,
  fetchBlocklistSources,
  fetchFirewallStatus,
  syncBlocklists,
  type BlocklistSource,
} from '@/api/firewall'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
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

const STATUS_POLL_MS = 2000
const SYNC_POLL_MAX_MS = 120000

const sources = ref<BlocklistSource[]>([])
const blockedCount = ref<number | null>(null)
const loadingSources = ref(true)
const loadingStatus = ref(true)
const syncing = ref(false)
const error = ref<string | null>(null)
const addDialogOpen = ref(false)
const newSourceURL = ref('')
const creating = ref(false)
const deletingId = ref<number | null>(null)

let statusPollTimer: ReturnType<typeof setInterval> | null = null
let syncPollTimer: ReturnType<typeof setInterval> | null = null
let syncStopTimer: ReturnType<typeof setTimeout> | null = null

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

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

function clearSyncPolling(): void {
  if (syncPollTimer !== null) {
    clearInterval(syncPollTimer)
    syncPollTimer = null
  }
  if (syncStopTimer !== null) {
    clearTimeout(syncStopTimer)
    syncStopTimer = null
  }
}

function stopSyncing(): void {
  clearSyncPolling()
  syncing.value = false
}

async function loadStatus(): Promise<void> {
  loadingStatus.value = blockedCount.value === null
  try {
    const response = await fetchFirewallStatus()
    blockedCount.value = response.blocked_domains_count
  } catch (err) {
    error.value = parseApiError(err, 'Failed to load firewall status')
  } finally {
    loadingStatus.value = false
  }
}

async function loadSources(): Promise<void> {
  loadingSources.value = true
  try {
    const response = await fetchBlocklistSources()
    sources.value = response.sources
  } catch (err) {
    error.value = parseApiError(err, 'Failed to load blocklist sources')
  } finally {
    loadingSources.value = false
  }
}

function startStatusPolling(): void {
  if (statusPollTimer !== null) {
    return
  }
  statusPollTimer = setInterval(() => {
    void loadStatus()
  }, STATUS_POLL_MS)
}

function openAddDialog(): void {
  newSourceURL.value = ''
  addDialogOpen.value = true
}

async function submitSource(): Promise<void> {
  const url = newSourceURL.value.trim()
  if (!url) {
    return
  }

  creating.value = true
  error.value = null
  try {
    await createBlocklistSource(url)
    addDialogOpen.value = false
    newSourceURL.value = ''
    await loadSources()
  } catch (err) {
    error.value = parseApiError(err, 'Failed to add blocklist source')
  } finally {
    creating.value = false
  }
}

async function removeSource(source: BlocklistSource): Promise<void> {
  deletingId.value = source.id
  error.value = null
  try {
    await deleteBlocklistSource(source.id)
    await loadSources()
  } catch (err) {
    error.value = parseApiError(err, 'Failed to delete blocklist source')
  } finally {
    deletingId.value = null
  }
}

async function triggerSync(): Promise<void> {
  if (syncing.value) {
    return
  }

  syncing.value = true
  error.value = null
  clearSyncPolling()

  try {
    await syncBlocklists()
    syncPollTimer = setInterval(() => {
      void Promise.all([loadStatus(), loadSources()])
    }, STATUS_POLL_MS)
    syncStopTimer = setTimeout(() => {
      stopSyncing()
      void Promise.all([loadStatus(), loadSources()])
    }, SYNC_POLL_MAX_MS)
  } catch (err) {
    stopSyncing()
    error.value = parseApiError(err, 'Failed to start blocklist sync')
  }
}

onMounted(async () => {
  await Promise.all([loadStatus(), loadSources()])
  startStatusPolling()
})

onUnmounted(() => {
  if (statusPollTimer !== null) {
    clearInterval(statusPollTimer)
    statusPollTimer = null
  }
  clearSyncPolling()
  stopSyncing()
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="font-heading text-2xl font-semibold tracking-tight">Blocklists</h1>
        <p class="text-sm text-muted-foreground">
          Configure remote ad and malware feeds, then sync them into the local firewall.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <Button variant="outline" :disabled="syncing" @click="triggerSync">
          <Loader2 v-if="syncing" class="size-4 animate-spin" />
          <RefreshCw v-else class="size-4" />
          Update Gravity / Sync
        </Button>
        <Button @click="openAddDialog">
          <Plus class="size-4" />
          Add List
        </Button>
      </div>
    </div>

    <p
      v-if="error"
      class="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive"
    >
      {{ error }}
    </p>

    <Card>
      <CardHeader>
        <CardTitle class="flex items-center gap-2 text-base">
          <ShieldBan class="size-4 text-muted-foreground" />
          Blocked Domains
        </CardTitle>
        <CardDescription>Unique domains loaded from all blocklist files</CardDescription>
      </CardHeader>
      <CardContent>
        <p class="font-heading text-3xl font-semibold tabular-nums">
          <template v-if="loadingStatus && blockedCount === null">—</template>
          <template v-else>{{ formatNumber(blockedCount ?? 0) }}</template>
        </p>
        <p v-if="syncing" class="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 class="size-3 animate-spin" />
          Syncing remote feeds...
        </p>
      </CardContent>
    </Card>

    <Card>
      <CardHeader class="pb-3">
        <CardTitle class="text-base">Remote Sources</CardTitle>
        <CardDescription>
          HTTP(S) feeds downloaded into <code class="text-xs">./blocklists/</code> on sync
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div
          v-if="loadingSources"
          class="flex items-center gap-2 py-10 text-sm text-muted-foreground"
        >
          <Loader2 class="size-4 animate-spin" />
          Loading sources...
        </div>
        <div
          v-else-if="sources.length === 0"
          class="py-10 text-center text-sm text-muted-foreground"
        >
          No remote blocklist sources configured. Add a feed URL to get started.
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full min-w-[640px] text-left text-sm">
            <thead>
              <tr class="border-b border-border text-muted-foreground">
                <th class="px-3 py-2 font-medium">ID</th>
                <th class="px-3 py-2 font-medium">URL</th>
                <th class="px-3 py-2 font-medium">Status</th>
                <th class="px-3 py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="source in sources"
                :key="source.id"
                class="border-b border-border/70 last:border-0"
              >
                <td class="px-3 py-2 tabular-nums">{{ source.id }}</td>
                <td class="max-w-xl truncate px-3 py-2 font-mono text-xs" :title="source.url">
                  {{ source.url }}
                </td>
                <td class="px-3 py-2">
                  <span
                    :class="source.enabled ? 'text-foreground' : 'text-muted-foreground'"
                  >
                    {{ source.enabled ? 'Enabled' : 'Disabled' }}
                  </span>
                </td>
                <td class="px-3 py-2 text-right">
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    :disabled="deletingId === source.id"
                    :aria-label="`Delete source ${source.id}`"
                    @click="removeSource(source)"
                  >
                    <Loader2
                      v-if="deletingId === source.id"
                      class="size-4 animate-spin"
                    />
                    <Trash2 v-else class="size-4 text-destructive" />
                  </Button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>

    <Dialog v-model:open="addDialogOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Blocklist Source</DialogTitle>
          <DialogDescription>
            Enter the HTTP or HTTPS URL of a HOSTS-formatted or plain domain list feed.
          </DialogDescription>
        </DialogHeader>

        <form class="space-y-4" @submit.prevent="submitSource">
          <div class="space-y-2">
            <Label for="source-url">Feed URL</Label>
            <Input
              id="source-url"
              v-model="newSourceURL"
              type="url"
              placeholder="https://example.com/lists/ads.txt"
              required
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="creating"
              @click="addDialogOpen = false"
            >
              Cancel
            </Button>
            <Button type="submit" :disabled="creating">
              <Loader2 v-if="creating" class="size-4 animate-spin" />
              Add Source
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </div>
</template>
