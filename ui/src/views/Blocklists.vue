<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { Loader2, Plus, RefreshCw, ShieldBan, Trash2 } from 'lucide-vue-next'
import { toast } from 'vue-sonner'
import {
  createBlocklistSource,
  createCustomBlocklistDomain,
  deleteBlocklistSource,
  deleteCustomBlocklistDomain,
  fetchBlocklistSources,
  fetchCustomBlocklist,
  fetchFirewallStatus,
  syncBlocklists,
  updateBlocklistSource,
  type BlocklistSource,
  type CustomBlocklistEntry,
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
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { parseApiError } from '@/utils/apiError'

const STATUS_POLL_MS = 2000
const SYNC_POLL_MAX_MS = 120000

const sources = ref<BlocklistSource[]>([])
const customDomains = ref<CustomBlocklistEntry[]>([])
const blockedCount = ref<number | null>(null)
const loadingSources = ref(true)
const loadingCustom = ref(true)
const loadingStatus = ref(true)
const isSyncing = ref(false)
const isSyncPolling = ref(false)
const addSourceDialogOpen = ref(false)
const addCustomDialogOpen = ref(false)
const newSourceURL = ref('')
const newSourceDescription = ref('')
const newCustomDomain = ref('')
const creatingSource = ref(false)
const creatingCustom = ref(false)
const deletingSourceId = ref<number | null>(null)
const deletingCustomId = ref<number | null>(null)
const togglingSourceId = ref<number | null>(null)

let statusPollTimer: ReturnType<typeof setInterval> | null = null
let syncPollTimer: ReturnType<typeof setInterval> | null = null
let syncStopTimer: ReturnType<typeof setTimeout> | null = null

function formatNumber(value: number): string {
  return new Intl.NumberFormat().format(value)
}

function formatDateTime(value?: string): string {
  if (!value) {
    return '—'
  }
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date)
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
  isSyncPolling.value = false
}

function pauseStatusPolling(): void {
  if (statusPollTimer !== null) {
    clearInterval(statusPollTimer)
    statusPollTimer = null
  }
}

function resumeStatusPolling(): void {
  if (isSyncing.value || isSyncPolling.value || statusPollTimer !== null) {
    return
  }
  statusPollTimer = setInterval(() => {
    void loadStatus()
  }, STATUS_POLL_MS)
}

async function loadStatus(): Promise<void> {
  loadingStatus.value = blockedCount.value === null
  try {
    const response = await fetchFirewallStatus()
    blockedCount.value = response.blocked_domains_count
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to load firewall status'))
  } finally {
    loadingStatus.value = false
  }
}

async function loadSources(silent = false): Promise<void> {
  if (!silent) {
    loadingSources.value = true
  }
  try {
    const response = await fetchBlocklistSources()
    sources.value = response.sources
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to load blocklist sources'))
  } finally {
    if (!silent) {
      loadingSources.value = false
    }
  }
}

async function loadCustomDomains(): Promise<void> {
  loadingCustom.value = true
  try {
    const response = await fetchCustomBlocklist()
    customDomains.value = response.domains
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to load custom blocklist domains'))
  } finally {
    loadingCustom.value = false
  }
}

function openAddSourceDialog(): void {
  newSourceURL.value = ''
  newSourceDescription.value = ''
  addSourceDialogOpen.value = true
}

function openAddCustomDialog(): void {
  newCustomDomain.value = ''
  addCustomDialogOpen.value = true
}

async function submitSource(): Promise<void> {
  const url = newSourceURL.value.trim()
  if (!url) {
    return
  }

  creatingSource.value = true
  try {
    await createBlocklistSource(url, newSourceDescription.value.trim() || undefined)
    addSourceDialogOpen.value = false
    newSourceURL.value = ''
    newSourceDescription.value = ''
    await loadSources()
    toast.success('Blocklist source added')
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to add blocklist source'))
  } finally {
    creatingSource.value = false
  }
}

async function submitCustomDomain(): Promise<void> {
  const domain = newCustomDomain.value.trim()
  if (!domain) {
    return
  }

  creatingCustom.value = true
  try {
    await createCustomBlocklistDomain(domain)
    addCustomDialogOpen.value = false
    newCustomDomain.value = ''
    await Promise.all([loadCustomDomains(), loadStatus()])
    toast.success('Custom domain blocked')
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to add custom blocklist domain'))
  } finally {
    creatingCustom.value = false
  }
}

async function removeSource(source: BlocklistSource): Promise<void> {
  deletingSourceId.value = source.id
  try {
    await deleteBlocklistSource(source.id)
    await loadSources()
    toast.success('Blocklist source removed')
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to delete blocklist source'))
  } finally {
    deletingSourceId.value = null
  }
}

async function toggleSourceEnabled(source: BlocklistSource, enabled: boolean): Promise<void> {
  togglingSourceId.value = source.id
  const previous = source.enabled
  source.enabled = enabled
  try {
    const response = await updateBlocklistSource(source.id, { enabled })
    if (response.source) {
      const index = sources.value.findIndex((item) => item.id === source.id)
      if (index >= 0) {
        sources.value[index] = response.source
      }
    }
    await loadStatus()
  } catch (err) {
    source.enabled = previous
    toast.error(parseApiError(err, 'Failed to update blocklist source'))
  } finally {
    togglingSourceId.value = null
  }
}

async function removeCustomDomain(entry: CustomBlocklistEntry): Promise<void> {
  deletingCustomId.value = entry.id
  try {
    await deleteCustomBlocklistDomain(entry.id)
    await Promise.all([loadCustomDomains(), loadStatus()])
    toast.success('Custom domain removed')
  } catch (err) {
    toast.error(parseApiError(err, 'Failed to delete custom blocklist domain'))
  } finally {
    deletingCustomId.value = null
  }
}

async function triggerSync(): Promise<void> {
  if (isSyncing.value) {
    return
  }

  isSyncing.value = true
  pauseStatusPolling()
  clearSyncPolling()

  try {
    await syncBlocklists()
    toast.success('Blocklist sync started')
    isSyncPolling.value = true
    syncPollTimer = setInterval(() => {
      void Promise.all([loadStatus(), loadSources(true)])
    }, STATUS_POLL_MS)
    syncStopTimer = setTimeout(() => {
      clearSyncPolling()
      resumeStatusPolling()
      void Promise.all([loadStatus(), loadSources(true)])
    }, SYNC_POLL_MAX_MS)
  } catch (err) {
    clearSyncPolling()
    resumeStatusPolling()
    toast.error(parseApiError(err, 'Failed to start blocklist sync'))
  } finally {
    isSyncing.value = false
  }
}

onMounted(async () => {
  await Promise.all([loadStatus(), loadSources(), loadCustomDomains()])
  resumeStatusPolling()
})

onUnmounted(() => {
  pauseStatusPolling()
  clearSyncPolling()
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="font-heading text-2xl font-semibold tracking-tight">Blocklists</h1>
        <p class="text-sm text-muted-foreground">
          Configure remote ad and malware feeds, custom rules, then sync into the local firewall.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <Button variant="outline" :disabled="isSyncing" @click="triggerSync">
          <Loader2 v-if="isSyncing" class="size-4 animate-spin" />
          <RefreshCw v-else class="size-4" />
          Update Feeds
        </Button>
        <Button variant="outline" @click="openAddSourceDialog">
          <Plus class="size-4" />
          Add Feed
        </Button>
        <Button @click="openAddCustomDialog">
          <Plus class="size-4" />
          Add Domain
        </Button>
      </div>
    </div>

    <Card>
      <CardHeader>
        <CardTitle class="flex items-center gap-2 text-base">
          <ShieldBan class="size-4 text-muted-foreground" />
          Blocked Domains
        </CardTitle>
        <CardDescription>Unique domains loaded from remote feeds and custom rules</CardDescription>
      </CardHeader>
      <CardContent>
        <p class="font-heading text-3xl font-semibold tabular-nums">
          <template v-if="loadingStatus && blockedCount === null">—</template>
          <template v-else>{{ formatNumber(blockedCount ?? 0) }}</template>
        </p>
        <p v-if="isSyncPolling" class="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
          <Loader2 class="size-3 animate-spin" />
          Syncing remote feeds...
        </p>
      </CardContent>
    </Card>

    <Tabs default-value="feeds" class="w-full">
      <TabsList>
        <TabsTrigger value="feeds">Remote Feeds</TabsTrigger>
        <TabsTrigger value="custom">Custom Rules</TabsTrigger>
      </TabsList>

      <TabsContent value="feeds">
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
              <table class="w-full min-w-[760px] text-left text-sm">
                <thead>
                  <tr class="border-b border-border text-muted-foreground">
                    <th class="px-3 py-2 font-medium">ID</th>
                    <th class="px-3 py-2 font-medium">URL</th>
                    <th class="px-3 py-2 font-medium">Domains</th>
                    <th class="px-3 py-2 font-medium">Last Sync</th>
                    <th class="px-3 py-2 font-medium">Enabled</th>
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
                    <td class="max-w-xl px-3 py-2">
                      <p class="truncate font-mono text-xs" :title="source.url">
                        {{ source.url }}
                      </p>
                      <p
                        v-if="source.description"
                        class="mt-0.5 truncate text-xs text-muted-foreground"
                        :title="source.description"
                      >
                        {{ source.description }}
                      </p>
                    </td>
                    <td class="px-3 py-2 tabular-nums">
                      {{ formatNumber(source.last_count ?? 0) }}
                    </td>
                    <td class="px-3 py-2 text-muted-foreground">
                      {{ formatDateTime(source.last_sync) }}
                    </td>
                    <td class="px-3 py-2">
                      <Switch
                        :checked="source.enabled"
                        :disabled="togglingSourceId === source.id"
                        :aria-label="`Toggle source ${source.id}`"
                        @update:checked="(enabled) => toggleSourceEnabled(source, enabled)"
                      />
                    </td>
                    <td class="px-3 py-2 text-right">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        :disabled="deletingSourceId === source.id"
                        :aria-label="`Delete source ${source.id}`"
                        @click="removeSource(source)"
                      >
                        <Loader2
                          v-if="deletingSourceId === source.id"
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
      </TabsContent>

      <TabsContent value="custom">
        <Card>
          <CardHeader class="pb-3">
            <CardTitle class="text-base">Custom Rules</CardTitle>
            <CardDescription>
              Manually blocked domains applied immediately without a remote sync
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div
              v-if="loadingCustom"
              class="flex items-center gap-2 py-10 text-sm text-muted-foreground"
            >
              <Loader2 class="size-4 animate-spin" />
              Loading custom domains...
            </div>
            <div
              v-else-if="customDomains.length === 0"
              class="py-10 text-center text-sm text-muted-foreground"
            >
              No custom blocklist domains configured. Add a domain to block it immediately.
            </div>
            <div v-else class="overflow-x-auto">
              <table class="w-full min-w-[560px] text-left text-sm">
                <thead>
                  <tr class="border-b border-border text-muted-foreground">
                    <th class="px-3 py-2 font-medium">ID</th>
                    <th class="px-3 py-2 font-medium">Domain</th>
                    <th class="px-3 py-2 font-medium">Created</th>
                    <th class="px-3 py-2 text-right font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="entry in customDomains"
                    :key="entry.id"
                    class="border-b border-border/70 last:border-0"
                  >
                    <td class="px-3 py-2 tabular-nums">{{ entry.id }}</td>
                    <td class="px-3 py-2 font-mono text-xs">{{ entry.domain }}</td>
                    <td class="px-3 py-2 text-muted-foreground">
                      {{ formatDateTime(entry.created_at) }}
                    </td>
                    <td class="px-3 py-2 text-right">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        :disabled="deletingCustomId === entry.id"
                        :aria-label="`Delete custom domain ${entry.domain}`"
                        @click="removeCustomDomain(entry)"
                      >
                        <Loader2
                          v-if="deletingCustomId === entry.id"
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
      </TabsContent>
    </Tabs>

    <Dialog v-model:open="addSourceDialogOpen">
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

          <div class="space-y-2">
            <Label for="source-description">Description (Optional)</Label>
            <Input
              id="source-description"
              v-model="newSourceDescription"
              type="text"
              placeholder="e.g. Primary ad-blocking list"
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="creatingSource"
              @click="addSourceDialogOpen = false"
            >
              Cancel
            </Button>
            <Button type="submit" :disabled="creatingSource">
              <Loader2 v-if="creatingSource" class="size-4 animate-spin" />
              Add Source
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="addCustomDialogOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Custom Domain</DialogTitle>
          <DialogDescription>
            Block a domain immediately. Subdomains of the listed apex are also blocked.
          </DialogDescription>
        </DialogHeader>

        <form class="space-y-4" @submit.prevent="submitCustomDomain">
          <div class="space-y-2">
            <Label for="custom-domain">Domain</Label>
            <Input
              id="custom-domain"
              v-model="newCustomDomain"
              type="text"
              placeholder="bad-site.com"
              required
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="creatingCustom"
              @click="addCustomDialogOpen = false"
            >
              Cancel
            </Button>
            <Button type="submit" :disabled="creatingCustom">
              <Loader2 v-if="creatingCustom" class="size-4 animate-spin" />
              Add Domain
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </div>
</template>
