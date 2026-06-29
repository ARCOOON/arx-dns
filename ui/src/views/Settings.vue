<script setup lang="ts">
import { onMounted, ref, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  FileText,
  Loader2,
  Monitor,
  Pencil,
  Plus,
  Save,
  Server,
  ShieldCheck,
  Trash2,
} from 'lucide-vue-next'
import { notify } from '@/composables/useNotifications'
import {
  cloneAppConfig,
  fetchConfig,
  updateConfig,
  type AppConfig,
} from '@/api/config'
import {
  fetchACLConfig,
  updateACLConfig,
  type ACLConfig,
} from '@/api/client'
import { Alert } from '@/components/ui/alert'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import TokenInput from '@/components/ui/token-input/TokenInput.vue'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  TOAST_POSITION_OPTIONS,
  useToastPosition,
  type ToastPosition,
} from '@/composables/useToastPosition'
import { parseApiError } from '@/utils/apiError'

const TAB_IDS = ['dns', 'security', 'logging', 'ui'] as const
type TabId = (typeof TAB_IDS)[number]

const ACL_KEYWORDS = ['any', 'none', 'localhost'] as const

const EMPTY_ACL: ACLConfig = {
  match_lists: {},
  allow_query: [],
  allow_recursion: [],
  allow_transfer: [],
}

const route = useRoute()
const router = useRouter()

const activeTab = ref<TabId>('dns')
const config = ref<AppConfig | null>(null)
const configLoading = ref(true)
const configSaving = ref(false)
const requiresRestart = ref(false)

const toastPosition = useToastPosition()

const upstreams = ref<string[]>([])

const aclConfig = ref<ACLConfig | null>(null)
const aclLoading = ref(true)
const aclSaving = ref(false)
const matchLists = ref<Record<string, string[]>>({})
const allowQuery = ref<string[]>([])
const allowRecursion = ref<string[]>([])
const allowTransfer = ref<string[]>([])

const matchListDialogOpen = ref(false)
const editingMatchListName = ref<string | null>(null)
const matchListNameInput = ref('')
const matchListValues = ref<string[]>([])
const deletingMatchListName = ref<string | null>(null)

const upstreamDialogOpen = ref(false)
const upstreamInput = ref('')
const deletingUpstreamIndex = ref<number | null>(null)

function isValidTab(value: string): value is TabId {
  return TAB_IDS.includes(value as TabId)
}

function syncTabFromRoute(): void {
  const tab = route.query.tab
  if (typeof tab === 'string' && tab === 'audit') {
    void router.replace({ path: '/audit' })
    return
  }
  if (typeof tab === 'string' && isValidTab(tab)) {
    activeTab.value = tab
  }
}

function applyConfigToForm(cfg: AppConfig): void {
  upstreams.value = [...cfg.recursive.upstreams]
}

function applyACLToForm(cfg: ACLConfig | null | undefined): void {
  const safe = cfg ?? EMPTY_ACL
  matchLists.value = Object.fromEntries(
    Object.entries(safe.match_lists ?? {}).map(([name, values]) => [
      name,
      [...(values ?? [])],
    ]),
  )
  allowQuery.value = [...(safe.allow_query ?? [])]
  allowRecursion.value = [...(safe.allow_recursion ?? [])]
  allowTransfer.value = [...(safe.allow_transfer ?? [])]
}

const matchListEntries = computed(() =>
  Object.entries(matchLists.value ?? {}).sort(([a], [b]) => a.localeCompare(b)),
)

const policySuggestions = computed(() => {
  const listNames = Object.keys(matchLists.value ?? {}).sort()
  return [...ACL_KEYWORDS, ...listNames]
})

function buildACLPayload(): ACLConfig {
  return {
    match_lists: Object.fromEntries(
      Object.entries(matchLists.value).map(([name, values]) => [
        name,
        values.map((value) => value.trim()).filter(Boolean),
      ]),
    ),
    allow_query: allowQuery.value.map((value) => value.trim()).filter(Boolean),
    allow_recursion: allowRecursion.value.map((value) => value.trim()).filter(Boolean),
    allow_transfer: allowTransfer.value.map((value) => value.trim()).filter(Boolean),
    zones: aclConfig.value?.zones,
  }
}

function buildConfigPayload(): AppConfig {
  if (!config.value) {
    throw new Error('configuration is not loaded')
  }
  const payload = cloneAppConfig(config.value)
  payload.recursive.upstreams = upstreams.value
    .map((upstream) => upstream.trim())
    .filter(Boolean)
  return payload
}

async function loadConfig(): Promise<void> {
  configLoading.value = true
  try {
    const loaded = await fetchConfig()
    config.value = loaded
    applyConfigToForm(loaded)
  } catch (err) {
    notify(parseApiError(err, 'Failed to load configuration'), 'error')
  } finally {
    configLoading.value = false
  }
}

async function saveConfig(section: string): Promise<void> {
  if (!config.value) {
    return
  }
  configSaving.value = true
  try {
    const response = await updateConfig(buildConfigPayload())
    if (response.requires_restart) {
      requiresRestart.value = true
    }
    notify(`${section} settings saved`)
    await loadConfig()
  } catch (err) {
    notify(parseApiError(err, `Failed to save ${section.toLowerCase()} settings`), 'error')
  } finally {
    configSaving.value = false
  }
}

async function loadACL(): Promise<void> {
  aclLoading.value = true
  try {
    const loaded = await fetchACLConfig()
    aclConfig.value = loaded ?? EMPTY_ACL
    applyACLToForm(loaded)
  } catch (err) {
    notify(parseApiError(err, 'Failed to load ACL configuration'), 'error')
    aclConfig.value = EMPTY_ACL
    applyACLToForm(EMPTY_ACL)
  } finally {
    aclLoading.value = false
  }
}

async function saveACL(): Promise<void> {
  aclSaving.value = true
  try {
    await updateACLConfig(buildACLPayload())
    notify('Security & ACL settings saved')
    await loadACL()
  } catch (err) {
    notify(parseApiError(err, 'Failed to save ACL configuration'), 'error')
  } finally {
    aclSaving.value = false
  }
}

function openAddMatchListDialog(): void {
  editingMatchListName.value = null
  matchListNameInput.value = ''
  matchListValues.value = []
  matchListDialogOpen.value = true
}

function openEditMatchListDialog(name: string, values: string[]): void {
  editingMatchListName.value = name
  matchListNameInput.value = name
  matchListValues.value = [...values]
  matchListDialogOpen.value = true
}

function submitMatchListDialog(): void {
  const name = matchListNameInput.value.trim()
  if (!name) {
    notify('Match list name is required', 'error')
    return
  }
  if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(name)) {
    notify('Name must start with a letter and contain only letters, digits, hyphens, or underscores', 'error')
    return
  }
  const values = matchListValues.value.map((value) => value.trim()).filter(Boolean)
  if (values.length === 0) {
    notify('At least one network entry is required', 'error')
    return
  }

  const next = { ...matchLists.value }
  if (editingMatchListName.value && editingMatchListName.value !== name) {
    delete next[editingMatchListName.value]
  }
  next[name] = values
  matchLists.value = next
  matchListDialogOpen.value = false
}

function removeMatchList(name: string): void {
  deletingMatchListName.value = name
  const next = { ...matchLists.value }
  delete next[name]
  matchLists.value = next
  deletingMatchListName.value = null
}

function openUpstreamDialog(): void {
  upstreamInput.value = ''
  upstreamDialogOpen.value = true
}

function addUpstream(): void {
  const upstream = upstreamInput.value.trim()
  if (!upstream) {
    notify('Upstream IP or hostname is required', 'error')
    return
  }
  if (upstreams.value.includes(upstream)) {
    notify('Upstream is already listed', 'error')
    return
  }
  upstreams.value = [...upstreams.value, upstream]
  upstreamDialogOpen.value = false
}

function removeUpstream(index: number): void {
  deletingUpstreamIndex.value = index
  upstreams.value = upstreams.value.filter((_, i) => i !== index)
  deletingUpstreamIndex.value = null
}

watch(activeTab, (tab) => {
  router.replace({ query: { ...route.query, tab } })
})

watch(
  () => route.query.tab,
  () => {
    syncTabFromRoute()
  },
)

onMounted(() => {
  syncTabFromRoute()
  void loadConfig()
  void loadACL()
})
</script>

<template>
  <div class="mx-auto max-w-5xl space-y-6">
    <div class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Settings</h1>
      <p class="text-sm text-muted-foreground">
        Manage DNS configuration, security policies, and logging.
      </p>
    </div>

    <Alert v-if="requiresRestart" variant="destructive">
      Restart required to apply network changes.
    </Alert>

    <Tabs v-model="activeTab" class="space-y-4">
      <TabsList class="grid h-auto w-full grid-cols-2 gap-1 sm:grid-cols-2 lg:grid-cols-4">
        <TabsTrigger value="dns" class="gap-1.5">
          <Server class="size-4" />
          DNS &amp; System
        </TabsTrigger>
        <TabsTrigger value="security" class="gap-1.5">
          <ShieldCheck class="size-4" />
          Security &amp; ACL
        </TabsTrigger>
        <TabsTrigger value="logging" class="gap-1.5">
          <FileText class="size-4" />
          Logging
        </TabsTrigger>
        <TabsTrigger value="ui" class="gap-1.5">
          <Monitor class="size-4" />
          UI Preferences
        </TabsTrigger>
      </TabsList>

      <TabsContent value="dns">
        <Card>
          <CardHeader>
            <CardTitle>DNS &amp; System</CardTitle>
            <CardDescription>
              Resolver mode, upstreams, root hints, and response rate limiting.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-6">
            <div v-if="configLoading" class="flex items-center gap-2 py-8 text-sm text-muted-foreground">
              <Loader2 class="size-4 animate-spin" />
              Loading configuration…
            </div>

            <template v-else-if="config">
              <div class="grid gap-4 sm:grid-cols-2">
                <div class="grid gap-2">
                  <Label for="resolver-mode">Resolver mode</Label>
                  <Select :model-value="config.resolver.mode"
                    @update:model-value="(v) => { config!.resolver.mode = String(v) }">
                    <SelectTrigger id="resolver-mode">
                      <SelectValue placeholder="Select mode" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="forward">Forward</SelectItem>
                      <SelectItem value="iterative">Iterative</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div class="grid gap-2">
                  <Label for="root-hints-file">Root hints file</Label>
                  <Input id="root-hints-file" v-model="config.resolver.root_hints_file" />
                </div>
              </div>

              <div class="flex flex-wrap gap-6">
                <div class="flex items-center gap-2">
                  <Switch id="auto-root-hints" v-model:checked="config.resolver.auto_update_root_hints" />
                  <Label for="auto-root-hints">Auto-update root hints</Label>
                </div>
                <div class="flex items-center gap-2">
                  <Switch id="qname-min" v-model:checked="config.resolver.qname_minimization" />
                  <Label for="qname-min">QNAME minimization</Label>
                </div>
              </div>

              <div class="space-y-4 rounded-md border p-4">
                <div class="flex items-start justify-between gap-4">
                  <div class="space-y-1">
                    <p class="text-sm font-medium">Upstream resolvers</p>
                    <p class="text-xs text-muted-foreground">
                      Forwarding targets for recursive queries. Port 53 is assumed when omitted.
                    </p>
                  </div>
                  <Button size="sm" @click="openUpstreamDialog">
                    <Plus class="mr-1.5 size-4" />
                    Add Upstream
                  </Button>
                </div>

                <div v-if="upstreams.length === 0"
                  class="rounded-md border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
                  No upstream resolvers configured. At least one is required in forward mode.
                </div>

                <div v-else class="overflow-x-auto rounded-md border">
                  <table class="w-full text-sm">
                    <thead>
                      <tr class="border-b bg-muted/40 text-left">
                        <th class="px-4 py-3 font-medium">Address</th>
                        <th class="w-20 px-4 py-3 font-medium text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr v-for="(upstream, index) in upstreams" :key="`${upstream}-${index}`"
                        class="border-b last:border-b-0">
                        <td class="px-4 py-3 font-mono text-xs sm:text-sm">
                          {{ upstream }}
                        </td>
                        <td class="px-4 py-3 text-right">
                          <Button variant="ghost" size="icon" class="size-8 text-destructive hover:text-destructive"
                            :disabled="deletingUpstreamIndex === index" @click="removeUpstream(index)">
                            <Loader2 v-if="deletingUpstreamIndex === index" class="size-4 animate-spin" />
                            <Trash2 v-else class="size-4" />
                          </Button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              <div class="grid gap-4 rounded-md border p-4">
                <div class="flex items-center justify-between gap-4">
                  <div>
                    <p class="text-sm font-medium">Rate limiting</p>
                    <p class="text-xs text-muted-foreground">
                      Per-client response rate limiting (RRL).
                    </p>
                  </div>
                  <Switch v-model:checked="config.rate_limit.enabled" />
                </div>
                <div class="grid gap-4 sm:grid-cols-2">
                  <div class="grid gap-2">
                    <Label for="rate-rps">Requests per second</Label>
                    <Input id="rate-rps" v-model.number="config.rate_limit.requests_per_second" type="number" min="1" />
                  </div>
                  <div class="grid gap-2">
                    <Label for="rate-burst">Burst</Label>
                    <Input id="rate-burst" v-model.number="config.rate_limit.burst" type="number" min="1" />
                  </div>
                </div>
              </div>

              <div class="flex justify-end">
                <Button :disabled="configSaving" @click="saveConfig('DNS & System')">
                  <Loader2 v-if="configSaving" class="mr-1.5 size-4 animate-spin" />
                  <Save v-else class="mr-1.5 size-4" />
                  Save DNS &amp; System
                </Button>
              </div>
            </template>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="security">
        <div class="space-y-4">
          <Card>
            <CardHeader class="flex flex-row items-start justify-between gap-4 space-y-0">
              <div class="space-y-1">
                <CardTitle>Match Lists (Network Groups)</CardTitle>
                <CardDescription>
                  Named groups of IP addresses and CIDR ranges. Reference these names in global and zone policies below.
                </CardDescription>
              </div>
              <Button size="sm" :disabled="aclLoading" @click="openAddMatchListDialog">
                <Plus class="mr-1.5 size-4" />
                Add Group
              </Button>
            </CardHeader>
            <CardContent class="space-y-4">
              <div v-if="aclLoading" class="flex items-center gap-2 py-8 text-sm text-muted-foreground">
                <Loader2 class="size-4 animate-spin" />
                Loading ACL configuration…
              </div>

              <div v-else-if="matchListEntries.length === 0"
                class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground">
                No match lists defined. Create a group such as
                <span class="font-mono">trusted-lan</span> with your LAN CIDRs.
              </div>

              <div v-else class="overflow-x-auto rounded-md border">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="border-b bg-muted/40 text-left">
                      <th class="px-4 py-3 font-medium">Name</th>
                      <th class="px-4 py-3 font-medium">Networks</th>
                      <th class="w-28 px-4 py-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="[name, values] in matchListEntries" :key="name" class="border-b last:border-b-0">
                      <td class="px-4 py-3 font-mono text-xs sm:text-sm">{{ name }}</td>
                      <td class="px-4 py-3">
                        <div class="flex flex-wrap gap-1">
                          <span v-for="value in values" :key="value"
                            class="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                            {{ value }}
                          </span>
                        </div>
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="inline-flex items-center gap-1">
                          <Button variant="ghost" size="icon" class="size-8"
                            @click="openEditMatchListDialog(name, values)">
                            <Pencil class="size-4" />
                          </Button>
                          <Button variant="ghost" size="icon" class="size-8 text-destructive hover:text-destructive"
                            :disabled="deletingMatchListName === name" @click="removeMatchList(name)">
                            <Loader2 v-if="deletingMatchListName === name" class="size-4 animate-spin" />
                            <Trash2 v-else class="size-4" />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Global Policies</CardTitle>
              <CardDescription>
                BIND9-style ACL directives applied server-wide. Use keywords
                (<span class="font-mono">any</span>, <span class="font-mono">none</span>,
                <span class="font-mono">localhost</span>), raw IPs/CIDRs, or match list names.
              </CardDescription>
            </CardHeader>
            <CardContent class="space-y-6">
              <div class="grid gap-2">
                <Label for="allow-query">Allow Query</Label>
                <p class="text-xs text-muted-foreground">
                  Clients permitted to send DNS queries. Defaults to <span class="font-mono">any</span> when empty.
                </p>
                <TokenInput id="allow-query" v-model="allowQuery" :suggestions="policySuggestions"
                  placeholder="any, trusted-lan, 10.0.0.0/8…" :disabled="aclLoading" />
              </div>

              <div class="grid gap-2">
                <Label for="allow-recursion">Allow Recursion</Label>
                <p class="text-xs text-muted-foreground">
                  Clients permitted to use recursive resolution. Falls back to legacy trusted subnets when empty.
                </p>
                <TokenInput id="allow-recursion" v-model="allowRecursion" :suggestions="policySuggestions"
                  placeholder="trusted-lan, localhost…" :disabled="aclLoading" />
              </div>

              <div class="grid gap-2">
                <Label for="allow-transfer">Allow Transfer</Label>
                <p class="text-xs text-muted-foreground">
                  Clients permitted to request zone transfers (AXFR/IXFR).
                </p>
                <TokenInput id="allow-transfer" v-model="allowTransfer" :suggestions="policySuggestions"
                  placeholder="none, trusted-lan…" :disabled="aclLoading" />
              </div>

              <div class="flex justify-end">
                <Button :disabled="aclSaving || aclLoading" @click="saveACL">
                  <Loader2 v-if="aclSaving" class="mr-1.5 size-4 animate-spin" />
                  <Save v-else class="mr-1.5 size-4" />
                  Save Security &amp; ACL
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <TabsContent value="logging">
        <Card>
          <CardHeader>
            <CardTitle>Logging</CardTitle>
            <CardDescription>
              Runtime log level and file rotation parameters persisted to config.toml.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <template v-if="config">
              <div class="grid gap-2">
                <Label for="log-level">Log level</Label>
                <Select :model-value="config.server.log_level"
                  @update:model-value="(v) => { config!.server.log_level = String(v) }">
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
                <Input id="log-file" v-model="config.logging.file_path" />
              </div>

              <div class="grid grid-cols-3 gap-3">
                <div class="grid gap-2">
                  <Label for="max-size">Max size (MB)</Label>
                  <Input id="max-size" v-model.number="config.logging.max_size_mb" type="number" min="1" />
                </div>
                <div class="grid gap-2">
                  <Label for="max-backups">Max backups</Label>
                  <Input id="max-backups" v-model.number="config.logging.max_backups" type="number" min="0" />
                </div>
                <div class="grid gap-2">
                  <Label for="max-age">Max age (days)</Label>
                  <Input id="max-age" v-model.number="config.logging.max_age_days" type="number" min="0" />
                </div>
              </div>

              <div class="flex justify-end">
                <Button :disabled="configSaving" @click="saveConfig('Logging')">
                  <Loader2 v-if="configSaving" class="mr-1.5 size-4 animate-spin" />
                  <Save v-else class="mr-1.5 size-4" />
                  Save logging settings
                </Button>
              </div>
            </template>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="ui">
        <Card>
          <CardHeader>
            <CardTitle>UI Preferences</CardTitle>
            <CardDescription>
              Client-side display options stored in this browser only.
            </CardDescription>
          </CardHeader>
          <CardContent class="space-y-4">
            <div class="grid gap-2 sm:max-w-xs">
              <Label for="toast-position">Notification position</Label>
              <Select :model-value="toastPosition"
                @update:model-value="(v) => { toastPosition = String(v) as ToastPosition }">
                <SelectTrigger id="toast-position">
                  <SelectValue placeholder="Select position" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem v-for="position in TOAST_POSITION_OPTIONS" :key="position.value" :value="position.value">
                    {{ position.label }}
                  </SelectItem>
                </SelectContent>
              </Select>
              <p class="text-xs text-muted-foreground">
                Controls where toast notifications appear across the management console.
              </p>
            </div>
          </CardContent>
        </Card>
      </TabsContent>
    </Tabs>

    <Dialog v-model:open="matchListDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {{ editingMatchListName === null ? 'Add Match List' : 'Edit Match List' }}
          </DialogTitle>
          <DialogDescription>
            Define a named network group. Use letters, digits, hyphens, and underscores in the name.
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="match-list-name">Name</Label>
            <Input id="match-list-name" v-model="matchListNameInput" placeholder="trusted-lan" autocomplete="off" />
          </div>
          <div class="grid gap-2">
            <Label for="match-list-values">Networks</Label>
            <TokenInput id="match-list-values" v-model="matchListValues" placeholder="192.168.0.0/16, 10.0.0.0/8…" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="matchListDialogOpen = false">Cancel</Button>
          <Button @click="submitMatchListDialog">
            {{ editingMatchListName === null ? 'Add Group' : 'Save Changes' }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="upstreamDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add Upstream</DialogTitle>
          <DialogDescription>
            Enter an IP address or hostname. Port 53 is used automatically when omitted.
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="upstream-address">IP / Hostname</Label>
            <Input id="upstream-address" v-model="upstreamInput" placeholder="1.1.1.1 or 1.1.1.1:53" autocomplete="off"
              @keyup.enter="addUpstream" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="upstreamDialogOpen = false">Cancel</Button>
          <Button @click="addUpstream">Add Upstream</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
