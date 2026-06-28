<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
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
  createACLRule,
  deleteACLRule,
  fetchACLRules,
  updateACLRule,
  type ACLAction,
  type ACLRule,
} from '@/api/settings'
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import {
  TOAST_POSITION_OPTIONS,
  useToastPosition,
  type ToastPosition,
} from '@/composables/useToastPosition'
import { parseApiError } from '@/utils/apiError'

const TAB_IDS = ['dns', 'security', 'logging', 'ui'] as const
type TabId = (typeof TAB_IDS)[number]

const route = useRoute()
const router = useRouter()

const activeTab = ref<TabId>('dns')
const config = ref<AppConfig | null>(null)
const configLoading = ref(true)
const configSaving = ref(false)
const requiresRestart = ref(false)

const toastPosition = useToastPosition()

const upstreams = ref<string[]>([])
const trustedSubnets = ref<string[]>([])

const upstreamDialogOpen = ref(false)
const upstreamInput = ref('')
const deletingUpstreamIndex = ref<number | null>(null)

const rules = ref<ACLRule[]>([])
const aclLoading = ref(true)
const ruleDialogOpen = ref(false)
const editingRuleId = ref<number | null>(null)
const ruleSubnet = ref('')
const ruleDescription = ref('')
const ruleAction = ref<ACLAction>('allow')
const savingRule = ref(false)
const deletingId = ref<number | null>(null)

const trustedDialogOpen = ref(false)
const trustedSubnetInput = ref('')
const deletingTrustedIndex = ref<number | null>(null)

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
  trustedSubnets.value = [...cfg.recursive.trusted_subnets]
}

function buildConfigPayload(): AppConfig {
  if (!config.value) {
    throw new Error('configuration is not loaded')
  }
  const payload = cloneAppConfig(config.value)
  payload.recursive.upstreams = upstreams.value
    .map((upstream) => upstream.trim())
    .filter(Boolean)
  payload.recursive.trusted_subnets = trustedSubnets.value
    .map((subnet) => subnet.trim())
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

async function loadRules(): Promise<void> {
  aclLoading.value = true
  try {
    const response = await fetchACLRules()
    rules.value = response.rules
  } catch (err) {
    notify(parseApiError(err, 'Failed to load ACL rules'), 'error')
  } finally {
    aclLoading.value = false
  }
}

function openAddRuleDialog(): void {
  editingRuleId.value = null
  ruleSubnet.value = ''
  ruleDescription.value = ''
  ruleAction.value = 'allow'
  ruleDialogOpen.value = true
}

function openEditRuleDialog(rule: ACLRule): void {
  editingRuleId.value = rule.id
  ruleSubnet.value = rule.subnet
  ruleDescription.value = rule.description ?? ''
  ruleAction.value = rule.action
  ruleDialogOpen.value = true
}

async function submitRuleDialog(): Promise<void> {
  const subnet = ruleSubnet.value.trim()
  if (!subnet) {
    notify('Subnet or IP address is required', 'error')
    return
  }

  savingRule.value = true
  try {
    if (editingRuleId.value === null) {
      await createACLRule(subnet, ruleDescription.value, ruleAction.value)
      notify('ACL rule added')
    } else {
      await updateACLRule(
        editingRuleId.value,
        subnet,
        ruleDescription.value,
        ruleAction.value,
      )
      notify('ACL rule updated')
    }
    ruleDialogOpen.value = false
    await loadRules()
  } catch (err) {
    notify(parseApiError(err, 'Failed to save ACL rule'), 'error')
  } finally {
    savingRule.value = false
  }
}

async function removeRule(id: number): Promise<void> {
  deletingId.value = id
  try {
    await deleteACLRule(id)
    await loadRules()
    notify('ACL rule removed')
  } catch (err) {
    notify(parseApiError(err, 'Failed to delete ACL rule'), 'error')
  } finally {
    deletingId.value = null
  }
}

function openTrustedDialog(): void {
  trustedSubnetInput.value = ''
  trustedDialogOpen.value = true
}

function addTrustedSubnet(): void {
  const subnet = trustedSubnetInput.value.trim()
  if (!subnet) {
    notify('Subnet or IP address is required', 'error')
    return
  }
  if (trustedSubnets.value.includes(subnet)) {
    notify('Subnet is already listed', 'error')
    return
  }
  trustedSubnets.value = [...trustedSubnets.value, subnet]
  trustedDialogOpen.value = false
}

function removeTrustedSubnet(index: number): void {
  deletingTrustedIndex.value = index
  trustedSubnets.value = trustedSubnets.value.filter((_, i) => i !== index)
  deletingTrustedIndex.value = null
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

function actionBadgeClass(action: ACLAction): string {
  return action === 'block'
    ? 'bg-destructive/10 text-destructive'
    : 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
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
  void loadRules()
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
            <div
              v-if="configLoading"
              class="flex items-center gap-2 py-8 text-sm text-muted-foreground"
            >
              <Loader2 class="size-4 animate-spin" />
              Loading configuration…
            </div>

            <template v-else-if="config">
              <div class="grid gap-4 sm:grid-cols-2">
                <div class="grid gap-2">
                  <Label for="resolver-mode">Resolver mode</Label>
                  <Select
                    :model-value="config.resolver.mode"
                    @update:model-value="(v) => { config!.resolver.mode = String(v) }"
                  >
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
                  <Input
                    id="root-hints-file"
                    v-model="config.resolver.root_hints_file"
                  />
                </div>
              </div>

              <div class="flex flex-wrap gap-6">
                <div class="flex items-center gap-2">
                  <Switch
                    id="auto-root-hints"
                    v-model:checked="config.resolver.auto_update_root_hints"
                  />
                  <Label for="auto-root-hints">Auto-update root hints</Label>
                </div>
                <div class="flex items-center gap-2">
                  <Switch
                    id="qname-min"
                    v-model:checked="config.resolver.qname_minimization"
                  />
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

                <div
                  v-if="upstreams.length === 0"
                  class="rounded-md border border-dashed px-4 py-8 text-center text-sm text-muted-foreground"
                >
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
                      <tr
                        v-for="(upstream, index) in upstreams"
                        :key="`${upstream}-${index}`"
                        class="border-b last:border-b-0"
                      >
                        <td class="px-4 py-3 font-mono text-xs sm:text-sm">
                          {{ upstream }}
                        </td>
                        <td class="px-4 py-3 text-right">
                          <Button
                            variant="ghost"
                            size="icon"
                            class="size-8 text-destructive hover:text-destructive"
                            :disabled="deletingUpstreamIndex === index"
                            @click="removeUpstream(index)"
                          >
                            <Loader2
                              v-if="deletingUpstreamIndex === index"
                              class="size-4 animate-spin"
                            />
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
                    <Input
                      id="rate-rps"
                      v-model.number="config.rate_limit.requests_per_second"
                      type="number"
                      min="1"
                    />
                  </div>
                  <div class="grid gap-2">
                    <Label for="rate-burst">Burst</Label>
                    <Input
                      id="rate-burst"
                      v-model.number="config.rate_limit.burst"
                      type="number"
                      min="1"
                    />
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
                <CardTitle>Recursive trusted subnets</CardTitle>
                <CardDescription>
                  Clients in these CIDR ranges may send recursive queries.
                </CardDescription>
              </div>
              <Button size="sm" :disabled="!config" @click="openTrustedDialog">
                <Plus class="mr-1.5 size-4" />
                Add Subnet
              </Button>
            </CardHeader>
            <CardContent class="space-y-4">
              <div
                v-if="trustedSubnets.length === 0"
                class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground"
              >
                No trusted subnets configured. Recursive queries from any client may be refused.
              </div>

              <div v-else class="overflow-x-auto rounded-md border">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="border-b bg-muted/40 text-left">
                      <th class="px-4 py-3 font-medium">Subnet</th>
                      <th class="w-20 px-4 py-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="(subnet, index) in trustedSubnets"
                      :key="`${subnet}-${index}`"
                      class="border-b last:border-b-0"
                    >
                      <td class="px-4 py-3 font-mono text-xs sm:text-sm">
                        {{ subnet }}
                      </td>
                      <td class="px-4 py-3 text-right">
                        <Button
                          variant="ghost"
                          size="icon"
                          class="size-8 text-destructive hover:text-destructive"
                          :disabled="deletingTrustedIndex === index"
                          @click="removeTrustedSubnet(index)"
                        >
                          <Loader2
                            v-if="deletingTrustedIndex === index"
                            class="size-4 animate-spin"
                          />
                          <Trash2 v-else class="size-4" />
                        </Button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div class="flex justify-end">
                <Button
                  :disabled="configSaving || !config"
                  @click="saveConfig('Security')"
                >
                  <Loader2 v-if="configSaving" class="mr-1.5 size-4 animate-spin" />
                  <Save v-else class="mr-1.5 size-4" />
                  Save trusted subnets
                </Button>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader class="flex flex-row items-start justify-between gap-4 space-y-0">
              <div class="space-y-1">
                <CardTitle class="flex items-center gap-2 text-lg">
                  <ShieldCheck class="size-5 text-muted-foreground" />
                  Query ACL rules
                </CardTitle>
                <CardDescription>
                  Restrict DNS queries to specific IP addresses or CIDR subnets. When no
                  rules are configured, all clients are allowed.
                </CardDescription>
              </div>
              <Button size="sm" @click="openAddRuleDialog">
                <Plus class="mr-1.5 size-4" />
                Add Subnet
              </Button>
            </CardHeader>
            <CardContent>
              <div
                v-if="aclLoading"
                class="flex items-center justify-center gap-2 py-10 text-sm text-muted-foreground"
              >
                <Loader2 class="size-4 animate-spin" />
                Loading ACL rules…
              </div>

              <div
                v-else-if="rules.length === 0"
                class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground"
              >
                No ACL rules configured. All clients may send DNS queries.
              </div>

              <div v-else class="overflow-x-auto rounded-md border">
                <table class="w-full text-sm">
                  <thead>
                    <tr class="border-b bg-muted/40 text-left">
                      <th class="px-4 py-3 font-medium">Subnet</th>
                      <th class="px-4 py-3 font-medium">Description</th>
                      <th class="px-4 py-3 font-medium">Action</th>
                      <th class="w-28 px-4 py-3 font-medium text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr
                      v-for="rule in rules"
                      :key="rule.id"
                      class="border-b last:border-b-0"
                    >
                      <td class="px-4 py-3 font-mono text-xs sm:text-sm">
                        {{ rule.subnet }}
                      </td>
                      <td class="px-4 py-3 text-muted-foreground">
                        {{ rule.description || '—' }}
                      </td>
                      <td class="px-4 py-3">
                        <span
                          :class="[
                            'rounded px-1.5 py-0.5 text-xs font-medium uppercase tracking-wide',
                            actionBadgeClass(rule.action),
                          ]"
                        >
                          {{ rule.action }}
                        </span>
                      </td>
                      <td class="px-4 py-3 text-right">
                        <div class="inline-flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            class="size-8"
                            @click="openEditRuleDialog(rule)"
                          >
                            <Pencil class="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            class="size-8 text-destructive hover:text-destructive"
                            :disabled="deletingId === rule.id"
                            @click="removeRule(rule.id)"
                          >
                            <Loader2
                              v-if="deletingId === rule.id"
                              class="size-4 animate-spin"
                            />
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
                <Select
                  :model-value="config.server.log_level"
                  @update:model-value="(v) => { config!.server.log_level = String(v) }"
                >
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
                  <Input
                    id="max-size"
                    v-model.number="config.logging.max_size_mb"
                    type="number"
                    min="1"
                  />
                </div>
                <div class="grid gap-2">
                  <Label for="max-backups">Max backups</Label>
                  <Input
                    id="max-backups"
                    v-model.number="config.logging.max_backups"
                    type="number"
                    min="0"
                  />
                </div>
                <div class="grid gap-2">
                  <Label for="max-age">Max age (days)</Label>
                  <Input
                    id="max-age"
                    v-model.number="config.logging.max_age_days"
                    type="number"
                    min="0"
                  />
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
              <Select
                :model-value="toastPosition"
                @update:model-value="(v) => { toastPosition = String(v) as ToastPosition }"
              >
                <SelectTrigger id="toast-position">
                  <SelectValue placeholder="Select position" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem
                    v-for="position in TOAST_POSITION_OPTIONS"
                    :key="position.value"
                    :value="position.value"
                  >
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

    <Dialog v-model:open="ruleDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{{ editingRuleId === null ? 'Add Subnet' : 'Edit Rule' }}</DialogTitle>
          <DialogDescription>
            Enter an IP address (e.g. 192.168.1.10) or CIDR block (e.g. 10.0.0.0/8).
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="acl-subnet">Subnet / IP</Label>
            <Input
              id="acl-subnet"
              v-model="ruleSubnet"
              placeholder="192.168.0.0/16"
              autocomplete="off"
              @keyup.enter="submitRuleDialog"
            />
          </div>
          <div class="grid gap-2">
            <Label for="acl-action">Action</Label>
            <Select
              :model-value="ruleAction"
              @update:model-value="(v) => { ruleAction = String(v) as ACLAction }"
            >
              <SelectTrigger id="acl-action">
                <SelectValue placeholder="Select action" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="allow">Allow</SelectItem>
                <SelectItem value="block">Block</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div class="grid gap-2">
            <Label for="acl-description">Description (optional)</Label>
            <Input
              id="acl-description"
              v-model="ruleDescription"
              placeholder="Office LAN"
              autocomplete="off"
              @keyup.enter="submitRuleDialog"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="ruleDialogOpen = false">Cancel</Button>
          <Button :disabled="savingRule" @click="submitRuleDialog">
            <Loader2 v-if="savingRule" class="mr-1.5 size-4 animate-spin" />
            {{ editingRuleId === null ? 'Add Rule' : 'Save Changes' }}
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
            <Input
              id="upstream-address"
              v-model="upstreamInput"
              placeholder="1.1.1.1 or 1.1.1.1:53"
              autocomplete="off"
              @keyup.enter="addUpstream"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="upstreamDialogOpen = false">Cancel</Button>
          <Button @click="addUpstream">Add Upstream</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="trustedDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add Trusted Subnet</DialogTitle>
          <DialogDescription>
            Clients in this range may send recursive DNS queries.
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="trusted-subnet">Subnet / IP</Label>
            <Input
              id="trusted-subnet"
              v-model="trustedSubnetInput"
              placeholder="10.0.0.0/8"
              autocomplete="off"
              @keyup.enter="addTrustedSubnet"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="trustedDialogOpen = false">Cancel</Button>
          <Button @click="addTrustedSubnet">Add Subnet</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
