<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Loader2, Pencil, Plus, Save, Shield, Trash2 } from 'lucide-vue-next'
import {
  fetchRPZConfig,
  updateRPZConfig,
  type RPZAction,
  type RPZConfig,
  type RPZPolicy,
} from '@/api/client'
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
import { notify } from '@/composables/useNotifications'
import { parseApiError } from '@/utils/apiError'

const RPZ_ACTIONS: { value: RPZAction; label: string }[] = [
  { value: 'NXDOMAIN', label: 'NXDOMAIN' },
  { value: 'NODATA', label: 'NODATA' },
  { value: 'DROP', label: 'DROP' },
  { value: 'CNAME', label: 'CNAME' },
  { value: 'A', label: 'Override (A)' },
  { value: 'AAAA', label: 'Override (AAAA)' },
]

const TARGET_ACTIONS: RPZAction[] = ['CNAME', 'A', 'AAAA']

const EMPTY_CONFIG: RPZConfig = {
  enabled: false,
  policies: [],
}

const config = ref<RPZConfig>({ ...EMPTY_CONFIG, policies: [] })
const loading = ref(true)
const saving = ref(false)

const policyDialogOpen = ref(false)
const editingPolicyIndex = ref<number | null>(null)
const policyDomainInput = ref('')
const policyActionInput = ref<RPZAction>('NXDOMAIN')
const policyTargetInput = ref('')
const deletingPolicyIndex = ref<number | null>(null)

const showTargetField = computed(() => TARGET_ACTIONS.includes(policyActionInput.value))

const targetPlaceholder = computed(() => {
  switch (policyActionInput.value) {
    case 'A':
      return '10.0.0.5'
    case 'AAAA':
      return '2001:db8::1'
    default:
      return 'sinkhole.example.'
  }
})

const targetHelpText = computed(() => {
  switch (policyActionInput.value) {
    case 'A':
      return 'IPv4 address (required for Override A action).'
    case 'AAAA':
      return 'IPv6 address (required for Override AAAA action).'
    default:
      return 'CNAME target hostname (required for CNAME action).'
  }
})

function isValidIPv4(value: string): boolean {
  const parts = value.split('.')
  if (parts.length !== 4) {
    return false
  }
  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false
    }
    const n = Number(part)
    return n >= 0 && n <= 255
  })
}

function isValidIPv6(value: string): boolean {
  try {
    const url = new URL(`http://[${value}]`)
    return url.hostname.includes(':')
  } catch {
    return false
  }
}

function applyConfigToForm(cfg: RPZConfig): void {
  config.value = {
    enabled: cfg.enabled,
    policies: cfg.policies.map((policy) => ({
      domain: policy.domain,
      action: policy.action,
      target: policy.target ?? '',
    })),
  }
}

function buildPayload(): RPZConfig {
  return {
    enabled: config.value.enabled,
    policies: config.value.policies.map((policy) => {
      const entry: RPZPolicy = {
        domain: policy.domain.trim(),
        action: policy.action,
      }
      if (TARGET_ACTIONS.includes(policy.action) && policy.target?.trim()) {
        entry.target = policy.target.trim()
      }
      return entry
    }),
  }
}

async function loadConfig(): Promise<void> {
  loading.value = true
  try {
    const loaded = await fetchRPZConfig()
    applyConfigToForm(loaded ?? EMPTY_CONFIG)
  } catch (err) {
    notify(parseApiError(err, 'Failed to load RPZ configuration'), 'error')
    applyConfigToForm(EMPTY_CONFIG)
  } finally {
    loading.value = false
  }
}

async function saveConfig(): Promise<void> {
  saving.value = true
  try {
    await updateRPZConfig(buildPayload())
    notify('DNS Firewall settings saved')
    await loadConfig()
  } catch (err) {
    notify(parseApiError(err, 'Failed to save RPZ configuration'), 'error')
  } finally {
    saving.value = false
  }
}

function openAddPolicyDialog(): void {
  editingPolicyIndex.value = null
  policyDomainInput.value = ''
  policyActionInput.value = 'NXDOMAIN'
  policyTargetInput.value = ''
  policyDialogOpen.value = true
}

function openEditPolicyDialog(index: number): void {
  const policy = config.value.policies[index]
  if (!policy) {
    return
  }
  editingPolicyIndex.value = index
  policyDomainInput.value = policy.domain
  policyActionInput.value = policy.action
  policyTargetInput.value = policy.target ?? ''
  policyDialogOpen.value = true
}

function submitPolicyDialog(): void {
  const domain = policyDomainInput.value.trim()
  if (!domain) {
    notify('Domain pattern is required', 'error')
    return
  }

  const action = policyActionInput.value
  const target = policyTargetInput.value.trim()

  if (action === 'CNAME' && !target) {
    notify('CNAME action requires a target hostname', 'error')
    return
  }
  if (action === 'A') {
    if (!target) {
      notify('Override (A) action requires an IPv4 address', 'error')
      return
    }
    if (!isValidIPv4(target)) {
      notify('Target must be a valid IPv4 address', 'error')
      return
    }
  }
  if (action === 'AAAA') {
    if (!target) {
      notify('Override (AAAA) action requires an IPv6 address', 'error')
      return
    }
    if (!isValidIPv6(target)) {
      notify('Target must be a valid IPv6 address', 'error')
      return
    }
  }

  const next = [...config.value.policies]
  const entry: RPZPolicy = { domain, action }
  if (TARGET_ACTIONS.includes(action)) {
    entry.target = target
  }

  if (editingPolicyIndex.value === null) {
    next.push(entry)
  } else {
    next[editingPolicyIndex.value] = entry
  }

  config.value = { ...config.value, policies: next }
  policyDialogOpen.value = false
}

function removePolicy(index: number): void {
  deletingPolicyIndex.value = index
  config.value = {
    ...config.value,
    policies: config.value.policies.filter((_, i) => i !== index),
  }
  deletingPolicyIndex.value = null
}

function formatTarget(policy: RPZPolicy): string {
  if (TARGET_ACTIONS.includes(policy.action) && policy.target) {
    return policy.target
  }
  return '—'
}

function formatActionLabel(action: RPZAction): string {
  const match = RPZ_ACTIONS.find((item) => item.value === action)
  return match?.label ?? action
}

onMounted(() => {
  void loadConfig()
})
</script>

<template>
  <div class="mx-auto max-w-5xl space-y-6">
    <div class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">DNS Firewall (RPZ)</h1>
      <p class="text-sm text-muted-foreground">
        Response Policy Zone rules applied before cache lookup and recursion. Use exact domains or
        <span class="font-mono">*.wildcard</span> patterns.
      </p>
    </div>

    <Card>
      <CardHeader class="flex flex-row items-start justify-between gap-4 space-y-0">
        <div class="space-y-1">
          <CardTitle class="flex items-center gap-2">
            <Shield class="size-5" />
            RPZ Engine
          </CardTitle>
          <CardDescription>
            Enable or disable all RPZ policies globally. Changes are hot-reloaded without restart.
          </CardDescription>
        </div>
        <div class="flex items-center gap-2">
          <Switch
            id="rpz-enabled"
            :checked="config.enabled"
            :disabled="loading"
            @update:checked="(v) => { config.enabled = v }"
          />
          <Label for="rpz-enabled" class="text-sm font-medium">
            {{ config.enabled ? 'Enabled' : 'Disabled' }}
          </Label>
        </div>
      </CardHeader>

      <CardContent class="space-y-4">
        <div class="flex items-start justify-between gap-4">
          <div class="space-y-1">
            <p class="text-sm font-medium">Policy Rules</p>
            <p class="text-xs text-muted-foreground">
              Matched queries receive the configured action: NXDOMAIN, NODATA, DROP (no response), CNAME redirect, or A/AAAA override.
            </p>
          </div>
          <Button size="sm" :disabled="loading" @click="openAddPolicyDialog">
            <Plus class="mr-1.5 size-4" />
            Add Rule
          </Button>
        </div>

        <div v-if="loading" class="flex items-center gap-2 py-8 text-sm text-muted-foreground">
          <Loader2 class="size-4 animate-spin" />
          Loading RPZ configuration…
        </div>

        <div
          v-else-if="config.policies.length === 0"
          class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground"
        >
          No RPZ policies configured. Add a rule to block or redirect matching query names.
        </div>

        <div v-else class="overflow-x-auto rounded-md border">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b bg-muted/40 text-left">
                <th class="px-4 py-3 font-medium">Domain</th>
                <th class="px-4 py-3 font-medium">Action</th>
                <th class="px-4 py-3 font-medium">Target</th>
                <th class="w-28 px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(policy, index) in config.policies"
                :key="`${policy.domain}-${index}`"
                class="border-b last:border-b-0"
              >
                <td class="px-4 py-3 font-mono text-xs sm:text-sm">
                  {{ policy.domain }}
                </td>
                <td class="px-4 py-3">
                  <span class="rounded bg-muted px-2 py-0.5 font-mono text-xs">
                    {{ formatActionLabel(policy.action) }}
                  </span>
                </td>
                <td class="px-4 py-3 font-mono text-xs text-muted-foreground">
                  {{ formatTarget(policy) }}
                </td>
                <td class="px-4 py-3 text-right">
                  <div class="inline-flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      class="size-8"
                      @click="openEditPolicyDialog(index)"
                    >
                      <Pencil class="size-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      class="size-8 text-destructive hover:text-destructive"
                      :disabled="deletingPolicyIndex === index"
                      @click="removePolicy(index)"
                    >
                      <Loader2 v-if="deletingPolicyIndex === index" class="size-4 animate-spin" />
                      <Trash2 v-else class="size-4" />
                    </Button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="flex justify-end pt-2">
          <Button :disabled="saving || loading" @click="saveConfig">
            <Loader2 v-if="saving" class="mr-1.5 size-4 animate-spin" />
            <Save v-else class="mr-1.5 size-4" />
            Save DNS Firewall
          </Button>
        </div>
      </CardContent>
    </Card>

    <Dialog v-model:open="policyDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            {{ editingPolicyIndex === null ? 'Add RPZ Rule' : 'Edit RPZ Rule' }}
          </DialogTitle>
          <DialogDescription>
            Enter a domain or wildcard pattern. Wildcards must start with
            <span class="font-mono">*.</span> (e.g. <span class="font-mono">*.ads.example</span>).
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="rpz-domain">Domain</Label>
            <Input
              id="rpz-domain"
              v-model="policyDomainInput"
              placeholder="example.com or *.telemetry.local"
              autocomplete="off"
            />
          </div>
          <div class="grid gap-2">
            <Label for="rpz-action">Action</Label>
            <Select
              :model-value="policyActionInput"
              @update:model-value="(v) => { policyActionInput = String(v) as RPZAction }"
            >
              <SelectTrigger id="rpz-action">
                <SelectValue placeholder="Select action" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-for="action in RPZ_ACTIONS" :key="action.value" :value="action.value">
                  {{ action.label }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div v-if="showTargetField" class="grid gap-2">
            <Label for="rpz-target">Target</Label>
            <Input
              id="rpz-target"
              v-model="policyTargetInput"
              :placeholder="targetPlaceholder"
              autocomplete="off"
            />
            <p class="text-xs text-muted-foreground">
              {{ targetHelpText }}
            </p>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="policyDialogOpen = false">Cancel</Button>
          <Button @click="submitPolicyDialog">
            {{ editingPolicyIndex === null ? 'Add Rule' : 'Save Changes' }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
