<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Loader2, Pencil, Plus, Shield, Trash2 } from 'lucide-vue-next'
import { notify } from '@/composables/useNotifications'
import {
  createZone,
  createZoneRecord,
  deleteZone,
  deleteZoneRecord,
  disableZoneDNSSEC,
  enableZoneDNSSEC,
  fetchZoneDNSSEC,
  fetchZoneRecords,
  fetchZones,
  updateZoneRecord,
  type ZoneDNSSECStatus,
  type ZoneInfo,
  type ZoneRecord,
} from '@/api/client'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
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
import { Textarea } from '@/components/ui/textarea'
import { Switch } from '@/components/ui/switch'
import ClipboardText from '@/components/ClipboardText.vue'
import { cn } from '@/lib/utils'
import {
  CAA_TAGS,
  CERT_TYPES,
  DANE_MATCHING_TYPES,
  DANE_SELECTORS,
  DANE_USAGES,
  DNSKEY_FLAGS,
  DNSKEY_PROTOCOLS,
  DNSSEC_ALGORITHMS,
  DS_DIGEST_TYPES,
  LOC_HEMISPHERES,
  RECORD_TYPES,
  SSHFP_ALGORITHMS,
  SSHFP_TYPES,
  buildRecordValue,
  contentPlaceholder,
  createDefaultFormState,
  isDaneType,
  isMultilineContentType,
  isSimpleContentType,
  populateFormFromRecord,
  stripTrailingDot,
  type RecordFormErrors,
  type RecordFormState,
  type RecordType,
  validateRecordForm,
} from '@/utils/dnsFormatting'
import { parseApiError } from '@/utils/apiError'

type ZoneView = 'public' | 'internal'

const zones = ref<ZoneInfo[]>([])
const selectedZone = ref<ZoneInfo | null>(null)
const records = ref<ZoneRecord[]>([])
const loadingZones = ref(true)
const loadingRecords = ref(false)
const recordDialogOpen = ref(false)
const addZoneDialogOpen = ref(false)
const deleteZoneDialogOpen = ref(false)
const deleteRecordDialogOpen = ref(false)
const submitting = ref(false)
const creatingZone = ref(false)
const deletingZone = ref(false)
const deletingId = ref<string | null>(null)
const newZoneName = ref('')
const newZoneView = ref<ZoneView>('public')
const editingRecordId = ref<string | null>(null)
const recordPendingDelete = ref<ZoneRecord | null>(null)
const dnssecDialogOpen = ref(false)
const loadingDNSSEC = ref(false)
const enablingDNSSEC = ref(false)
const disablingDNSSEC = ref(false)
const dnssecStatus = ref<ZoneDNSSECStatus | null>(null)
const showDNSSECRecords = ref(false)

const DNSSEC_RECORD_TYPES = new Set(['RRSIG', 'NSEC', 'DNSKEY'])

const form = ref<RecordFormState>(createDefaultFormState())
const recordFormErrors = ref<RecordFormErrors>({})

const selectedOrigin = computed(() => selectedZone.value?.origin ?? '')
const isEditingRecord = computed(() => editingRecordId.value !== null)
const isSoaRecord = computed(() => form.value.type === 'SOA')
const displayRecords = computed(() => {
  if (showDNSSECRecords.value) {
    return records.value
  }
  return records.value.filter((record) => !DNSSEC_RECORD_TYPES.has(record.type))
})

const fqdnPreview = computed(() => recordFqdn(form.value.name))

function recordFqdn(name: string): string {
  const zoneName = selectedZone.value ? formatOrigin(selectedOrigin.value) : ''
  const trimmed = name.trim()

  if (!trimmed) {
    return ''
  }
  if (!zoneName) {
    return '—'
  }
  if (trimmed === '@') {
    return zoneName
  }
  return `${trimmed}.${zoneName}`
}

function clearRecordFieldError(field: keyof RecordFormErrors): void {
  if (!recordFormErrors.value[field]) {
    return
  }
  const next = { ...recordFormErrors.value }
  delete next[field]
  recordFormErrors.value = next
}

function setSelectNumber(
  field: keyof Pick<
    RecordFormState,
    | 'dsAlgorithm'
    | 'dsDigestType'
    | 'sshfpAlgorithm'
    | 'sshfpType'
    | 'daneUsage'
    | 'daneSelector'
    | 'daneMatchingType'
    | 'dnskeyFlags'
    | 'dnskeyProtocol'
    | 'dnskeyAlgorithm'
    | 'certType'
    | 'certAlgorithm'
  >,
  value: string,
): void {
  form.value[field] = Number(value) as never
}

function setSelectString(
  field: keyof Pick<RecordFormState, 'caaTag' | 'locLatHem' | 'locLonHem'>,
  value: string,
): void {
  form.value[field] = value as never
}

function formatOrigin(origin: string): string {
  return stripTrailingDot(origin)
}

function recordTypeBadgeClass(type: string): string {
  switch (type) {
    case 'A':
    case 'AAAA':
      return 'border-transparent bg-sky-500/10 text-sky-700 dark:text-sky-400'
    case 'CNAME':
    case 'PTR':
      return 'border-transparent bg-violet-500/10 text-violet-700 dark:text-violet-400'
    case 'MX':
    case 'TXT':
      return 'border-transparent bg-amber-500/10 text-amber-700 dark:text-amber-400'
    case 'SOA':
    case 'NS':
      return 'border-transparent bg-emerald-500/10 text-emerald-700 dark:text-emerald-400'
    case 'RRSIG':
    case 'NSEC':
    case 'DNSKEY':
    case 'DS':
      return 'border-transparent bg-muted text-muted-foreground'
    default:
      return 'border-transparent bg-secondary text-secondary-foreground'
  }
}

function zoneKey(zone: ZoneInfo): string {
  return `${zone.origin}:${zone.view}`
}

function isSelected(zone: ZoneInfo): boolean {
  if (!selectedZone.value) {
    return false
  }
  return zoneKey(zone) === zoneKey(selectedZone.value)
}

async function loadZones(): Promise<void> {
  loadingZones.value = true
  try {
    const response = await fetchZones()
    zones.value = response.zones
    if (!selectedZone.value && zones.value.length > 0) {
      selectedZone.value = zones.value[0]
    } else if (selectedZone.value) {
      const match = zones.value.find((zone) => isSelected(zone))
      selectedZone.value = match ?? zones.value[0] ?? null
    }
  } catch (err) {
    notify(parseApiError(err, 'Failed to load zones'), 'error')
  } finally {
    loadingZones.value = false
  }
}

async function loadRecords(): Promise<void> {
  if (!selectedZone.value) {
    records.value = []
    return
  }

  loadingRecords.value = true
  try {
    const response = await fetchZoneRecords(
      selectedZone.value.origin,
      selectedZone.value.view,
    )
    records.value = response.records
  } catch (err) {
    records.value = []
    notify(parseApiError(err, 'Failed to load records'), 'error')
  } finally {
    loadingRecords.value = false
  }
}

function selectZone(zone: ZoneInfo): void {
  selectedZone.value = zone
}

function resetForm(): void {
  form.value = createDefaultFormState()
  recordFormErrors.value = {}
  editingRecordId.value = null
}

function openAddDialog(): void {
  resetForm()
  recordDialogOpen.value = true
}

function openEditDialog(record: ZoneRecord): void {
  resetForm()
  editingRecordId.value = record.id
  populateFormFromRecord(form.value, record)
  recordDialogOpen.value = true
}

function openAddZoneDialog(): void {
  newZoneName.value = ''
  newZoneView.value = 'public'
  addZoneDialogOpen.value = true
}

function openDeleteZoneDialog(): void {
  deleteZoneDialogOpen.value = true
}

function openDeleteRecordDialog(record: ZoneRecord): void {
  recordPendingDelete.value = record
  deleteRecordDialogOpen.value = true
}

async function submitZone(): Promise<void> {
  const name = newZoneName.value.trim()
  if (!name) {
    return
  }

  creatingZone.value = true
  try {
    await createZone(name, newZoneView.value)
    addZoneDialogOpen.value = false
    newZoneName.value = ''
    await loadZones()
    const created = zones.value.find(
      (zone) =>
        formatOrigin(zone.origin).toLowerCase() === name.toLowerCase() &&
        zone.view === newZoneView.value,
    )
    if (created) {
      selectedZone.value = created
    }
    await loadRecords()
    notify('Zone created')
  } catch (err) {
    notify(parseApiError(err, 'Failed to create zone'), 'error')
  } finally {
    creatingZone.value = false
  }
}

async function confirmDeleteZone(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  deletingZone.value = true
  try {
    await deleteZone(selectedZone.value.origin, selectedZone.value.view)
    deleteZoneDialogOpen.value = false
    selectedZone.value = null
    records.value = []
    await loadZones()
    await loadRecords()
    notify('Zone deleted')
  } catch (err) {
    notify(parseApiError(err, 'Failed to delete zone'), 'error')
  } finally {
    deletingZone.value = false
  }
}

async function submitRecord(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  const errors = validateRecordForm(form.value)
  recordFormErrors.value = errors
  if (Object.keys(errors).length > 0) {
    return
  }

  submitting.value = true
  const payload = {
    name: form.value.name.trim(),
    type: form.value.type,
    value: buildRecordValue(form.value),
    ttl: form.value.ttl.trim(),
    view: selectedZone.value.view,
  }

  try {
    if (isEditingRecord.value && editingRecordId.value) {
      await updateZoneRecord(
        selectedZone.value.origin,
        editingRecordId.value,
        payload,
      )
      notify('Record updated')
    } else {
      await createZoneRecord(selectedZone.value.origin, payload)
      notify('Record created')
    }
    recordDialogOpen.value = false
    resetForm()
    await Promise.all([loadZones(), loadRecords()])
  } catch (err) {
    notify(
      parseApiError(
        err,
        isEditingRecord.value ? 'Failed to update record' : 'Failed to create record',
      ),
      'error',
    )
  } finally {
    submitting.value = false
  }
}

async function openDNSSECDialog(): Promise<void> {
  if (!selectedZone.value) {
    return
  }
  dnssecDialogOpen.value = true
  await loadDNSSECStatus()
}

async function loadDNSSECStatus(): Promise<void> {
  if (!selectedZone.value) {
    dnssecStatus.value = null
    return
  }

  loadingDNSSEC.value = true
  try {
    dnssecStatus.value = await fetchZoneDNSSEC(
      selectedZone.value.origin,
      selectedZone.value.view,
    )
  } catch (err) {
    dnssecStatus.value = null
    notify(parseApiError(err, 'Failed to load DNSSEC status'), 'error')
  } finally {
    loadingDNSSEC.value = false
  }
}

async function enableDNSSEC(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  enablingDNSSEC.value = true
  try {
    dnssecStatus.value = await enableZoneDNSSEC(
      selectedZone.value.origin,
      selectedZone.value.view,
    )
    await Promise.all([loadZones(), loadRecords()])
    notify('DNSSEC enabled and zone signed')
  } catch (err) {
    notify(parseApiError(err, 'Failed to enable DNSSEC'), 'error')
  } finally {
    enablingDNSSEC.value = false
  }
}

async function disableDNSSEC(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  disablingDNSSEC.value = true
  try {
    dnssecStatus.value = await disableZoneDNSSEC(
      selectedZone.value.origin,
      selectedZone.value.view,
    )
    await Promise.all([loadZones(), loadRecords()])
    notify('DNSSEC disabled and signing records removed')
  } catch (err) {
    notify(parseApiError(err, 'Failed to disable DNSSEC'), 'error')
  } finally {
    disablingDNSSEC.value = false
  }
}

async function confirmDeleteRecord(): Promise<void> {
  if (!selectedZone.value || !recordPendingDelete.value) {
    return
  }

  const record = recordPendingDelete.value
  deletingId.value = record.id
  try {
    await deleteZoneRecord(
      selectedZone.value.origin,
      record.id,
      selectedZone.value.view,
    )
    deleteRecordDialogOpen.value = false
    recordPendingDelete.value = null
    await Promise.all([loadZones(), loadRecords()])
    notify('Record deleted')
  } catch (err) {
    notify(parseApiError(err, 'Failed to delete record'), 'error')
  } finally {
    deletingId.value = null
  }
}

function onRecordTypeChange(value: string): void {
  form.value.type = value as RecordType
  recordFormErrors.value = {}
}

watch(selectedZone, () => {
  void loadRecords()
})

watch(
  () => form.value.name,
  () => clearRecordFieldError('name'),
)

watch(
  () => form.value.ttl,
  () => clearRecordFieldError('ttl'),
)

onMounted(async () => {
  await loadZones()
  await loadRecords()
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="font-heading text-2xl font-semibold tracking-tight">Zones & Records</h1>
        <p class="text-sm text-muted-foreground">
          Manage authoritative DNS zones and records.
        </p>
      </div>
      <div class="flex flex-wrap gap-2">
        <Button
          variant="outline"
          :disabled="!selectedZone || loadingDNSSEC"
          @click="openDNSSECDialog"
        >
          <Shield class="size-4" />
          DNSSEC
        </Button>
        <Button variant="outline" :disabled="!selectedZone || deletingZone" @click="openDeleteZoneDialog">
          <Trash2 class="size-4 text-destructive" />
          Delete Zone
        </Button>
        <Button :disabled="!selectedZone || loadingRecords" @click="openAddDialog">
          <Plus class="size-4" />
          Add Record
        </Button>
      </div>
    </div>

    <div class="grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
      <Card class="h-fit">
        <CardHeader class="pb-3">
          <div class="flex items-start justify-between gap-2">
            <div>
              <CardTitle class="text-base">Zones</CardTitle>
              <CardDescription>Loaded authoritative zones</CardDescription>
            </div>
          </div>
          <Button variant="outline" size="sm" class="mt-2 w-full" :disabled="creatingZone" @click="openAddZoneDialog">
            <Plus class="size-4" />
            Add Zone
          </Button>
        </CardHeader>
        <CardContent class="p-0">
          <div v-if="loadingZones" class="flex items-center gap-2 px-4 py-6 text-sm text-muted-foreground">
            <Loader2 class="size-4 animate-spin" />
            Loading zones...
          </div>
          <div v-else-if="zones.length === 0" class="px-4 py-6 text-sm text-muted-foreground">
            No zones loaded.
          </div>
          <ul v-else class="divide-y divide-border">
            <li v-for="zone in zones" :key="zoneKey(zone)">
              <button type="button" :class="cn(
                'flex w-full flex-col items-start gap-1 px-4 py-3 text-left text-sm transition-colors hover:bg-accent',
                isSelected(zone) && 'bg-accent text-accent-foreground',
              )" @click="selectZone(zone)">
                <span class="font-medium">{{ formatOrigin(zone.origin) }}</span>
                <span class="inline-flex items-center gap-2 text-xs text-muted-foreground">
                  <span :class="cn(
                    'rounded px-1.5 py-0.5 font-medium uppercase tracking-wide',
                    zone.view === 'internal'
                      ? 'bg-amber-500/10 text-amber-700 dark:text-amber-400'
                      : 'bg-sky-500/10 text-sky-700 dark:text-sky-400',
                  )">
                    {{ zone.view }}
                  </span>
                  <span>{{ zone.records }} records</span>
                </span>
              </button>
            </li>
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader class="pb-3">
          <CardTitle class="text-base">
            <template v-if="selectedZone">
              {{ formatOrigin(selectedOrigin) }}
            </template>
            <template v-else>
              Records
            </template>
          </CardTitle>
          <CardDescription>
            <template v-if="selectedZone">
              {{ selectedZone.view }} view · BIND zone file records
            </template>
            <template v-else>
              Select a zone to view records
            </template>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div v-if="!selectedZone" class="py-10 text-center text-sm text-muted-foreground">
            Select a zone from the sidebar.
          </div>
          <div v-else-if="loadingRecords" class="flex items-center gap-2 py-10 text-sm text-muted-foreground">
            <Loader2 class="size-4 animate-spin" />
            Loading records...
          </div>
          <div v-else-if="records.length === 0" class="py-10 text-center text-sm text-muted-foreground">
            No records in this zone.
          </div>
          <div v-else class="space-y-3">
            <div class="flex items-center gap-2">
              <Switch id="show-dnssec-records" v-model:checked="showDNSSECRecords" />
              <Label for="show-dnssec-records" class="text-sm font-normal">
                Show DNSSEC records
              </Label>
            </div>
            <div v-if="displayRecords.length === 0" class="py-10 text-center text-sm text-muted-foreground">
              No user records to display. Enable "Show DNSSEC records" to view signing data.
            </div>
            <div v-else class="overflow-x-auto">
            <table class="w-full min-w-[640px] text-left text-sm">
              <thead>
                <tr class="border-b border-border text-muted-foreground">
                  <th class="px-3 py-2 font-medium">Name</th>
                  <th class="px-3 py-2 font-medium">Type</th>
                  <th class="px-3 py-2 font-medium">TTL</th>
                  <th class="px-3 py-2 font-medium">Value</th>
                  <th class="px-3 py-2 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="record in displayRecords" :key="record.id" class="border-b border-border/70 last:border-0">
                  <td class="px-3 py-2 font-mono text-xs">
                    {{ record.name }}
                    <span class="text-muted-foreground">
                      ({{ recordFqdn(record.name) }})
                    </span>
                  </td>
                  <td class="px-3 py-2">
                    <Badge :class="recordTypeBadgeClass(record.type)">
                      {{ record.type }}
                    </Badge>
                  </td>
                  <td class="px-3 py-2">{{ record.ttl }}</td>
                  <td class="max-w-md truncate px-3 py-2 font-mono text-xs" :title="record.value">
                    {{ record.value }}
                  </td>
                  <td class="px-3 py-2 text-right">
                    <div class="flex justify-end gap-1">
                      <Button variant="ghost" size="icon-sm" :aria-label="`Edit ${record.name} ${record.type}`"
                        @click="openEditDialog(record)">
                        <Pencil class="size-4" />
                      </Button>
                      <Button
                        v-if="record.type !== 'SOA'"
                        variant="ghost"
                        size="icon-sm"
                        :disabled="deletingId === record.id"
                        :aria-label="`Delete ${record.name} ${record.type}`"
                        @click="openDeleteRecordDialog(record)"
                      >
                        <Loader2 v-if="deletingId === record.id" class="size-4 animate-spin" />
                        <Trash2 v-else class="size-4 text-destructive" />
                      </Button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>

    <Dialog v-model:open="addZoneDialogOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add Zone</DialogTitle>
          <DialogDescription>
            Create a new authoritative DNS zone. A valid SOA record is written automatically.
          </DialogDescription>
        </DialogHeader>

        <form class="space-y-4" @submit.prevent="submitZone">
          <div class="space-y-2">
            <Label for="zone-name">Domain name</Label>
            <Input id="zone-name" v-model="newZoneName" placeholder="example.com" required />
          </div>

          <div class="space-y-2">
            <Label for="zone-view">View</Label>
            <select id="zone-view" v-model="newZoneView"
              class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring">
              <option value="public">public</option>
              <option value="internal">internal</option>
            </select>
            <p class="text-xs text-muted-foreground">
              Split-horizon view: public zones are served to all clients; internal zones are served only to trusted
              subnets.
            </p>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" :disabled="creatingZone" @click="addZoneDialogOpen = false">
              Cancel
            </Button>
            <Button type="submit" :disabled="creatingZone">
              <Loader2 v-if="creatingZone" class="size-4 animate-spin" />
              Create Zone
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <AlertDialog v-model:open="deleteZoneDialogOpen">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Zone</AlertDialogTitle>
          <AlertDialogDescription>
            This will permanently delete the entire zone and all of its records from disk.
            This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <p v-if="selectedZone" class="text-sm">
          Zone:
          <span class="font-medium">{{ formatOrigin(selectedOrigin) }}</span>
          ({{ selectedZone.view }} view)
        </p>

        <AlertDialogFooter>
          <AlertDialogCancel :disabled="deletingZone">Cancel</AlertDialogCancel>
          <AlertDialogAction class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            :disabled="deletingZone" @click.prevent="confirmDeleteZone">
            <Loader2 v-if="deletingZone" class="size-4 animate-spin" />
            Delete Zone
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    <AlertDialog v-model:open="deleteRecordDialogOpen">
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Record</AlertDialogTitle>
          <AlertDialogDescription>
            This will permanently remove the record from the zone file.
            This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>

        <p v-if="recordPendingDelete" class="text-sm font-mono">
          {{ recordPendingDelete.name }}
          <span class="text-muted-foreground">
            ({{ recordFqdn(recordPendingDelete.name) }})
          </span>
          {{ recordPendingDelete.type }}
          {{ recordPendingDelete.value }}
        </p>

        <AlertDialogFooter>
          <AlertDialogCancel :disabled="deletingId !== null">Cancel</AlertDialogCancel>
          <AlertDialogAction class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            :disabled="deletingId !== null" @click.prevent="confirmDeleteRecord">
            <Loader2 v-if="deletingId !== null" class="size-4 animate-spin" />
            Delete Record
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    <Dialog v-model:open="recordDialogOpen">
      <DialogContent class="max-h-[90vh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {{ isEditingRecord ? 'Edit DNS Record' : 'Add DNS Record' }}
          </DialogTitle>
          <DialogDescription>
            {{ isEditingRecord ? 'Update' : 'Create' }} a record in
            <span class="font-medium text-foreground">
              {{ selectedZone ? formatOrigin(selectedOrigin) : 'zone' }}
            </span>.
          </DialogDescription>
        </DialogHeader>

        <form class="space-y-4" novalidate @submit.prevent="submitRecord">
          <div class="space-y-2">
            <Label for="record-name">Name</Label>
            <Input id="record-name" v-model="form.name" placeholder="www or @"
              :class="recordFormErrors.name && 'border-destructive focus-visible:ring-destructive'"
              :aria-invalid="recordFormErrors.name ? true : undefined"
              :aria-describedby="recordFormErrors.name ? 'record-name-error' : 'record-name-preview'" />
            <p id="record-name-preview" class="text-xs text-muted-foreground"
              :class="recordFormErrors.name && 'sr-only'">
              Resolves to: {{ fqdnPreview || 'Enter @ for root' }}
            </p>
            <p v-if="recordFormErrors.name" id="record-name-error" class="text-xs text-destructive">
              {{ recordFormErrors.name }}
            </p>
          </div>

          <div class="space-y-2">
            <Label>Type</Label>
            <Select :model-value="form.type" :disabled="isSoaRecord" @update:model-value="onRecordTypeChange">
              <SelectTrigger :class="isSoaRecord && 'opacity-60'">
                <SelectValue placeholder="Select record type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem v-if="isSoaRecord" value="SOA">SOA</SelectItem>
                <SelectItem v-for="recordType in RECORD_TYPES" :key="recordType" :value="recordType">
                  {{ recordType }}
                </SelectItem>
              </SelectContent>
            </Select>
          </div>

          <!-- Simple content types: A, AAAA, CNAME, PTR, NS, OPENPGPKEY, TXT -->
          <div v-if="isSimpleContentType(form.type)" class="space-y-2">
            <Label for="record-content">
              {{ form.type === 'TXT' ? 'Content' : form.type === 'A' || form.type === 'AAAA' ? 'Address' : 'Target' }}
            </Label>
            <Textarea v-if="isMultilineContentType(form.type)" id="record-content" v-model="form.content"
              :placeholder="contentPlaceholder(form.type)"
              :class="recordFormErrors.value && 'border-destructive focus-visible:ring-destructive'" />
            <Input v-else id="record-content" v-model="form.content" :placeholder="contentPlaceholder(form.type)"
              :class="recordFormErrors.value && 'border-destructive focus-visible:ring-destructive'" />
            <p v-if="recordFormErrors.value" class="text-xs text-destructive">
              {{ recordFormErrors.value }}
            </p>
          </div>

          <!-- MX -->
          <template v-if="form.type === 'MX'">
            <div class="space-y-2">
              <Label for="record-mx-priority">Priority</Label>
              <Input id="record-mx-priority" v-model.number="form.mxPriority" type="number" min="0"
                :class="recordFormErrors.mxPriority && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.mxPriority" class="text-xs text-destructive">
                {{ recordFormErrors.mxPriority }}
              </p>
            </div>
            <div class="space-y-2">
              <Label for="record-mx-target">Mail Server Target</Label>
              <Input id="record-mx-target" v-model="form.mxTarget" placeholder="mail.example.com"
                :class="recordFormErrors.mxTarget && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.mxTarget" class="text-xs text-destructive">
                {{ recordFormErrors.mxTarget }}
              </p>
            </div>
          </template>

          <!-- SRV -->
          <template v-if="form.type === 'SRV'">
            <div class="grid gap-4 sm:grid-cols-3">
              <div class="space-y-2">
                <Label for="record-srv-priority">Priority</Label>
                <Input id="record-srv-priority" v-model.number="form.srvPriority" type="number" min="0"
                  :class="recordFormErrors.srvPriority && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.srvPriority" class="text-xs text-destructive">
                  {{ recordFormErrors.srvPriority }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-srv-weight">Weight</Label>
                <Input id="record-srv-weight" v-model.number="form.srvWeight" type="number" min="0"
                  :class="recordFormErrors.srvWeight && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.srvWeight" class="text-xs text-destructive">
                  {{ recordFormErrors.srvWeight }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-srv-port">Port</Label>
                <Input id="record-srv-port" v-model.number="form.srvPort" type="number" min="1" max="65535"
                  :class="recordFormErrors.srvPort && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.srvPort" class="text-xs text-destructive">
                  {{ recordFormErrors.srvPort }}
                </p>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-srv-target">Target</Label>
              <Input id="record-srv-target" v-model="form.srvTarget" placeholder="sip.example.com"
                :class="recordFormErrors.srvTarget && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.srvTarget" class="text-xs text-destructive">
                {{ recordFormErrors.srvTarget }}
              </p>
            </div>
          </template>

          <!-- CAA -->
          <template v-if="form.type === 'CAA'">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label>Tag</Label>
                <Select :model-value="form.caaTag" @update:model-value="setSelectString('caaTag', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Select tag" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in CAA_TAGS" :key="opt.value" :value="opt.value">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label for="record-caa-flags">Flags</Label>
                <Input id="record-caa-flags" v-model.number="form.caaFlags" type="number" min="0" max="255" />
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-caa-value">Value</Label>
              <Input id="record-caa-value" v-model="form.caaValue" placeholder="letsencrypt.org"
                :class="recordFormErrors.caaValue && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.caaValue" class="text-xs text-destructive">
                {{ recordFormErrors.caaValue }}
              </p>
            </div>
          </template>

          <!-- DS -->
          <template v-if="form.type === 'DS'">
            <div class="space-y-2">
              <Label for="record-ds-key-tag">Key Tag</Label>
              <Input id="record-ds-key-tag" v-model.number="form.dsKeyTag" type="number" min="0" max="65535" />
            </div>
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label>Algorithm</Label>
                <Select :model-value="String(form.dsAlgorithm)"
                  @update:model-value="setSelectNumber('dsAlgorithm', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Select algorithm" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DNSSEC_ALGORITHMS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Digest Type</Label>
                <Select :model-value="String(form.dsDigestType)"
                  @update:model-value="setSelectNumber('dsDigestType', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Select digest type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DS_DIGEST_TYPES" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-ds-digest">Digest</Label>
              <Input id="record-ds-digest" v-model="form.dsDigest" placeholder="Hex digest" class="font-mono text-xs"
                :class="recordFormErrors.dsDigest && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.dsDigest" class="text-xs text-destructive">
                {{ recordFormErrors.dsDigest }}
              </p>
            </div>
          </template>

          <!-- SSHFP -->
          <template v-if="form.type === 'SSHFP'">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label>Algorithm</Label>
                <Select :model-value="String(form.sshfpAlgorithm)"
                  @update:model-value="setSelectNumber('sshfpAlgorithm', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Select algorithm" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in SSHFP_ALGORITHMS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Type</Label>
                <Select :model-value="String(form.sshfpType)"
                  @update:model-value="setSelectNumber('sshfpType', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Select fingerprint type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in SSHFP_TYPES" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-sshfp-fingerprint">Fingerprint</Label>
              <Input id="record-sshfp-fingerprint" v-model="form.sshfpFingerprint" placeholder="Hex fingerprint"
                class="font-mono text-xs"
                :class="recordFormErrors.sshfpFingerprint && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.sshfpFingerprint" class="text-xs text-destructive">
                {{ recordFormErrors.sshfpFingerprint }}
              </p>
            </div>
          </template>

          <!-- TLSA / SMIMEA -->
          <template v-if="isDaneType(form.type)">
            <div class="grid gap-4 sm:grid-cols-3">
              <div class="space-y-2">
                <Label>Usage</Label>
                <Select :model-value="String(form.daneUsage)"
                  @update:model-value="setSelectNumber('daneUsage', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Usage" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DANE_USAGES" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Selector</Label>
                <Select :model-value="String(form.daneSelector)"
                  @update:model-value="setSelectNumber('daneSelector', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Selector" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DANE_SELECTORS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Matching Type</Label>
                <Select :model-value="String(form.daneMatchingType)"
                  @update:model-value="setSelectNumber('daneMatchingType', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Matching type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DANE_MATCHING_TYPES" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-dane-cert">Certificate / Data</Label>
              <Textarea id="record-dane-cert" v-model="form.daneCertificate"
                placeholder="Hex certificate association data" class="font-mono text-xs"
                :class="recordFormErrors.daneCertificate && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.daneCertificate" class="text-xs text-destructive">
                {{ recordFormErrors.daneCertificate }}
              </p>
            </div>
          </template>

          <!-- DNSKEY -->
          <template v-if="form.type === 'DNSKEY'">
            <div class="grid gap-4 sm:grid-cols-3">
              <div class="space-y-2">
                <Label>Flags</Label>
                <Select :model-value="String(form.dnskeyFlags)"
                  @update:model-value="setSelectNumber('dnskeyFlags', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Flags" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DNSKEY_FLAGS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Protocol</Label>
                <Select :model-value="String(form.dnskeyProtocol)"
                  @update:model-value="setSelectNumber('dnskeyProtocol', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Protocol" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DNSKEY_PROTOCOLS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label>Algorithm</Label>
                <Select :model-value="String(form.dnskeyAlgorithm)"
                  @update:model-value="setSelectNumber('dnskeyAlgorithm', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Algorithm" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DNSSEC_ALGORITHMS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-dnskey-key">Public Key</Label>
              <Textarea id="record-dnskey-key" v-model="form.dnskeyPublicKey" placeholder="Base64-encoded public key"
                class="font-mono text-xs"
                :class="recordFormErrors.dnskeyPublicKey && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.dnskeyPublicKey" class="text-xs text-destructive">
                {{ recordFormErrors.dnskeyPublicKey }}
              </p>
            </div>
          </template>

          <!-- HTTPS / SVCB -->
          <template v-if="form.type === 'HTTPS' || form.type === 'SVCB'">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-svc-priority">Priority</Label>
                <Input id="record-svc-priority" v-model.number="form.svcPriority" type="number" min="0" />
              </div>
              <div class="space-y-2">
                <Label for="record-svc-target">Target</Label>
                <Input id="record-svc-target" v-model="form.svcTarget" placeholder=". or hostname"
                  :class="recordFormErrors.svcTarget && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.svcTarget" class="text-xs text-destructive">
                  {{ recordFormErrors.svcTarget }}
                </p>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-svc-params">Parameters (optional)</Label>
              <Input id="record-svc-params" v-model="form.svcParams" placeholder="alpn=h2,h3 ipv4hint=192.0.2.1" />
              <p class="text-xs text-muted-foreground">
                Space-separated SvcParams (e.g. alpn, port, ipv4hint).
              </p>
            </div>
          </template>

          <!-- CERT -->
          <template v-if="form.type === 'CERT'">
            <div class="grid gap-4 sm:grid-cols-3">
              <div class="space-y-2">
                <Label>Type</Label>
                <Select :model-value="String(form.certType)" @update:model-value="setSelectNumber('certType', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Certificate type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in CERT_TYPES" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div class="space-y-2">
                <Label for="record-cert-key-tag">Key Tag</Label>
                <Input id="record-cert-key-tag" v-model.number="form.certKeyTag" type="number" min="0" />
              </div>
              <div class="space-y-2">
                <Label>Algorithm</Label>
                <Select :model-value="String(form.certAlgorithm)"
                  @update:model-value="setSelectNumber('certAlgorithm', $event)">
                  <SelectTrigger>
                    <SelectValue placeholder="Algorithm" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in DNSSEC_ALGORITHMS" :key="opt.value" :value="String(opt.value)">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-cert-data">Certificate / Data</Label>
              <Textarea id="record-cert-data" v-model="form.certData" placeholder="Hex certificate data"
                class="font-mono text-xs"
                :class="recordFormErrors.certData && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.certData" class="text-xs text-destructive">
                {{ recordFormErrors.certData }}
              </p>
            </div>
          </template>

          <!-- NAPTR -->
          <template v-if="form.type === 'NAPTR'">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-naptr-order">Order</Label>
                <Input id="record-naptr-order" v-model.number="form.naptrOrder" type="number" min="0" />
              </div>
              <div class="space-y-2">
                <Label for="record-naptr-preference">Preference</Label>
                <Input id="record-naptr-preference" v-model.number="form.naptrPreference" type="number" min="0" />
              </div>
            </div>
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-naptr-flags">Flags</Label>
                <Input id="record-naptr-flags" v-model="form.naptrFlags" placeholder="u"
                  :class="recordFormErrors.naptrFlags && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.naptrFlags" class="text-xs text-destructive">
                  {{ recordFormErrors.naptrFlags }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-naptr-service">Service</Label>
                <Input id="record-naptr-service" v-model="form.naptrService" placeholder="sip+E2U"
                  :class="recordFormErrors.naptrService && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.naptrService" class="text-xs text-destructive">
                  {{ recordFormErrors.naptrService }}
                </p>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-naptr-regexp">Regular Expression</Label>
              <Input id="record-naptr-regexp" v-model="form.naptrRegexp" placeholder="!^.*$!sip:info@example.com!"
                :class="recordFormErrors.naptrRegexp && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.naptrRegexp" class="text-xs text-destructive">
                {{ recordFormErrors.naptrRegexp }}
              </p>
            </div>
            <div class="space-y-2">
              <Label for="record-naptr-replacement">Replacement</Label>
              <Input id="record-naptr-replacement" v-model="form.naptrReplacement" placeholder=". or hostname"
                :class="recordFormErrors.naptrReplacement && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.naptrReplacement" class="text-xs text-destructive">
                {{ recordFormErrors.naptrReplacement }}
              </p>
            </div>
          </template>

          <!-- LOC -->
          <template v-if="form.type === 'LOC'">
            <p class="text-xs font-medium text-muted-foreground">Latitude</p>
            <div class="grid gap-4 sm:grid-cols-4">
              <div class="space-y-2">
                <Label for="record-loc-lat-deg">Degrees</Label>
                <Input id="record-loc-lat-deg" v-model.number="form.locLatDeg" type="number" min="0" max="90" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-lat-min">Minutes</Label>
                <Input id="record-loc-lat-min" v-model.number="form.locLatMin" type="number" min="0" max="59" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-lat-sec">Seconds</Label>
                <Input id="record-loc-lat-sec" v-model="form.locLatSec" placeholder="0.000" />
              </div>
              <div class="space-y-2">
                <Label>Hemisphere</Label>
                <Select :model-value="form.locLatHem" @update:model-value="setSelectString('locLatHem', $event)">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in LOC_HEMISPHERES.filter((h) => h.value === 'N' || h.value === 'S')"
                      :key="opt.value" :value="opt.value">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <p class="text-xs font-medium text-muted-foreground">Longitude</p>
            <div class="grid gap-4 sm:grid-cols-4">
              <div class="space-y-2">
                <Label for="record-loc-lon-deg">Degrees</Label>
                <Input id="record-loc-lon-deg" v-model.number="form.locLonDeg" type="number" min="0" max="180" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-lon-min">Minutes</Label>
                <Input id="record-loc-lon-min" v-model.number="form.locLonMin" type="number" min="0" max="59" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-lon-sec">Seconds</Label>
                <Input id="record-loc-lon-sec" v-model="form.locLonSec" placeholder="0.000" />
              </div>
              <div class="space-y-2">
                <Label>Hemisphere</Label>
                <Select :model-value="form.locLonHem" @update:model-value="setSelectString('locLonHem', $event)">
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="opt in LOC_HEMISPHERES.filter((h) => h.value === 'E' || h.value === 'W')"
                      :key="opt.value" :value="opt.value">
                      {{ opt.label }}
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-loc-alt">Altitude</Label>
                <Input id="record-loc-alt" v-model="form.locAltitude" placeholder="0.00m" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-size">Size</Label>
                <Input id="record-loc-size" v-model="form.locSize" placeholder="1m" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-horiz">Horizontal Precision</Label>
                <Input id="record-loc-horiz" v-model="form.locHorizPre" placeholder="10000m" />
              </div>
              <div class="space-y-2">
                <Label for="record-loc-vert">Vertical Precision</Label>
                <Input id="record-loc-vert" v-model="form.locVertPre" placeholder="10m" />
              </div>
            </div>
          </template>

          <!-- URI -->
          <template v-if="form.type === 'URI'">
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-uri-priority">Priority</Label>
                <Input id="record-uri-priority" v-model.number="form.uriPriority" type="number" min="0" />
              </div>
              <div class="space-y-2">
                <Label for="record-uri-weight">Weight</Label>
                <Input id="record-uri-weight" v-model.number="form.uriWeight" type="number" min="0" />
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-uri-target">Target URI</Label>
              <Input id="record-uri-target" v-model="form.uriTarget" placeholder="https://example.com/path"
                :class="recordFormErrors.uriTarget && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.uriTarget" class="text-xs text-destructive">
                {{ recordFormErrors.uriTarget }}
              </p>
            </div>
          </template>

          <!-- SOA -->
          <template v-if="form.type === 'SOA'">
            <div class="space-y-2">
              <Label for="record-soa-primary-ns">Primary NS (MNAME)</Label>
              <Input id="record-soa-primary-ns" v-model="form.soaPrimaryNS" placeholder="ns1.example.com"
                :class="recordFormErrors.soaPrimaryNS && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.soaPrimaryNS" class="text-xs text-destructive">
                {{ recordFormErrors.soaPrimaryNS }}
              </p>
            </div>
            <div class="space-y-2">
              <Label for="record-soa-admin-email">Admin Email (RNAME)</Label>
              <Input id="record-soa-admin-email" v-model="form.soaAdminEmail" placeholder="hostmaster.example.com"
                :class="recordFormErrors.soaAdminEmail && 'border-destructive focus-visible:ring-destructive'" />
              <p v-if="recordFormErrors.soaAdminEmail" class="text-xs text-destructive">
                {{ recordFormErrors.soaAdminEmail }}
              </p>
            </div>
            <div class="space-y-2">
              <Label for="record-soa-serial">Serial</Label>
              <Input id="record-soa-serial" :model-value="String(form.soaSerial)" readonly class="bg-muted" />
              <p class="text-xs text-muted-foreground">
                Serial is managed automatically by the zone and cannot be edited here.
              </p>
            </div>
            <div class="grid gap-4 sm:grid-cols-2">
              <div class="space-y-2">
                <Label for="record-soa-refresh">Refresh</Label>
                <Input id="record-soa-refresh" v-model="form.soaRefresh" placeholder="1h"
                  :class="recordFormErrors.soaRefresh && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.soaRefresh" class="text-xs text-destructive">
                  {{ recordFormErrors.soaRefresh }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-soa-retry">Retry</Label>
                <Input id="record-soa-retry" v-model="form.soaRetry" placeholder="10m"
                  :class="recordFormErrors.soaRetry && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.soaRetry" class="text-xs text-destructive">
                  {{ recordFormErrors.soaRetry }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-soa-expire">Expire</Label>
                <Input id="record-soa-expire" v-model="form.soaExpire" placeholder="1d"
                  :class="recordFormErrors.soaExpire && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.soaExpire" class="text-xs text-destructive">
                  {{ recordFormErrors.soaExpire }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-soa-minimum">Minimum TTL</Label>
                <Input id="record-soa-minimum" v-model="form.soaMinimumTTL" placeholder="5m"
                  :class="recordFormErrors.soaMinimumTTL && 'border-destructive focus-visible:ring-destructive'" />
                <p v-if="recordFormErrors.soaMinimumTTL" class="text-xs text-destructive">
                  {{ recordFormErrors.soaMinimumTTL }}
                </p>
              </div>
            </div>
          </template>

          <div class="space-y-2">
            <Label for="record-ttl">TTL</Label>
            <Input id="record-ttl" v-model="form.ttl" placeholder="3600, 5m, 1h, 1d"
              :class="recordFormErrors.ttl && 'border-destructive focus-visible:ring-destructive'"
              :aria-invalid="recordFormErrors.ttl ? true : undefined"
              :aria-describedby="recordFormErrors.ttl ? 'record-ttl-error' : 'record-ttl-hint'" />
            <p id="record-ttl-hint" class="text-xs text-muted-foreground" :class="recordFormErrors.ttl && 'sr-only'">
              BIND-style TTL: seconds or suffixes w, d, h, m, s (e.g. 1h30m).
            </p>
            <p v-if="recordFormErrors.ttl" id="record-ttl-error" class="text-xs text-destructive">
              {{ recordFormErrors.ttl }}
            </p>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" :disabled="submitting" @click="recordDialogOpen = false">
              Cancel
            </Button>
            <Button type="submit" :disabled="submitting">
              <Loader2 v-if="submitting" class="size-4 animate-spin" />
              {{ isEditingRecord ? 'Save Changes' : 'Add Record' }}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="dnssecDialogOpen">
      <DialogContent class="max-w-lg">
        <DialogHeader>
          <DialogTitle>DNSSEC</DialogTitle>
          <DialogDescription>
            Auto-DNSSEC signs authoritative zones with ECDSAP256SHA256 (algorithm 13),
            generates NSEC denial chains, and produces a DS record for your registrar.
          </DialogDescription>
        </DialogHeader>

        <div v-if="loadingDNSSEC" class="flex items-center gap-2 py-6 text-sm text-muted-foreground">
          <Loader2 class="size-4 animate-spin" />
          Loading DNSSEC status...
        </div>

        <div v-else class="space-y-4">
          <div class="rounded-md border border-border p-3 text-sm">
            <p class="font-medium">
              Status:
              <span
                :class="dnssecStatus?.enabled ? 'text-emerald-600 dark:text-emerald-400' : 'text-muted-foreground'"
              >
                {{ dnssecStatus?.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </p>
            <p v-if="dnssecStatus?.enabled && dnssecStatus.ksk_tag" class="mt-1 text-xs text-muted-foreground">
              KSK tag {{ dnssecStatus.ksk_tag }} · ZSK tag {{ dnssecStatus.zsk_tag }} · Algorithm
              {{ dnssecStatus.algorithm }}
            </p>
          </div>

          <div v-if="dnssecStatus?.enabled && dnssecStatus.ds" class="space-y-2">
            <Label>DS record (add at your TLD registrar)</Label>
            <ClipboardText :value="dnssecStatus.ds" label="Copy DS record" />
          </div>

          <p v-else class="text-sm text-muted-foreground">
            Enable Auto-DNSSEC to generate KSK/ZSK keys, sign all RRsets, and produce a DS record
            for delegation at the parent zone.
          </p>
        </div>

        <DialogFooter class="gap-2 sm:justify-between">
          <Button
            v-if="dnssecStatus?.enabled"
            type="button"
            variant="destructive"
            :disabled="disablingDNSSEC || loadingDNSSEC || !selectedZone"
            @click="disableDNSSEC"
          >
            <Loader2 v-if="disablingDNSSEC" class="size-4 animate-spin" />
            Disable DNSSEC
          </Button>
          <div class="flex gap-2 sm:ml-auto">
          <Button type="button" variant="outline" @click="dnssecDialogOpen = false">
            Close
          </Button>
          <Button
            v-if="!dnssecStatus?.enabled"
            type="button"
            :disabled="enablingDNSSEC || loadingDNSSEC || !selectedZone"
            @click="enableDNSSEC"
          >
            <Loader2 v-if="enablingDNSSEC" class="size-4 animate-spin" />
            Enable DNSSEC
          </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
