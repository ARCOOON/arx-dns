<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Loader2, Pencil, Plus, Trash2 } from 'lucide-vue-next'
import {
  ApiError,
  createZone,
  createZoneRecord,
  deleteZone,
  deleteZoneRecord,
  fetchZoneRecords,
  fetchZones,
  updateZoneRecord,
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
import { cn } from '@/lib/utils'

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV'] as const
type RecordType = (typeof RECORD_TYPES)[number]

const zones = ref<ZoneInfo[]>([])
const selectedZone = ref<ZoneInfo | null>(null)
const records = ref<ZoneRecord[]>([])
const loadingZones = ref(true)
const loadingRecords = ref(false)
const error = ref<string | null>(null)
const recordDialogOpen = ref(false)
const addZoneDialogOpen = ref(false)
const deleteZoneDialogOpen = ref(false)
const deleteRecordDialogOpen = ref(false)
const submitting = ref(false)
const creatingZone = ref(false)
const deletingZone = ref(false)
const deletingId = ref<string | null>(null)
const newZoneName = ref('')
const editingRecordId = ref<string | null>(null)
const recordPendingDelete = ref<ZoneRecord | null>(null)

const form = ref({
  name: '',
  type: 'A' as RecordType,
  value: '',
  ttl: 3600,
  mxPriority: 10,
  mxTarget: '',
  srvPriority: 0,
  srvWeight: 0,
  srvPort: 5060,
  srvTarget: '',
})

type RecordFormErrors = {
  name?: string
  value?: string
  ttl?: string
  mxPriority?: string
  mxTarget?: string
  srvPriority?: string
  srvWeight?: string
  srvPort?: string
  srvTarget?: string
}

const recordFormErrors = ref<RecordFormErrors>({})

const selectedOrigin = computed(() => selectedZone.value?.origin ?? '')
const isEditingRecord = computed(() => editingRecordId.value !== null)

const fqdnPreview = computed(() => {
  return recordFqdn(form.value.name)
})

const showSimpleValue = computed(() =>
  ['A', 'AAAA', 'CNAME', 'TXT'].includes(form.value.type),
)
const showMxFields = computed(() => form.value.type === 'MX')
const showSrvFields = computed(() => form.value.type === 'SRV')

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

function buildRecordValue(): string {
  if (form.value.type === 'MX') {
    return `${form.value.mxPriority} ${form.value.mxTarget.trim()}`
  }
  if (form.value.type === 'SRV') {
    return `${form.value.srvPriority} ${form.value.srvWeight} ${form.value.srvPort} ${form.value.srvTarget.trim()}`
  }
  return form.value.value.trim()
}

function populateFormFromRecord(record: ZoneRecord): void {
  form.value.name = record.name
  form.value.type = record.type as RecordType
  form.value.ttl = record.ttl

  if (record.type === 'MX') {
    const parts = record.value.trim().split(/\s+/)
    form.value.mxPriority = Number(parts[0]) || 10
    form.value.mxTarget = parts.slice(1).join(' ')
    form.value.value = ''
    form.value.srvPriority = 0
    form.value.srvWeight = 0
    form.value.srvPort = 5060
    form.value.srvTarget = ''
    return
  }

  if (record.type === 'SRV') {
    const parts = record.value.trim().split(/\s+/)
    form.value.srvPriority = Number(parts[0]) || 0
    form.value.srvWeight = Number(parts[1]) || 0
    form.value.srvPort = Number(parts[2]) || 0
    form.value.srvTarget = parts.slice(3).join(' ')
    form.value.value = ''
    form.value.mxPriority = 10
    form.value.mxTarget = ''
    return
  }

  form.value.value = record.value
  form.value.mxPriority = 10
  form.value.mxTarget = ''
  form.value.srvPriority = 0
  form.value.srvWeight = 0
  form.value.srvPort = 5060
  form.value.srvTarget = ''
}

function validateRecordForm(): boolean {
  const errors: RecordFormErrors = {}
  const name = form.value.name.trim()

  if (!name) {
    errors.name = 'Name is required. Use @ for the zone apex.'
  } else if (name !== '@') {
    if (name.includes('..')) {
      errors.name = 'Name cannot contain consecutive dots.'
    } else if (!/^[a-zA-Z0-9_*.-]+$/.test(name)) {
      errors.name = 'Name contains invalid characters.'
    } else {
      for (const label of name.split('.')) {
        if (!label) {
          errors.name = 'Name cannot contain empty labels.'
          break
        }
        if (label.length > 63) {
          errors.name = 'Each label must be 63 characters or fewer.'
          break
        }
        if (label.startsWith('-') || label.endsWith('-')) {
          errors.name = 'Labels cannot start or end with a hyphen.'
          break
        }
      }
    }
  }

  if (form.value.type === 'MX') {
    if (!Number.isFinite(form.value.mxPriority) || form.value.mxPriority < 0) {
      errors.mxPriority = 'Priority must be 0 or greater.'
    }
    if (!form.value.mxTarget.trim()) {
      errors.mxTarget = 'Mail server target is required.'
    }
  } else if (form.value.type === 'SRV') {
    if (!Number.isFinite(form.value.srvPriority) || form.value.srvPriority < 0) {
      errors.srvPriority = 'Priority must be 0 or greater.'
    }
    if (!Number.isFinite(form.value.srvWeight) || form.value.srvWeight < 0) {
      errors.srvWeight = 'Weight must be 0 or greater.'
    }
    if (!Number.isFinite(form.value.srvPort) || form.value.srvPort < 1 || form.value.srvPort > 65535) {
      errors.srvPort = 'Port must be between 1 and 65535.'
    }
    if (!form.value.srvTarget.trim()) {
      errors.srvTarget = 'Target is required.'
    }
  } else if (!form.value.value.trim()) {
    errors.value = 'Value is required.'
  }

  if (!Number.isFinite(form.value.ttl) || form.value.ttl < 1) {
    errors.ttl = 'TTL must be at least 1.'
  }

  recordFormErrors.value = errors
  return Object.keys(errors).length === 0
}

function formatOrigin(origin: string): string {
  return origin.replace(/\.$/, '')
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
  error.value = null
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
    error.value = err instanceof ApiError ? err.message : 'Failed to load zones'
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
  error.value = null
  try {
    const response = await fetchZoneRecords(
      selectedZone.value.origin,
      selectedZone.value.view,
    )
    records.value = response.records
  } catch (err) {
    records.value = []
    error.value = err instanceof ApiError ? err.message : 'Failed to load records'
  } finally {
    loadingRecords.value = false
  }
}

function selectZone(zone: ZoneInfo): void {
  selectedZone.value = zone
}

function resetForm(): void {
  form.value = {
    name: '',
    type: 'A',
    value: '',
    ttl: 3600,
    mxPriority: 10,
    mxTarget: '',
    srvPriority: 0,
    srvWeight: 0,
    srvPort: 5060,
    srvTarget: '',
  }
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
  populateFormFromRecord(record)
  recordDialogOpen.value = true
}

function openAddZoneDialog(): void {
  newZoneName.value = ''
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
  error.value = null
  try {
    await createZone(name, 'public')
    addZoneDialogOpen.value = false
    newZoneName.value = ''
    await loadZones()
    const created = zones.value.find(
      (zone) =>
        formatOrigin(zone.origin).toLowerCase() === name.toLowerCase() &&
        zone.view === 'public',
    )
    if (created) {
      selectedZone.value = created
    }
    await loadRecords()
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'Failed to create zone'
  } finally {
    creatingZone.value = false
  }
}

async function confirmDeleteZone(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  deletingZone.value = true
  error.value = null
  try {
    await deleteZone(selectedZone.value.origin, selectedZone.value.view)
    deleteZoneDialogOpen.value = false
    selectedZone.value = null
    records.value = []
    await loadZones()
    await loadRecords()
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'Failed to delete zone'
  } finally {
    deletingZone.value = false
  }
}

async function submitRecord(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  if (!validateRecordForm()) {
    return
  }

  submitting.value = true
  error.value = null
  const payload = {
    name: form.value.name.trim(),
    type: form.value.type,
    value: buildRecordValue(),
    ttl: form.value.ttl,
    view: selectedZone.value.view,
  }

  try {
    if (isEditingRecord.value && editingRecordId.value) {
      await updateZoneRecord(
        selectedZone.value.origin,
        editingRecordId.value,
        payload,
      )
    } else {
      await createZoneRecord(selectedZone.value.origin, payload)
    }
    recordDialogOpen.value = false
    resetForm()
    await Promise.all([loadZones(), loadRecords()])
  } catch (err) {
    error.value =
      err instanceof ApiError
        ? err.message
        : isEditingRecord.value
          ? 'Failed to update record'
          : 'Failed to create record'
  } finally {
    submitting.value = false
  }
}

async function confirmDeleteRecord(): Promise<void> {
  if (!selectedZone.value || !recordPendingDelete.value) {
    return
  }

  const record = recordPendingDelete.value
  deletingId.value = record.id
  error.value = null
  try {
    await deleteZoneRecord(
      selectedZone.value.origin,
      record.id,
      selectedZone.value.view,
    )
    deleteRecordDialogOpen.value = false
    recordPendingDelete.value = null
    await Promise.all([loadZones(), loadRecords()])
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'Failed to delete record'
  } finally {
    deletingId.value = null
  }
}

watch(selectedZone, () => {
  void loadRecords()
})

watch(
  () => form.value.name,
  () => clearRecordFieldError('name'),
)

watch(
  () => form.value.value,
  () => clearRecordFieldError('value'),
)

watch(
  () => form.value.ttl,
  () => clearRecordFieldError('ttl'),
)

watch(
  () => form.value.mxPriority,
  () => clearRecordFieldError('mxPriority'),
)

watch(
  () => form.value.mxTarget,
  () => clearRecordFieldError('mxTarget'),
)

watch(
  () => form.value.srvPriority,
  () => clearRecordFieldError('srvPriority'),
)

watch(
  () => form.value.srvWeight,
  () => clearRecordFieldError('srvWeight'),
)

watch(
  () => form.value.srvPort,
  () => clearRecordFieldError('srvPort'),
)

watch(
  () => form.value.srvTarget,
  () => clearRecordFieldError('srvTarget'),
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
          :disabled="!selectedZone || deletingZone"
          @click="openDeleteZoneDialog"
        >
          <Trash2 class="size-4 text-destructive" />
          Delete Zone
        </Button>
        <Button
          :disabled="!selectedZone || loadingRecords"
          @click="openAddDialog"
        >
          <Plus class="size-4" />
          Add Record
        </Button>
      </div>
    </div>

    <p
      v-if="error"
      class="rounded-md border border-destructive/30 bg-destructive/5 px-4 py-3 text-sm text-destructive"
    >
      {{ error }}
    </p>

    <div class="grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
      <Card class="h-fit">
        <CardHeader class="pb-3">
          <div class="flex items-start justify-between gap-2">
            <div>
              <CardTitle class="text-base">Zones</CardTitle>
              <CardDescription>Loaded authoritative zones</CardDescription>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            class="mt-2 w-full"
            :disabled="creatingZone"
            @click="openAddZoneDialog"
          >
            <Plus class="size-4" />
            Add Zone
          </Button>
        </CardHeader>
        <CardContent class="p-0">
          <div v-if="loadingZones" class="flex items-center gap-2 px-4 py-6 text-sm text-muted-foreground">
            <Loader2 class="size-4 animate-spin" />
            Loading zones...
          </div>
          <div
            v-else-if="zones.length === 0"
            class="px-4 py-6 text-sm text-muted-foreground"
          >
            No zones loaded.
          </div>
          <ul v-else class="divide-y divide-border">
            <li v-for="zone in zones" :key="zoneKey(zone)">
              <button
                type="button"
                :class="
                  cn(
                    'flex w-full flex-col items-start gap-1 px-4 py-3 text-left text-sm transition-colors hover:bg-accent',
                    isSelected(zone) && 'bg-accent text-accent-foreground',
                  )
                "
                @click="selectZone(zone)"
              >
                <span class="font-medium">{{ formatOrigin(zone.origin) }}</span>
                <span class="text-xs text-muted-foreground">
                  {{ zone.view }} · {{ zone.records }} records
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
          <div
            v-if="!selectedZone"
            class="py-10 text-center text-sm text-muted-foreground"
          >
            Select a zone from the sidebar.
          </div>
          <div
            v-else-if="loadingRecords"
            class="flex items-center gap-2 py-10 text-sm text-muted-foreground"
          >
            <Loader2 class="size-4 animate-spin" />
            Loading records...
          </div>
          <div
            v-else-if="records.length === 0"
            class="py-10 text-center text-sm text-muted-foreground"
          >
            No records in this zone.
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
                <tr
                  v-for="record in records"
                  :key="record.id"
                  class="border-b border-border/70 last:border-0"
                >
                  <td class="px-3 py-2 font-mono text-xs">
                    {{ record.name }}
                    <span class="text-muted-foreground">
                      ({{ recordFqdn(record.name) }})
                    </span>
                  </td>
                  <td class="px-3 py-2">{{ record.type }}</td>
                  <td class="px-3 py-2">{{ record.ttl }}</td>
                  <td class="max-w-md truncate px-3 py-2 font-mono text-xs" :title="record.value">
                    {{ record.value }}
                  </td>
                  <td class="px-3 py-2 text-right">
                    <div class="flex justify-end gap-1">
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        :aria-label="`Edit ${record.name} ${record.type}`"
                        @click="openEditDialog(record)"
                      >
                        <Pencil class="size-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        :disabled="deletingId === record.id"
                        :aria-label="`Delete ${record.name} ${record.type}`"
                        @click="openDeleteRecordDialog(record)"
                      >
                        <Loader2
                          v-if="deletingId === record.id"
                          class="size-4 animate-spin"
                        />
                        <Trash2 v-else class="size-4 text-destructive" />
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
            <Input
              id="zone-name"
              v-model="newZoneName"
              placeholder="example.com"
              required
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="creatingZone"
              @click="addZoneDialogOpen = false"
            >
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
          <AlertDialogAction
            class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            :disabled="deletingZone"
            @click.prevent="confirmDeleteZone"
          >
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
          <AlertDialogAction
            class="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            :disabled="deletingId !== null"
            @click.prevent="confirmDeleteRecord"
          >
            <Loader2 v-if="deletingId !== null" class="size-4 animate-spin" />
            Delete Record
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    <Dialog v-model:open="recordDialogOpen">
      <DialogContent>
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
            <Input
              id="record-name"
              v-model="form.name"
              placeholder="www or @"
              :class="recordFormErrors.name && 'border-destructive focus-visible:ring-destructive'"
              :aria-invalid="recordFormErrors.name ? true : undefined"
              :aria-describedby="recordFormErrors.name ? 'record-name-error' : 'record-name-preview'"
            />
            <p
              id="record-name-preview"
              class="text-xs text-muted-foreground"
              :class="recordFormErrors.name && 'sr-only'"
            >
              Resolves to: {{ fqdnPreview || 'Enter @ for root' }}
            </p>
            <p
              v-if="recordFormErrors.name"
              id="record-name-error"
              class="text-xs text-destructive"
            >
              {{ recordFormErrors.name }}
            </p>
          </div>

          <div class="space-y-2">
            <Label for="record-type">Type</Label>
            <select
              id="record-type"
              v-model="form.type"
              class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
            >
              <option v-for="recordType in RECORD_TYPES" :key="recordType" :value="recordType">
                {{ recordType }}
              </option>
            </select>
          </div>

          <div v-if="showSimpleValue" class="space-y-2">
            <Label for="record-value">Value</Label>
            <Input
              id="record-value"
              v-model="form.value"
              :placeholder="
                form.type === 'TXT'
                  ? 'Text value or quoted string'
                  : form.type === 'A' || form.type === 'AAAA'
                    ? 'IP address'
                    : 'Target hostname'
              "
              :class="recordFormErrors.value && 'border-destructive focus-visible:ring-destructive'"
              :aria-invalid="recordFormErrors.value ? true : undefined"
              :aria-describedby="recordFormErrors.value ? 'record-value-error' : undefined"
            />
            <p
              v-if="recordFormErrors.value"
              id="record-value-error"
              class="text-xs text-destructive"
            >
              {{ recordFormErrors.value }}
            </p>
          </div>

          <template v-if="showMxFields">
            <div class="space-y-2">
              <Label for="record-mx-priority">Priority</Label>
              <Input
                id="record-mx-priority"
                v-model.number="form.mxPriority"
                type="number"
                min="0"
                :class="recordFormErrors.mxPriority && 'border-destructive focus-visible:ring-destructive'"
              />
              <p
                v-if="recordFormErrors.mxPriority"
                class="text-xs text-destructive"
              >
                {{ recordFormErrors.mxPriority }}
              </p>
            </div>
            <div class="space-y-2">
              <Label for="record-mx-target">Mail Server Target</Label>
              <Input
                id="record-mx-target"
                v-model="form.mxTarget"
                placeholder="mail.example.com"
                :class="recordFormErrors.mxTarget && 'border-destructive focus-visible:ring-destructive'"
              />
              <p
                v-if="recordFormErrors.mxTarget"
                class="text-xs text-destructive"
              >
                {{ recordFormErrors.mxTarget }}
              </p>
            </div>
          </template>

          <template v-if="showSrvFields">
            <div class="grid gap-4 sm:grid-cols-3">
              <div class="space-y-2">
                <Label for="record-srv-priority">Priority</Label>
                <Input
                  id="record-srv-priority"
                  v-model.number="form.srvPriority"
                  type="number"
                  min="0"
                  :class="recordFormErrors.srvPriority && 'border-destructive focus-visible:ring-destructive'"
                />
                <p
                  v-if="recordFormErrors.srvPriority"
                  class="text-xs text-destructive"
                >
                  {{ recordFormErrors.srvPriority }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-srv-weight">Weight</Label>
                <Input
                  id="record-srv-weight"
                  v-model.number="form.srvWeight"
                  type="number"
                  min="0"
                  :class="recordFormErrors.srvWeight && 'border-destructive focus-visible:ring-destructive'"
                />
                <p
                  v-if="recordFormErrors.srvWeight"
                  class="text-xs text-destructive"
                >
                  {{ recordFormErrors.srvWeight }}
                </p>
              </div>
              <div class="space-y-2">
                <Label for="record-srv-port">Port</Label>
                <Input
                  id="record-srv-port"
                  v-model.number="form.srvPort"
                  type="number"
                  min="1"
                  max="65535"
                  :class="recordFormErrors.srvPort && 'border-destructive focus-visible:ring-destructive'"
                />
                <p
                  v-if="recordFormErrors.srvPort"
                  class="text-xs text-destructive"
                >
                  {{ recordFormErrors.srvPort }}
                </p>
              </div>
            </div>
            <div class="space-y-2">
              <Label for="record-srv-target">Target</Label>
              <Input
                id="record-srv-target"
                v-model="form.srvTarget"
                placeholder="sip.example.com"
                :class="recordFormErrors.srvTarget && 'border-destructive focus-visible:ring-destructive'"
              />
              <p
                v-if="recordFormErrors.srvTarget"
                class="text-xs text-destructive"
              >
                {{ recordFormErrors.srvTarget }}
              </p>
            </div>
          </template>

          <div class="space-y-2">
            <Label for="record-ttl">TTL</Label>
            <Input
              id="record-ttl"
              v-model.number="form.ttl"
              type="number"
              :class="recordFormErrors.ttl && 'border-destructive focus-visible:ring-destructive'"
              :aria-invalid="recordFormErrors.ttl ? true : undefined"
              :aria-describedby="recordFormErrors.ttl ? 'record-ttl-error' : undefined"
            />
            <p
              v-if="recordFormErrors.ttl"
              id="record-ttl-error"
              class="text-xs text-destructive"
            >
              {{ recordFormErrors.ttl }}
            </p>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="submitting"
              @click="recordDialogOpen = false"
            >
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
  </div>
</template>
