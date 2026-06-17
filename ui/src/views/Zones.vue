<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { Loader2, Plus, Trash2 } from 'lucide-vue-next'
import {
  ApiError,
  createZoneRecord,
  deleteZoneRecord,
  fetchZoneRecords,
  fetchZones,
  type ZoneInfo,
  type ZoneRecord,
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
import { cn } from '@/lib/utils'

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV'] as const

const zones = ref<ZoneInfo[]>([])
const selectedZone = ref<ZoneInfo | null>(null)
const records = ref<ZoneRecord[]>([])
const loadingZones = ref(true)
const loadingRecords = ref(false)
const error = ref<string | null>(null)
const dialogOpen = ref(false)
const submitting = ref(false)
const deletingId = ref<string | null>(null)

const form = ref({
  name: '',
  type: 'A' as (typeof RECORD_TYPES)[number],
  value: '',
  ttl: 3600,
})

const selectedOrigin = computed(() => selectedZone.value?.origin ?? '')

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
  }
}

function openAddDialog(): void {
  resetForm()
  dialogOpen.value = true
}

async function submitRecord(): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  submitting.value = true
  error.value = null
  try {
    await createZoneRecord(selectedZone.value.origin, {
      name: form.value.name.trim(),
      type: form.value.type,
      value: form.value.value.trim(),
      ttl: form.value.ttl,
      view: selectedZone.value.view,
    })
    dialogOpen.value = false
    resetForm()
    await Promise.all([loadZones(), loadRecords()])
  } catch (err) {
    error.value = err instanceof ApiError ? err.message : 'Failed to create record'
  } finally {
    submitting.value = false
  }
}

async function removeRecord(record: ZoneRecord): Promise<void> {
  if (!selectedZone.value) {
    return
  }

  deletingId.value = record.id
  error.value = null
  try {
    await deleteZoneRecord(
      selectedZone.value.origin,
      record.id,
      selectedZone.value.view,
    )
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

onMounted(async () => {
  await loadZones()
  await loadRecords()
})
</script>

<template>
  <div class="space-y-6">
    <div class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <h1 class="font-heading text-2xl font-semibold tracking-tight">Zones</h1>
        <p class="text-sm text-muted-foreground">
          Manage authoritative DNS zones and records.
        </p>
      </div>
      <Button
        :disabled="!selectedZone || loadingRecords"
        @click="openAddDialog"
      >
        <Plus class="size-4" />
        Add Record
      </Button>
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
          <CardTitle class="text-base">Zones</CardTitle>
          <CardDescription>Loaded authoritative zones</CardDescription>
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
                  <td class="px-3 py-2 font-mono text-xs">{{ record.name }}</td>
                  <td class="px-3 py-2">{{ record.type }}</td>
                  <td class="px-3 py-2">{{ record.ttl }}</td>
                  <td class="max-w-md truncate px-3 py-2 font-mono text-xs" :title="record.value">
                    {{ record.value }}
                  </td>
                  <td class="px-3 py-2 text-right">
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      :disabled="deletingId === record.id"
                      :aria-label="`Delete ${record.name} ${record.type}`"
                      @click="removeRecord(record)"
                    >
                      <Loader2
                        v-if="deletingId === record.id"
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
    </div>

    <Dialog v-model:open="dialogOpen">
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add DNS Record</DialogTitle>
          <DialogDescription>
            Create a new record in
            <span class="font-medium text-foreground">
              {{ selectedZone ? formatOrigin(selectedOrigin) : 'zone' }}
            </span>.
          </DialogDescription>
        </DialogHeader>

        <form class="space-y-4" @submit.prevent="submitRecord">
          <div class="space-y-2">
            <Label for="record-name">Name</Label>
            <Input
              id="record-name"
              v-model="form.name"
              placeholder="www or @"
              required
            />
          </div>

          <div class="space-y-2">
            <Label for="record-type">Type</Label>
            <select
              id="record-type"
              v-model="form.type"
              class="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              required
            >
              <option v-for="recordType in RECORD_TYPES" :key="recordType" :value="recordType">
                {{ recordType }}
              </option>
            </select>
          </div>

          <div class="space-y-2">
            <Label for="record-value">Value</Label>
            <Input
              id="record-value"
              v-model="form.value"
              placeholder="IP address or target hostname"
              required
            />
          </div>

          <div class="space-y-2">
            <Label for="record-ttl">TTL</Label>
            <Input
              id="record-ttl"
              v-model.number="form.ttl"
              type="number"
              min="1"
              required
            />
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              :disabled="submitting"
              @click="dialogOpen = false"
            >
              Cancel
            </Button>
            <Button type="submit" :disabled="submitting">
              <Loader2 v-if="submitting" class="size-4 animate-spin" />
              Add Record
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  </div>
</template>
