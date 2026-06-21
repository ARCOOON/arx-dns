<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Activity, Loader2 } from 'lucide-vue-next'
import { fetchAuditLogs, type AuditLogEntry } from '@/api/audit'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { notify } from '@/composables/useNotifications'
import { parseApiError } from '@/utils/apiError'

const auditLogs = ref<AuditLogEntry[]>([])
const auditLoading = ref(true)

async function loadAuditLogs(): Promise<void> {
  auditLoading.value = true
  try {
    const response = await fetchAuditLogs()
    auditLogs.value = response.logs
  } catch (err) {
    notify(parseApiError(err, 'Failed to load audit trail'), 'error')
  } finally {
    auditLoading.value = false
  }
}

function formatTimestamp(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(date)
}

const sortedAuditLogs = computed(() =>
  [...auditLogs.value].sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
  ),
)

onMounted(() => {
  void loadAuditLogs()
})
</script>

<template>
  <div class="space-y-6">
    <div class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Audit Trail</h1>
      <p class="text-sm text-muted-foreground">
        Recent management API mutations, newest first (up to 500 entries).
      </p>
    </div>

    <Card>
      <CardHeader class="flex flex-row items-center justify-between gap-4 space-y-0">
        <div class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-base">
            <Activity class="size-4 text-muted-foreground" />
            API Activity
          </CardTitle>
          <CardDescription>
            POST and DELETE operations recorded with client IP, action, and target.
          </CardDescription>
        </div>
        <Button variant="outline" size="sm" @click="loadAuditLogs">
          <Loader2 v-if="auditLoading" class="mr-1.5 size-4 animate-spin" />
          Refresh
        </Button>
      </CardHeader>
      <CardContent>
        <div
          v-if="auditLoading"
          class="flex items-center gap-2 py-10 text-sm text-muted-foreground"
        >
          <Loader2 class="size-4 animate-spin" />
          Loading audit logs…
        </div>

        <div
          v-else-if="sortedAuditLogs.length === 0"
          class="rounded-md border border-dashed px-4 py-10 text-center text-sm text-muted-foreground"
        >
          No audit events recorded yet.
        </div>

        <div v-else class="overflow-x-auto rounded-md border">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b bg-muted/40 text-left">
                <th class="px-4 py-3 font-medium">Timestamp</th>
                <th class="px-4 py-3 font-medium">Client IP</th>
                <th class="px-4 py-3 font-medium">Action</th>
                <th class="px-4 py-3 font-medium">Target</th>
                <th class="px-4 py-3 font-medium">Details</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="entry in sortedAuditLogs"
                :key="entry.id"
                class="border-b last:border-b-0"
              >
                <td class="whitespace-nowrap px-4 py-3 text-xs text-muted-foreground">
                  {{ formatTimestamp(entry.timestamp) }}
                </td>
                <td class="px-4 py-3 font-mono text-xs">{{ entry.client_ip }}</td>
                <td class="px-4 py-3">{{ entry.action }}</td>
                <td class="px-4 py-3 font-mono text-xs">
                  {{ entry.target || '—' }}
                </td>
                <td class="max-w-xs truncate px-4 py-3 text-xs text-muted-foreground">
                  {{ entry.details || '—' }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  </div>
</template>
