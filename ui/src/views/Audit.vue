<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { Activity, Info, Loader2 } from 'lucide-vue-next'
import { fetchAuditLogs, type AuditLogEntry } from '@/api/audit'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { notify } from '@/composables/useNotifications'
import { parseApiError } from '@/utils/apiError'
import {
  auditDetailRows,
  formatAuditAction,
  type FormattedAuditEntry,
} from '@/utils/auditFormatting'

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

function formatEntry(entry: AuditLogEntry): FormattedAuditEntry {
  return formatAuditAction(entry.action, entry.details)
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
  <TooltipProvider>
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
                  <td class="px-4 py-3">
                    <Tooltip>
                      <TooltipTrigger as-child>
                        <button
                          type="button"
                          class="inline-flex items-center gap-1.5 font-medium text-foreground underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                        >
                          {{ formatEntry(entry).label }}
                          <Info class="size-3.5 text-muted-foreground" aria-hidden="true" />
                          <span class="sr-only">View technical details</span>
                        </button>
                      </TooltipTrigger>
                      <TooltipContent class="max-w-sm p-3">
                        <dl class="space-y-1.5 font-mono text-xs">
                          <div
                            v-for="row in auditDetailRows(formatEntry(entry).details)"
                            :key="row.key"
                            class="flex gap-2"
                          >
                            <dt class="shrink-0 text-neutral-400">{{ row.key }}:</dt>
                            <dd class="break-all text-neutral-100">{{ row.value }}</dd>
                          </div>
                        </dl>
                      </TooltipContent>
                    </Tooltip>
                  </td>
                  <td class="px-4 py-3 font-mono text-xs">
                    {{ entry.target || '—' }}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  </TooltipProvider>
</template>
