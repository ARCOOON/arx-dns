<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { Loader2, Plus, ShieldCheck, Trash2 } from 'lucide-vue-next'
import { ApiError } from '@/api/client'
import {
  createACLRule,
  deleteACLRule,
  fetchACLRules,
  type ACLRule,
} from '@/api/settings'
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

const rules = ref<ACLRule[]>([])
const loading = ref(true)
const error = ref<string | null>(null)
const addDialogOpen = ref(false)
const newSubnet = ref('')
const newDescription = ref('')
const creating = ref(false)
const deletingId = ref<number | null>(null)

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

async function loadRules(): Promise<void> {
  loading.value = true
  error.value = null
  try {
    const response = await fetchACLRules()
    rules.value = response.rules
  } catch (err) {
    error.value = parseApiError(err, 'Failed to load ACL rules')
  } finally {
    loading.value = false
  }
}

function openAddDialog(): void {
  newSubnet.value = ''
  newDescription.value = ''
  addDialogOpen.value = true
}

async function submitAddRule(): Promise<void> {
  const subnet = newSubnet.value.trim()
  if (!subnet) {
    error.value = 'Subnet or IP address is required'
    return
  }

  creating.value = true
  error.value = null
  try {
    await createACLRule(subnet, newDescription.value)
    addDialogOpen.value = false
    await loadRules()
  } catch (err) {
    error.value = parseApiError(err, 'Failed to add ACL rule')
  } finally {
    creating.value = false
  }
}

async function removeRule(id: number): Promise<void> {
  deletingId.value = id
  error.value = null
  try {
    await deleteACLRule(id)
    await loadRules()
  } catch (err) {
    error.value = parseApiError(err, 'Failed to delete ACL rule')
  } finally {
    deletingId.value = null
  }
}

onMounted(() => {
  void loadRules()
})
</script>

<template>
  <div class="mx-auto max-w-4xl space-y-6">
    <div class="space-y-1">
      <h1 class="font-heading text-2xl font-semibold tracking-tight">Settings</h1>
      <p class="text-sm text-muted-foreground">
        Configure server security and access policies.
      </p>
    </div>

    <p
      v-if="error"
      class="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive"
    >
      {{ error }}
    </p>

    <Card>
      <CardHeader class="flex flex-row items-start justify-between gap-4 space-y-0">
        <div class="space-y-1">
          <CardTitle class="flex items-center gap-2 text-lg">
            <ShieldCheck class="size-5 text-muted-foreground" />
            Security &amp; Access (ACL)
          </CardTitle>
          <CardDescription>
            Restrict DNS queries to specific IP addresses or CIDR subnets. When no rules
            are configured, all clients are allowed.
          </CardDescription>
        </div>
        <Button size="sm" @click="openAddDialog">
          <Plus class="mr-1.5 size-4" />
          Add Subnet
        </Button>
      </CardHeader>
      <CardContent>
        <div
          v-if="loading"
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
                <th class="w-20 px-4 py-3 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="rule in rules"
                :key="rule.id"
                class="border-b last:border-b-0"
              >
                <td class="px-4 py-3 font-mono text-xs sm:text-sm">{{ rule.subnet }}</td>
                <td class="px-4 py-3 text-muted-foreground">
                  {{ rule.description || '—' }}
                </td>
                <td class="px-4 py-3 text-right">
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
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>

    <Dialog v-model:open="addDialogOpen">
      <DialogContent class="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Add Subnet</DialogTitle>
          <DialogDescription>
            Enter an IP address (e.g. 192.168.1.10) or CIDR block (e.g. 10.0.0.0/8).
          </DialogDescription>
        </DialogHeader>
        <div class="grid gap-4 py-2">
          <div class="grid gap-2">
            <Label for="acl-subnet">Subnet / IP</Label>
            <Input
              id="acl-subnet"
              v-model="newSubnet"
              placeholder="192.168.0.0/16"
              autocomplete="off"
              @keyup.enter="submitAddRule"
            />
          </div>
          <div class="grid gap-2">
            <Label for="acl-description">Description (optional)</Label>
            <Input
              id="acl-description"
              v-model="newDescription"
              placeholder="Office LAN"
              autocomplete="off"
              @keyup.enter="submitAddRule"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" @click="addDialogOpen = false">Cancel</Button>
          <Button :disabled="creating" @click="submitAddRule">
            <Loader2 v-if="creating" class="mr-1.5 size-4 animate-spin" />
            Add Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
