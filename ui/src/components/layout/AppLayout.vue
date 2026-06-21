<script setup lang="ts">
import { RouterLink, RouterView, useRoute } from 'vue-router'
import {
  LayoutDashboard,
  List,
  ScrollText,
  Settings,
  ShieldAlert,
  ShieldBan,
} from 'lucide-vue-next'
import NotificationCenter from '@/components/NotificationCenter.vue'
import { cn } from '@/lib/utils'

const route = useRoute()

const navItems = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, exact: true },
  { to: '/zones', label: 'Zones & Records', icon: List, exact: false },
  { to: '/blocklists', label: 'Blocklists', icon: ShieldBan, exact: false },
  { to: '/logs', label: 'Logs', icon: ScrollText, exact: false },
  { to: '/audit', label: 'Audit', icon: ShieldAlert, exact: false },
  { to: '/settings', label: 'Settings', icon: Settings, exact: false },
]

function isActive(path: string, exact: boolean): boolean {
  if (exact) {
    return route.path === path
  }
  return route.path === path || route.path.startsWith(`${path}/`)
}
</script>

<template>
  <div class="flex min-h-screen bg-background">
    <aside class="flex w-56 shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
      <div class="border-b border-sidebar-border px-5 py-5">
        <p class="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          ARX DNS
        </p>
        <p class="font-heading text-lg font-semibold tracking-tight">
          Management
        </p>
      </div>

      <nav class="flex flex-1 flex-col gap-1 p-3">
        <RouterLink v-for="item in navItems" :key="item.to" :to="item.to" :class="cn(
          'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
          isActive(item.to, item.exact)
            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
            : 'text-sidebar-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground',
        )
          ">
          <component :is="item.icon" class="size-4 shrink-0" aria-hidden="true" />
          {{ item.label }}
        </RouterLink>
      </nav>
    </aside>

    <div class="flex min-w-0 flex-1 flex-col">
      <main class="flex-1 overflow-auto p-8">
        <RouterView />
      </main>
    </div>

    <NotificationCenter />
  </div>
</template>
