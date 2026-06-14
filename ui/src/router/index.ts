import { createRouter, createWebHistory } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'
import Blocklists from '@/views/Blocklists.vue'
import Dashboard from '@/views/Dashboard.vue'
import Login from '@/views/Login.vue'
import Settings from '@/views/Settings.vue'
import Zones from '@/views/Zones.vue'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: Login,
      meta: { public: true },
    },
    {
      path: '/',
      component: AppLayout,
      children: [
        {
          path: '',
          name: 'dashboard',
          component: Dashboard,
        },
        {
          path: 'zones',
          name: 'zones',
          component: Zones,
        },
        {
          path: 'blocklists',
          name: 'blocklists',
          component: Blocklists,
        },
        {
          path: 'settings',
          name: 'settings',
          component: Settings,
        },
      ],
    },
  ],
})

router.beforeEach((to) => {
  if (to.meta.public) {
    return true
  }

  const token = localStorage.getItem('arx_token')
  if (!token) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  return true
})

export default router
