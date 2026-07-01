import { createRouter, createWebHistory } from 'vue-router'
import AppLayout from '@/components/layout/AppLayout.vue'

const Login = () => import('@/views/Login.vue')
const Dashboard = () => import('@/views/Dashboard.vue')
const Zones = () => import('@/views/Zones.vue')
const Blocklists = () => import('@/views/Blocklists.vue')
const Firewall = () => import('@/views/Firewall.vue')
const Logs = () => import('@/views/Logs.vue')
const Audit = () => import('@/views/Audit.vue')
const Settings = () => import('@/views/Settings.vue')

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
          path: 'firewall',
          name: 'firewall',
          component: Firewall,
        },
        {
          path: 'logs',
          name: 'logs',
          component: Logs,
        },
        {
          path: 'audit',
          name: 'audit',
          component: Audit,
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
