import { createRouter, createWebHistory } from 'vue-router'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/',
      component: () => import('@/components/AppLayout.vue'),
      redirect: '/dashboard',
      children: [
        {
          path: 'dashboard',
          name: 'Dashboard',
          component: () => import('@/views/Dashboard.vue'),
          meta: { titleKey: 'nav.dashboard', icon: 'Monitor' },
        },
        {
          path: 'guards',
          name: 'Guards',
          component: () => import('@/views/Guards.vue'),
          meta: { titleKey: 'nav.guards', icon: 'Shield' },
        },
        {
          path: 'whitelist',
          name: 'Whitelist',
          component: () => import('@/views/Whitelist.vue'),
          meta: { titleKey: 'nav.whitelist', icon: 'Check' },
        },
        {
          path: 'policies',
          name: 'Policies',
          component: () => import('@/views/Policies.vue'),
          meta: { titleKey: 'nav.policies', icon: 'List' },
        },
        {
          path: 'threats',
          name: 'Threats',
          component: () => import('@/views/Threats.vue'),
          meta: { titleKey: 'nav.threats', icon: 'WarningFilled' },
        },
        {
          path: 'logs',
          name: 'Logs',
          component: () => import('@/views/Logs.vue'),
          meta: { titleKey: 'nav.logs', icon: 'Document' },
        },
        {
          path: 'discovery',
          name: 'Discovery',
          component: () => import('@/views/Discovery.vue'),
          meta: { titleKey: 'nav.discovery', icon: 'Search' },
        },
        {
          path: 'config',
          name: 'Config',
          component: () => import('@/views/Config.vue'),
          meta: { titleKey: 'nav.config', icon: 'Setting' },
        },
        {
          path: 'system',
          name: 'System',
          component: () => import('@/views/System.vue'),
          meta: { titleKey: 'nav.system', icon: 'Cpu' },
        },
      ],
    },
  ],
})

export default router
