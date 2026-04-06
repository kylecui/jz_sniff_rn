<script setup lang="ts">
import {
  Monitor,
  Lock,
  Check,
  List,
  Document,
  Search,
  Setting,
  Cpu,
  WarningFilled,
} from '@element-plus/icons-vue'

const { t, locale } = useI18n({ useScope: 'global' })
const route = useRoute()

const isCollapse = ref(false)
const activeMenu = computed(() => route.path)

const menuItems = [
  { path: '/dashboard', icon: Monitor, titleKey: 'nav.dashboard' },
  { path: '/guards', icon: Lock, titleKey: 'nav.guards' },
  { path: '/whitelist', icon: Check, titleKey: 'nav.whitelist' },
  { path: '/policies', icon: List, titleKey: 'nav.policies' },
  { path: '/threats', icon: WarningFilled, titleKey: 'nav.threats' },
  { path: '/logs', icon: Document, titleKey: 'nav.logs' },
  { path: '/discovery', icon: Search, titleKey: 'nav.discovery' },
  { path: '/config', icon: Setting, titleKey: 'nav.config' },
  { path: '/system', icon: Cpu, titleKey: 'nav.system' },
]

function toggleLang(lang: string) {
  locale.value = lang
}
</script>

<template>
  <el-container class="app-layout">
    <el-aside :width="isCollapse ? '64px' : '220px'" class="app-aside">
      <div class="aside-header">
        <h1 v-show="!isCollapse" class="app-title">JZZN</h1>
        <h1 v-show="isCollapse" class="app-title">JZ</h1>
      </div>

      <el-menu
        :default-active="activeMenu"
        :collapse="isCollapse"
        :collapse-transition="false"
        router
        background-color="#001529"
        text-color="#ffffffb3"
        active-text-color="#409eff"
      >
        <el-menu-item
          v-for="item in menuItems"
          :key="item.path"
          :index="item.path"
        >
          <el-icon><component :is="item.icon" /></el-icon>
          <template #title>{{ t(item.titleKey) }}</template>
        </el-menu-item>
      </el-menu>

      <div class="aside-footer">
        <el-button
          text
          class="collapse-btn"
          @click="isCollapse = !isCollapse"
        >
          <el-icon>
            <component :is="isCollapse ? Document : List" />
          </el-icon>
        </el-button>

        <el-dropdown v-show="!isCollapse" @command="toggleLang">
          <span class="lang-trigger">
            {{ t('common.language') }}
            <el-icon class="el-icon--right"><List /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="zh-cn">中文</el-dropdown-item>
              <el-dropdown-item command="en">English</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </div>
    </el-aside>

    <el-main class="app-main">
      <RouterView />
    </el-main>
  </el-container>
</template>

<style scoped>
.app-layout {
  height: 100vh;
}

.app-aside {
  background-color: #001529;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  transition: width 0.2s;
}

.aside-header {
  padding: 16px;
  text-align: center;
  border-bottom: 1px solid #ffffff1a;
}

.app-title {
  color: #fff;
  font-size: 20px;
  margin: 0;
  white-space: nowrap;
}

.aside-footer {
  margin-top: auto;
  padding: 12px;
  border-top: 1px solid #ffffff1a;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.collapse-btn {
  color: #ffffffb3;
}

.lang-trigger {
  color: #ffffffb3;
  cursor: pointer;
  font-size: 13px;
  display: flex;
  align-items: center;
}

.app-main {
  background-color: #f5f7fa;
  overflow-y: auto;
}
</style>
