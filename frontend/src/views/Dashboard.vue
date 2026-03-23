<script setup lang="ts">
import { getStats } from '@/api/stats'
import { getModules } from '@/api/system'
import { getDevices } from '@/api/discovery'
import type { Stats } from '@/api/stats'
import type { ModulesResponse } from '@/api/system'

const { t } = useI18n()

const loading = ref(true)
const stats = ref<Stats>({})
const modules = ref<ModulesResponse>({ modules: [] })
const deviceTotal = ref(0)

async function fetchData() {
  loading.value = true
  try {
    const [s, m, d] = await Promise.all([
      getStats(),
      getModules(),
      getDevices(),
    ])
    stats.value = s
    modules.value = m
    deviceTotal.value = d.total
  } catch {
    // errors handled per-call; stats stay at defaults
  } finally {
    loading.value = false
  }
}

onMounted(fetchData)
</script>

<template>
  <div class="dashboard">
    <h2>{{ t('dashboard.title') }}</h2>

    <el-skeleton :loading="loading" animated :count="1">
      <template #default>
        <el-row :gutter="16" class="stat-row">
          <el-col :span="6">
            <el-card shadow="hover">
              <el-statistic :title="t('dashboard.onlineDevices')" :value="deviceTotal" />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover">
              <el-statistic
                :title="t('dashboard.activeGuards')"
                :value="(stats.guards_static ?? 0) + (stats.guards_dynamic ?? 0)"
              />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover">
              <el-statistic :title="t('dashboard.attacksToday')" :value="stats.attacks_today ?? 0" />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover">
              <el-statistic :title="t('dashboard.threatsDetected')" :value="stats.attacks_total ?? 0" />
            </el-card>
          </el-col>
        </el-row>

        <el-card class="module-card">
          <template #header>{{ t('dashboard.moduleStatus') }}</template>
          <div class="module-tags">
            <el-tag
              v-for="mod in modules.modules"
              :key="mod.name"
              :type="mod.loaded ? 'success' : 'info'"
              class="module-tag"
            >
              {{ mod.name }} — {{ mod.loaded ? t('dashboard.loaded') : t('dashboard.unloaded') }}
            </el-tag>
            <span v-if="modules.modules.length === 0">{{ t('common.noData') }}</span>
          </div>
        </el-card>
      </template>
    </el-skeleton>
  </div>
</template>

<style scoped>
.dashboard {
  padding: 8px;
}
.stat-row {
  margin-bottom: 20px;
}
.module-card {
  margin-top: 8px;
}
.module-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.module-tag {
  font-size: 13px;
}
</style>
