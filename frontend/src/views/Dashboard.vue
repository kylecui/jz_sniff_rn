<script setup lang="ts">
import { ElMessage } from 'element-plus'
import { getStats } from '@/api/stats'
import { getModules } from '@/api/system'
import { getDevices } from '@/api/discovery'
import { getDhcpAlerts, addDhcpException } from '@/api/dhcp'
import type { Stats } from '@/api/stats'
import type { ModulesResponse } from '@/api/system'
import type { DhcpAlert } from '@/api/dhcp'

const { t } = useI18n()
const router = useRouter()

const loading = ref(true)
const stats = ref<Stats>({})
const modules = ref<ModulesResponse>({ modules: [] })
const deviceTotal = ref(0)
const dhcpServers = ref<DhcpAlert[]>([])

const unprotectedDhcp = computed(() => dhcpServers.value.filter(s => !s.protected))
const protectedDhcpCount = computed(() => dhcpServers.value.filter(s => s.protected).length)
const hasMultipleDhcp = computed(() => dhcpServers.value.length > 1)

async function fetchData() {
  loading.value = true
  try {
    const [s, m, d, dhcp] = await Promise.all([
      getStats(),
      getModules(),
      getDevices(),
      getDhcpAlerts(),
    ])
    stats.value = s
    modules.value = m
    deviceTotal.value = d.total
    dhcpServers.value = dhcp.servers
  } catch {
    // errors handled per-call; stats stay at defaults
  } finally {
    loading.value = false
  }
}

async function handleAddException(ip: string) {
  try {
    await addDhcpException({ ip })
    ElMessage.success(t('common.success'))
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

onMounted(fetchData)
</script>

<template>
  <div class="dashboard">
    <h2>{{ t('dashboard.title') }}</h2>

    <el-skeleton :loading="loading" animated :count="1">
      <template #default>
        <template v-if="unprotectedDhcp.length > 0">
          <el-alert
            type="warning"
            :title="t('dhcp.alertUnprotected')"
            :description="t('dhcp.alertUnprotectedDesc')"
            show-icon
            :closable="false"
            class="dhcp-alert"
          />
          <div class="dhcp-server-list">
            <el-tag
              v-for="srv in unprotectedDhcp"
              :key="srv.mac"
              type="warning"
              class="dhcp-server-tag"
            >
              {{ srv.ip }} ({{ srv.mac }})
              <el-button type="primary" text size="small" @click="handleAddException(srv.ip)">
                {{ t('dhcp.addExemption') }}
              </el-button>
            </el-tag>
          </div>
        </template>

        <el-alert
          v-if="hasMultipleDhcp && protectedDhcpCount > 0"
          type="error"
          :title="t('dhcp.alertMultiple')"
          :description="t('dhcp.alertMultipleDesc')"
          show-icon
          :closable="false"
          class="dhcp-alert"
        />

        <el-row :gutter="16" class="stat-row">
          <el-col :span="6">
            <el-card shadow="hover" class="stat-card" @click="router.push('/discovery')">
              <el-statistic :title="t('dashboard.onlineDevices')" :value="deviceTotal" />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover" class="stat-card" @click="router.push('/guards')">
              <el-statistic
                :title="t('dashboard.activeGuards')"
                :value="(stats.guards_static ?? 0) + (stats.guards_dynamic ?? 0)"
              />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover" class="stat-card" @click="router.push('/logs')">
              <el-statistic :title="t('dashboard.attacksToday')" :value="stats.attacks_today ?? 0" />
            </el-card>
          </el-col>
          <el-col :span="6">
            <el-card shadow="hover" class="stat-card" @click="router.push('/logs')">
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
.stat-card {
  cursor: pointer;
  transition: border-color 0.2s;
}
.stat-card:hover {
  border-color: #409eff;
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
.dhcp-alert {
  margin-bottom: 12px;
}
.dhcp-server-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 16px;
}
.dhcp-server-tag {
  font-size: 13px;
}
</style>
