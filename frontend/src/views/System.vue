<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { getModules, getDaemons, getInterfaceStatus, reloadModule, restartDaemon } from '@/api/system'
import type { BpfModule, NetworkInterface, DaemonStatus, RuntimeInterface } from '@/api/system'

const { t } = useI18n()

const loading = ref(true)
const modules = ref<BpfModule[]>([])
const interfaces = ref<NetworkInterface[]>([])
const runtimeInterfaces = ref<RuntimeInterface[]>([])
const daemonList = ref<DaemonStatus[]>([])

async function fetchData() {
  loading.value = true
  try {
    const [modRes, daemonRes, ifRes] = await Promise.all([getModules(), getDaemons(), getInterfaceStatus()])
    modules.value = modRes.modules
    interfaces.value = modRes.interfaces ?? []
    daemonList.value = daemonRes.daemons
    runtimeInterfaces.value = ifRes.interfaces
  } catch {
    // keep empty
  } finally {
    loading.value = false
  }
}

async function handleReload(name: string) {
  try {
    await reloadModule(name)
    ElMessage.success(t('common.success'))
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleRestart(daemon: string) {
  try {
    await ElMessageBox.confirm(t('system.confirmRestart', { daemon }), t('common.confirm'), { type: 'warning' })
    await restartDaemon(daemon)
    ElMessage.success(t('common.success'))
    setTimeout(async () => {
      try {
        const res = await getDaemons()
        daemonList.value = res.daemons
      } catch { /* ignore */ }
    }, 1500)
  } catch {
    // cancelled or error
  }
}

onMounted(fetchData)
</script>

<template>
  <div>
    <h2>{{ t('system.title') }}</h2>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <!-- Module Status -->
        <el-card class="section-card">
          <template #header>{{ t('system.modules') }}</template>
          <el-table :data="modules" stripe>
            <el-table-column prop="name" :label="t('system.moduleName')" />
            <el-table-column prop="stage" :label="t('system.moduleStage')" width="80" />
            <el-table-column :label="t('system.moduleLoaded')" width="100">
              <template #default="{ row }">
                <el-tag :type="row.loaded ? 'success' : 'info'" size="small">
                  {{ row.loaded ? t('common.enabled') : t('common.disabled') }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('common.action')" width="120">
              <template #default="{ row }">
                <el-button text size="small" @click="handleReload(row.name)">
                  {{ t('common.refresh') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- Interface Status -->
        <el-card class="section-card">
          <template #header>{{ t('system.interfaces') }}</template>
          <el-table :data="runtimeInterfaces" stripe>
            <el-table-column prop="name" :label="t('system.interfaceName')" width="120" />
            <el-table-column prop="ifindex" :label="t('system.ifindex')" width="80" />
            <el-table-column :label="t('system.role')" width="100">
              <template #default="{ row }">
                {{ interfaces.find(i => i.name === row.name)?.role || '-' }}
              </template>
            </el-table-column>
            <el-table-column :label="t('system.ipAddress')">
              <template #default="{ row }">
                <template v-if="row.ip">
                  {{ row.ip }}
                  <span v-if="row.netmask" class="text-secondary"> / {{ row.netmask }}</span>
                </template>
                <el-tag v-else type="warning" size="small">{{ t('system.noIp') }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('system.linkState')" width="100">
              <template #default="{ row }">
                <el-tag :type="row.up && row.running ? 'success' : 'danger'" size="small">
                  {{ row.up && row.running ? 'UP' : 'DOWN' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column :label="t('system.mtu')" width="80">
              <template #default="{ row }">
                {{ row.mtu ?? '-' }}
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- Daemon Control -->
        <el-card class="section-card">
          <template #header>{{ t('system.daemons') }}</template>
          <el-row :gutter="16">
            <el-col v-for="d in daemonList" :key="d.name" :span="6">
              <el-card shadow="hover" class="daemon-card">
                <div class="daemon-name">{{ d.name }}</div>
                <div class="daemon-info">
                  <el-tag :type="d.running ? 'success' : 'danger'" size="small">
                    {{ d.running ? t('system.running') : t('system.stopped') }}
                  </el-tag>
                  <span v-if="d.pid" class="daemon-pid">{{ t('system.pid') }}: {{ d.pid }}</span>
                </div>
                <el-button type="danger" size="small" @click="handleRestart(d.name)">
                  {{ t('system.restart') }}
                </el-button>
              </el-card>
            </el-col>
          </el-row>
        </el-card>
      </template>
    </el-skeleton>
  </div>
</template>

<style scoped>
.section-card {
  margin-bottom: 16px;
}
.daemon-card {
  text-align: center;
  padding: 16px 0;
}
.daemon-name {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 8px;
}
.daemon-info {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-bottom: 12px;
}
.daemon-pid {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  font-variant-numeric: tabular-nums;
}
.text-secondary {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>
