<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { getModules, reloadModule, restartDaemon } from '@/api/system'
import type { BpfModule, NetworkInterface } from '@/api/system'

const { t } = useI18n()

const loading = ref(true)
const modules = ref<BpfModule[]>([])
const interfaces = ref<NetworkInterface[]>([])

const daemons = ['sniffd', 'configd', 'collectord', 'uploadd']

async function fetchData() {
  loading.value = true
  try {
    const res = await getModules()
    modules.value = res.modules
    interfaces.value = res.interfaces ?? []
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
          <el-table :data="interfaces" stripe>
            <el-table-column prop="name" :label="t('system.interfaceName')" />
            <el-table-column prop="ifindex" :label="t('system.ifindex')" width="100" />
            <el-table-column prop="role" :label="t('system.role')" />
          </el-table>
        </el-card>

        <!-- Daemon Control -->
        <el-card class="section-card">
          <template #header>{{ t('system.daemons') }}</template>
          <el-row :gutter="16">
            <el-col v-for="d in daemons" :key="d" :span="6">
              <el-card shadow="hover" class="daemon-card">
                <div class="daemon-name">{{ d }}</div>
                <el-button type="danger" size="small" @click="handleRestart(d)">
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
  margin-bottom: 12px;
}
</style>
