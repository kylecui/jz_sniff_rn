<script setup lang="ts">
import { getDevices, getDevice } from '@/api/discovery'
import type { Device } from '@/api/discovery'

const { t } = useI18n()

const loading = ref(true)
const devices = ref<Device[]>([])
const drawerVisible = ref(false)
const selectedDevice = ref<Device | null>(null)
const detailLoading = ref(false)

async function fetchDevices() {
  loading.value = true
  try {
    const res = await getDevices()
    devices.value = res.devices
  } catch {
    devices.value = []
  } finally {
    loading.value = false
  }
}

async function handleRowClick(row: Device) {
  drawerVisible.value = true
  detailLoading.value = true
  try {
    selectedDevice.value = await getDevice(row.mac)
  } catch {
    selectedDevice.value = row
  } finally {
    detailLoading.value = false
  }
}

onMounted(fetchDevices)
</script>

<template>
  <div>
    <h2>{{ t('discovery.title') }}</h2>

    <el-button type="primary" class="mb" @click="fetchDevices">
      {{ t('common.refresh') }}
    </el-button>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-table :data="devices" stripe @row-click="handleRowClick" style="cursor: pointer">
          <el-table-column prop="ip" :label="t('common.ip')" />
          <el-table-column prop="mac" :label="t('common.mac')" />
          <el-table-column prop="vlan" :label="t('discovery.vlan')" width="80" />
          <el-table-column prop="hostname" :label="t('discovery.hostname')" />
          <el-table-column prop="vendor" :label="t('discovery.vendor')" />
          <el-table-column prop="os_guess" :label="t('discovery.osGuess')" />
          <el-table-column prop="last_seen" :label="t('discovery.lastSeen')" width="180" />
        </el-table>
      </template>
    </el-skeleton>

    <el-drawer
      v-model="drawerVisible"
      :title="t('discovery.detail')"
      direction="rtl"
      size="480px"
    >
      <el-skeleton :loading="detailLoading" animated>
        <template #default>
          <template v-if="selectedDevice">
            <el-descriptions :column="1" border>
              <el-descriptions-item :label="t('common.ip')">{{ selectedDevice.ip }}</el-descriptions-item>
              <el-descriptions-item :label="t('common.mac')">{{ selectedDevice.mac }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.vlan')">{{ selectedDevice.vlan ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.hostname')">{{ selectedDevice.hostname ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.vendor')">{{ selectedDevice.vendor ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.osGuess')">{{ selectedDevice.os_guess ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.firstSeen')">{{ selectedDevice.first_seen ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.lastSeen')">{{ selectedDevice.last_seen ?? '-' }}</el-descriptions-item>
            </el-descriptions>

            <h4 style="margin-top: 20px">{{ t('discovery.fingerprint') }}</h4>
            <pre class="fp-json">{{ JSON.stringify(selectedDevice.fingerprint, null, 2) ?? '{}' }}</pre>
          </template>
        </template>
      </el-skeleton>
    </el-drawer>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
.fp-json {
  background: #f5f7fa;
  padding: 12px;
  border-radius: 4px;
  font-size: 12px;
  overflow-x: auto;
  max-height: 400px;
}
</style>
