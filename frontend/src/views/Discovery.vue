<script setup lang="ts">
import { getDevices, getDevice, getDiscoveryConfig, setDiscoveryConfig } from '@/api/discovery'
import type { Device, DiscoveryConfig } from '@/api/discovery'

interface ConsolidatedDevice extends Device {
  _mergedMacs?: string[]
}

const { t } = useI18n()

const loading = ref(true)
const devices = ref<Device[]>([])
const drawerVisible = ref(false)
const selectedDevice = ref<ConsolidatedDevice | null>(null)
const detailLoading = ref(false)

const discoveryConfig = ref<DiscoveryConfig>({
  aggressive_mode: false,
  dhcp_probe_interval_sec: 120,
})
const configLoading = ref(false)

function ipToNum(ip: string): number {
  const parts = ip.split('.')
  return ((+parts[0]) << 24 | (+parts[1]) << 16 | (+parts[2]) << 8 | (+parts[3])) >>> 0
}

function formatTime(ts?: number): string {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString()
}

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

async function fetchConfig() {
  try {
    discoveryConfig.value = await getDiscoveryConfig()
  } catch {
    /* keep defaults */
  }
}

function macPrefix5(mac: string): string {
  return mac.split(':').slice(0, 5).join(':')
}

function macLastByte(mac: string): number {
  return parseInt(mac.split(':')[5], 16)
}

const consolidatedDevices = computed<ConsolidatedDevice[]>(() => {
  const groups = new Map<string, Device[]>()
  for (const d of devices.value) {
    const vendor = (d.vendor ?? '').trim()
    if (!vendor) {
      groups.set('_solo_' + d.mac, [d])
      continue
    }
    const key = vendor + '|' + (d.ifindex ?? d.interface ?? '') + '|' + macPrefix5(d.mac)
    const group = groups.get(key)
    if (group) {
      const last = macLastByte(d.mac)
      const adjacent = group.some(g => Math.abs(macLastByte(g.mac) - last) <= 4)
      if (adjacent) {
        group.push(d)
      } else {
        groups.set(key + '|' + d.mac, [d])
      }
    } else {
      groups.set(key, [d])
    }
  }
  return Array.from(groups.values()).map(group => {
    if (group.length === 1) {
      return { ...group[0], _mergedMacs: [group[0].mac] }
    }
    const primary = group.reduce((best, d) => {
      if (d.ip !== '0.0.0.0' && best.ip === '0.0.0.0') return d
      if (d.ip === '0.0.0.0' && best.ip !== '0.0.0.0') return best
      return (d.confidence ?? 0) > (best.confidence ?? 0) ? d : best
    })
    return {
      ...primary,
      hostname: group.find(d => d.hostname)?.hostname ?? '',
      os_class: group.find(d => d.os_class)?.os_class ?? '',
      device_class: group.find(d => d.device_class)?.device_class ?? '',
      confidence: Math.max(...group.map(d => d.confidence ?? 0)),
      signals: group.reduce((s, d) => s + (d.signals ?? 0), 0),
      first_seen: Math.min(...group.map(d => d.first_seen ?? Infinity)),
      last_seen: Math.max(...group.map(d => d.last_seen ?? 0)),
      _mergedMacs: group.map(d => d.mac),
    }
  })
})

async function handleConfigChange() {
  configLoading.value = true
  try {
    discoveryConfig.value = await setDiscoveryConfig(discoveryConfig.value)
  } catch {
    /* ignore */
  } finally {
    configLoading.value = false
  }
}

async function handleRowClick(row: ConsolidatedDevice) {
  drawerVisible.value = true
  detailLoading.value = true
  try {
    const detail = await getDevice(row.mac)
    selectedDevice.value = { ...detail, _mergedMacs: row._mergedMacs }
  } catch {
    selectedDevice.value = row
  } finally {
    detailLoading.value = false
  }
}

onMounted(() => {
  fetchDevices()
  fetchConfig()
})
</script>

<template>
  <div>
    <h2>{{ t('discovery.title') }}</h2>

    <el-card class="mb" shadow="never">
      <div class="config-row">
        <div class="config-item">
          <el-switch
            v-model="discoveryConfig.aggressive_mode"
            :loading="configLoading"
            @change="handleConfigChange"
          />
          <span class="config-label">{{ t('discovery.aggressiveMode') }}</span>
          <span class="config-desc">{{ t('discovery.aggressiveModeDesc') }}</span>
        </div>
        <div v-if="discoveryConfig.aggressive_mode" class="config-item">
          <span class="config-label">{{ t('discovery.probeInterval') }}</span>
          <el-input-number
            v-model="discoveryConfig.dhcp_probe_interval_sec"
            :min="10"
            :max="3600"
            :step="10"
            size="small"
            @change="handleConfigChange"
          />
        </div>
      </div>
    </el-card>

    <el-button type="primary" class="mb" @click="fetchDevices">
      {{ t('common.refresh') }}
    </el-button>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-table :data="consolidatedDevices" stripe @row-click="handleRowClick" style="cursor: pointer">
          <el-table-column prop="ip" :label="t('common.ip')" sortable :sort-method="(a: ConsolidatedDevice, b: ConsolidatedDevice) => ipToNum(a.ip) - ipToNum(b.ip)" />
          <el-table-column prop="mac" :label="t('common.mac')" sortable>
            <template #default="{ row }">
              {{ row.mac }}
              <el-tag v-if="row._mergedMacs && row._mergedMacs.length > 1" size="small" type="info" style="margin-left: 4px;">
                +{{ row._mergedMacs.length - 1 }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('discovery.interface')" width="120" sortable :sort-method="(a: ConsolidatedDevice, b: ConsolidatedDevice) => (a.interface || '').localeCompare(b.interface || '')">
            <template #default="{ row }">
              {{ row.interface || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="vlan" :label="t('discovery.vlan')" width="80" sortable />
          <el-table-column prop="hostname" :label="t('discovery.hostname')" sortable />
          <el-table-column prop="vendor" :label="t('discovery.vendor')" sortable />
          <el-table-column prop="os_class" :label="t('discovery.osClass')" sortable />
          <el-table-column prop="device_class" :label="t('discovery.deviceClass')" sortable />
          <el-table-column :label="t('discovery.lastSeen')" width="180" sortable :sort-method="(a: ConsolidatedDevice, b: ConsolidatedDevice) => (a.last_seen ?? 0) - (b.last_seen ?? 0)">
            <template #default="{ row }">
              {{ formatTime(row.last_seen) }}
            </template>
          </el-table-column>
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
              <el-descriptions-item :label="t('common.mac')">
                <div>{{ selectedDevice.mac }}</div>
                <div v-if="selectedDevice._mergedMacs && selectedDevice._mergedMacs.length > 1">
                  <el-tag v-for="m in selectedDevice._mergedMacs.filter((x: string) => x !== selectedDevice!.mac)" :key="m" size="small" type="info" style="margin-top: 4px; margin-right: 4px;">
                    {{ m }}
                  </el-tag>
                </div>
              </el-descriptions-item>
              <el-descriptions-item :label="t('discovery.interface')">{{ selectedDevice.interface ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.vlan')">{{ selectedDevice.vlan ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.hostname')">{{ selectedDevice.hostname ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.vendor')">{{ selectedDevice.vendor ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.osClass')">{{ selectedDevice.os_class ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.deviceClass')">{{ selectedDevice.device_class ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.confidence')">{{ selectedDevice.confidence ?? '-' }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.firstSeen')">{{ formatTime(selectedDevice.first_seen) }}</el-descriptions-item>
              <el-descriptions-item :label="t('discovery.lastSeen')">{{ formatTime(selectedDevice.last_seen) }}</el-descriptions-item>
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
.config-row {
  display: flex;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
}
.config-item {
  display: flex;
  align-items: center;
  gap: 8px;
}
.config-label {
  font-weight: 500;
  white-space: nowrap;
}
.config-desc {
  color: #909399;
  font-size: 12px;
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
