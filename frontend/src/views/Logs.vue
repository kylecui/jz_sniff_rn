<script setup lang="ts">
import { getLogs } from '@/api/logs'
import type { LogType, LogEntry } from '@/api/logs'

const { t } = useI18n()

const loading = ref(true)
const activeTab = ref<LogType>('attacks')
const logs = ref<LogEntry[]>([])
const limit = ref(20)
const offset = ref(0)
const timeRange = ref<[string, string] | null>(null)

const tabMap: { name: LogType; labelKey: string }[] = [
  { name: 'attacks', labelKey: 'logs.attack' },
  { name: 'sniffers', labelKey: 'logs.sniffer' },
  { name: 'background', labelKey: 'logs.background' },
  { name: 'threats', labelKey: 'logs.threat' },
  { name: 'audit', labelKey: 'logs.audit' },
  { name: 'heartbeat', labelKey: 'logs.heartbeat' },
]

const isAttackLike = computed(() =>
  ['attacks', 'sniffers', 'background', 'threats'].includes(activeTab.value),
)
const isAudit = computed(() => activeTab.value === 'audit')
const isHeartbeat = computed(() => activeTab.value === 'heartbeat')

async function fetchLogs() {
  loading.value = true
  try {
    const params: {
      limit?: number
      offset?: number
      since?: string
      until?: string
    } = {
      limit: limit.value,
      offset: offset.value,
    }
    if (timeRange.value) {
      params.since = timeRange.value[0]
      params.until = timeRange.value[1]
    }
    const res = await getLogs(activeTab.value, params)
    logs.value = res.rows ?? []
  } catch {
    logs.value = []
  } finally {
    loading.value = false
  }
}

function onTabChange() {
  offset.value = 0
  fetchLogs()
}

function onTimeChange() {
  offset.value = 0
  fetchLogs()
}

function onPrev() {
  offset.value = Math.max(0, offset.value - limit.value)
  fetchLogs()
}

function onNext() {
  if (logs.value.length >= limit.value) {
    offset.value += limit.value
    fetchLogs()
  }
}

function formatHeartbeatSummary(data: Record<string, unknown> | undefined): string {
  if (!data) return ''
  const parts: string[] = []
  if (data.modules_loaded !== undefined) parts.push(`modules: ${data.modules_loaded}/${Number(data.modules_loaded) + Number(data.modules_failed ?? 0)}`)
  if (data.static_guards !== undefined) parts.push(`static: ${data.static_guards}`)
  if (data.dynamic_guards !== undefined) parts.push(`dynamic: ${data.dynamic_guards}`)
  if (data.online_devices !== undefined) parts.push(`devices: ${data.online_devices}`)
  if (data.uptime_sec !== undefined) parts.push(`uptime: ${data.uptime_sec}s`)
  return parts.join(', ')
}

onMounted(fetchLogs)
</script>

<template>
  <div>
    <h2>{{ t('logs.title') }}</h2>

    <div class="filter-bar">
      <span class="filter-label">{{ t('logs.timeRange') }}:</span>
      <el-date-picker
        v-model="timeRange"
        type="datetimerange"
        :start-placeholder="t('logs.startTime')"
        :end-placeholder="t('logs.endTime')"
        value-format="YYYY-MM-DDTHH:mm:ss"
        @change="onTimeChange"
      />
    </div>

    <el-tabs v-model="activeTab" @tab-change="onTabChange">
      <el-tab-pane
        v-for="tab in tabMap"
        :key="tab.name"
        :label="t(tab.labelKey)"
        :name="tab.name"
      />
    </el-tabs>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-table v-if="isAttackLike" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" sortable />
          <el-table-column prop="src_ip" :label="t('policies.srcIp')" sortable />
          <el-table-column prop="dst_ip" :label="t('policies.dstIp')" sortable />
          <el-table-column prop="src_mac" :label="t('common.mac')" sortable />
          <el-table-column prop="vlan_id" :label="t('logs.vlan')" width="80" sortable />
          <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" sortable />
          <el-table-column prop="details" :label="t('common.description')" min-width="200" />
        </el-table>

        <el-table v-else-if="isAudit" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" sortable />
          <el-table-column prop="action" :label="t('logs.auditAction')" width="180" sortable />
          <el-table-column prop="actor" :label="t('logs.auditActor')" width="100" sortable />
          <el-table-column prop="target" :label="t('logs.auditTarget')" sortable />
          <el-table-column prop="details" :label="t('common.description')" min-width="200" />
          <el-table-column prop="result" :label="t('logs.auditResult')" width="100" sortable />
        </el-table>

        <el-table v-else-if="isHeartbeat" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" sortable />
          <el-table-column :label="t('logs.heartbeatSummary')" min-width="400">
            <template #default="{ row }">
              {{ formatHeartbeatSummary(row.data) }}
            </template>
          </el-table-column>
        </el-table>

        <div class="pagination">
          <el-button :disabled="offset <= 0" @click="onPrev">{{ t('logs.prev') }}</el-button>
          <span class="page-info">{{ t('logs.showing', { from: offset + 1, to: offset + logs.length }) }}</span>
          <el-button :disabled="logs.length < limit" @click="onNext">{{ t('logs.next') }}</el-button>
        </div>
      </template>
    </el-skeleton>
  </div>
</template>

<style scoped>
.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
}
.filter-label {
  white-space: nowrap;
  font-size: 14px;
}
.pagination {
  margin-top: 16px;
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 12px;
}
.page-info {
  font-size: 13px;
  color: #666;
}
</style>
