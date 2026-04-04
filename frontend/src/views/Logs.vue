<script setup lang="ts">
import { getLogs, exportLogsToCSV } from '@/api/logs'
import type { LogType, LogEntry, LogQueryParams } from '@/api/logs'

const { t } = useI18n()

const loading = ref(true)
const activeTab = ref<LogType>('attacks')
const logs = ref<LogEntry[]>([])
const limit = ref(20)
const offset = ref(0)
const timeRange = ref<[string, string] | null>(null)

/* --- per-tab filters --- */
const filterSrcIp = ref('')
const filterDstIp = ref('')
const filterProtocol = ref('')
const filterSrcPort = ref<number | undefined>(undefined)
const filterDstPort = ref<number | undefined>(undefined)
const filterIp = ref('')
const filterMac = ref('')
const filterAction = ref('')

const protocolOptions = [
  { value: '', label: t('logs.filterAll') },
  { value: 'ARP', label: 'ARP' },
  { value: 'ICMP', label: 'ICMP' },
  { value: 'TCP', label: 'TCP' },
  { value: 'UDP', label: 'UDP' },
]

const tabMap: { name: LogType; labelKey: string }[] = [
  { name: 'attacks', labelKey: 'logs.attack' },
  { name: 'sniffers', labelKey: 'logs.sniffer' },
  { name: 'background', labelKey: 'logs.background' },
  { name: 'threats', labelKey: 'logs.threat' },
  { name: 'audit', labelKey: 'logs.audit' },
  { name: 'heartbeat', labelKey: 'logs.heartbeat' },
]

const isAttacks = computed(() => activeTab.value === 'attacks')
const isSniffers = computed(() => activeTab.value === 'sniffers')
const isBackground = computed(() => activeTab.value === 'background')
const isThreats = computed(() => activeTab.value === 'threats')
const isAudit = computed(() => activeTab.value === 'audit')
const isHeartbeat = computed(() => activeTab.value === 'heartbeat')

const showIpFilters = computed(() =>
  ['attacks', 'threats'].includes(activeTab.value),
)
const showProtocolFilter = computed(() =>
  ['attacks', 'threats', 'background'].includes(activeTab.value),
)
const showPortFilters = computed(() => activeTab.value === 'attacks')
const showSnifferFilters = computed(() => activeTab.value === 'sniffers')
const showActionFilter = computed(() => activeTab.value === 'audit')

function resetFilters() {
  filterSrcIp.value = ''
  filterDstIp.value = ''
  filterProtocol.value = ''
  filterSrcPort.value = undefined
  filterDstPort.value = undefined
  filterIp.value = ''
  filterMac.value = ''
  filterAction.value = ''
}

async function fetchLogs() {
  loading.value = true
  try {
    const params: LogQueryParams = {
      limit: limit.value,
      offset: offset.value,
    }
    if (timeRange.value) {
      params.since = timeRange.value[0]
      params.until = timeRange.value[1]
    }
    if (showIpFilters.value) {
      if (filterSrcIp.value) params.src_ip = filterSrcIp.value
      if (filterDstIp.value) params.dst_ip = filterDstIp.value
    }
    if (showProtocolFilter.value && filterProtocol.value) {
      params.protocol = filterProtocol.value
    }
    if (showPortFilters.value) {
      if (filterSrcPort.value) params.src_port = filterSrcPort.value
      if (filterDstPort.value) params.dst_port = filterDstPort.value
    }
    if (showSnifferFilters.value) {
      if (filterIp.value) params.ip = filterIp.value
      if (filterMac.value) params.mac = filterMac.value
    }
    if (showActionFilter.value && filterAction.value) {
      params.action = filterAction.value
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
  resetFilters()
  fetchLogs()
}

function onFilterChange() {
  offset.value = 0
  fetchLogs()
}

function onTimeChange() {
  offset.value = 0
  fetchLogs()
}

function onPageSizeChange() {
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

async function onExport() {
  /* Fetch up to 10000 rows with current filters for export */
  const params: LogQueryParams = { limit: 10000, offset: 0 }
  if (timeRange.value) {
    params.since = timeRange.value[0]
    params.until = timeRange.value[1]
  }
  if (showIpFilters.value) {
    if (filterSrcIp.value) params.src_ip = filterSrcIp.value
    if (filterDstIp.value) params.dst_ip = filterDstIp.value
  }
  if (showProtocolFilter.value && filterProtocol.value) {
    params.protocol = filterProtocol.value
  }
  if (showPortFilters.value) {
    if (filterSrcPort.value) params.src_port = filterSrcPort.value
    if (filterDstPort.value) params.dst_port = filterDstPort.value
  }
  if (showSnifferFilters.value) {
    if (filterIp.value) params.ip = filterIp.value
    if (filterMac.value) params.mac = filterMac.value
  }
  if (showActionFilter.value && filterAction.value) {
    params.action = filterAction.value
  }
  try {
    const res = await getLogs(activeTab.value, params)
    exportLogsToCSV(res.rows ?? [], activeTab.value)
  } catch {
    /* silent */
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

      <template v-if="showIpFilters">
        <el-input
          v-model="filterSrcIp"
          :placeholder="t('policies.srcIp')"
          clearable
          style="width: 150px"
          @change="onFilterChange"
        />
        <el-input
          v-model="filterDstIp"
          :placeholder="t('policies.dstIp')"
          clearable
          style="width: 150px"
          @change="onFilterChange"
        />
      </template>

      <template v-if="showProtocolFilter">
        <el-select
          v-model="filterProtocol"
          :placeholder="t('policies.protocol')"
          style="width: 110px"
          @change="onFilterChange"
        >
          <el-option
            v-for="opt in protocolOptions"
            :key="opt.value"
            :label="opt.label"
            :value="opt.value"
          />
        </el-select>
      </template>

      <template v-if="showPortFilters">
        <el-input-number
          v-model="filterSrcPort"
          :placeholder="t('policies.srcPort')"
          :min="0"
          :max="65535"
          controls-position="right"
          style="width: 130px"
          @change="onFilterChange"
        />
        <el-input-number
          v-model="filterDstPort"
          :placeholder="t('policies.dstPort')"
          :min="0"
          :max="65535"
          controls-position="right"
          style="width: 130px"
          @change="onFilterChange"
        />
      </template>

      <template v-if="showSnifferFilters">
        <el-input
          v-model="filterIp"
          :placeholder="t('common.ip')"
          clearable
          style="width: 150px"
          @change="onFilterChange"
        />
        <el-input
          v-model="filterMac"
          :placeholder="t('common.mac')"
          clearable
          style="width: 180px"
          @change="onFilterChange"
        />
      </template>

      <template v-if="showActionFilter">
        <el-input
          v-model="filterAction"
          :placeholder="t('logs.auditAction')"
          clearable
          style="width: 150px"
          @change="onFilterChange"
        />
      </template>
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
        <!-- Attack Logs -->
        <el-table v-if="isAttacks" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" sortable />
          <el-table-column prop="src_ip" :label="t('policies.srcIp')" sortable />
          <el-table-column prop="dst_ip" :label="t('policies.dstIp')" sortable />
          <el-table-column prop="src_mac" :label="t('common.mac')" sortable />
          <el-table-column prop="guard_type" :label="t('logs.guardType')" width="110" sortable />
          <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" sortable />
          <el-table-column prop="src_port" :label="t('policies.srcPort')" width="100" sortable />
          <el-table-column prop="dst_port" :label="t('policies.dstPort')" width="100" sortable />
          <el-table-column prop="vlan_id" :label="t('logs.vlan')" width="80" sortable />
          <el-table-column prop="details" :label="t('common.description')" min-width="200" />
        </el-table>

        <!-- Threat Detection -->
        <el-table v-else-if="isThreats" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" sortable />
          <el-table-column prop="src_ip" :label="t('policies.srcIp')" sortable />
          <el-table-column prop="dst_ip" :label="t('policies.dstIp')" sortable />
          <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" sortable />
          <el-table-column prop="threat_level" :label="t('logs.threatLevel')" width="110" sortable />
          <el-table-column prop="src_port" :label="t('policies.srcPort')" width="100" sortable />
          <el-table-column prop="dst_port" :label="t('policies.dstPort')" width="100" sortable />
          <el-table-column prop="vlan_id" :label="t('logs.vlan')" width="80" sortable />
          <el-table-column prop="details" :label="t('common.description')" min-width="200" />
        </el-table>

        <!-- Sniffer Detection -->
        <el-table v-else-if="isSniffers" :data="logs" stripe>
          <el-table-column prop="mac" :label="t('common.mac')" width="180" sortable />
          <el-table-column prop="ip" :label="t('common.ip')" sortable />
          <el-table-column prop="probe_ip" :label="t('logs.probeIp')" sortable />
          <el-table-column prop="response_count" :label="t('logs.responseCount')" width="120" sortable />
          <el-table-column prop="first_seen" :label="t('logs.firstSeen')" width="180" sortable />
          <el-table-column prop="last_seen" :label="t('logs.lastSeen')" width="180" sortable />
          <el-table-column prop="ifindex" :label="t('system.ifindex')" width="80" sortable />
        </el-table>

        <!-- Background Traffic -->
        <el-table v-else-if="isBackground" :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('logs.periodStart')" width="180" sortable />
          <el-table-column prop="period_end" :label="t('logs.periodEnd')" width="180" sortable />
          <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" sortable />
          <el-table-column prop="packet_count" :label="t('logs.packetCount')" width="110" sortable />
          <el-table-column prop="byte_count" :label="t('logs.byteCount')" width="110" sortable />
          <el-table-column prop="unique_sources" :label="t('logs.uniqueSources')" width="130" sortable />
          <el-table-column prop="src_ip" :label="t('policies.srcIp')" sortable />
          <el-table-column prop="dst_ip" :label="t('policies.dstIp')" sortable />
          <el-table-column prop="src_mac" :label="t('common.mac')" sortable />
          <el-table-column prop="vlan_id" :label="t('logs.vlan')" width="80" sortable />
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

          <el-select v-model="limit" style="width: 100px; margin-left: 16px" @change="onPageSizeChange">
            <el-option :value="20" label="20 / page" />
            <el-option :value="50" label="50 / page" />
            <el-option :value="100" label="100 / page" />
            <el-option :value="200" label="200 / page" />
          </el-select>

          <el-button style="margin-left: 16px" @click="onExport">
            {{ t('logs.export') }}
          </el-button>
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
  flex-wrap: wrap;
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
