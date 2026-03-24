<script setup lang="ts">
import { getLogs } from '@/api/logs'
import type { LogType, LogEntry } from '@/api/logs'

const { t } = useI18n()

const loading = ref(true)
const activeTab = ref<LogType>('attacks')
const logs = ref<LogEntry[]>([])
const total = ref(0)
const page = ref(1)
const perPage = ref(20)
const timeRange = ref<[string, string] | null>(null)

const tabMap: { name: LogType; labelKey: string }[] = [
  { name: 'attacks', labelKey: 'logs.attack' },
  { name: 'sniffers', labelKey: 'logs.sniffer' },
  { name: 'background', labelKey: 'logs.background' },
  { name: 'threats', labelKey: 'logs.threat' },
  { name: 'audit', labelKey: 'logs.audit' },
]

async function fetchLogs() {
  loading.value = true
  try {
    const params: {
      page?: number
      per_page?: number
      start_time?: string
      end_time?: string
    } = {
      page: page.value,
      per_page: perPage.value,
    }
    if (timeRange.value) {
      params.start_time = timeRange.value[0]
      params.end_time = timeRange.value[1]
    }
    const res = await getLogs(activeTab.value, params)
    logs.value = res.logs
    total.value = res.total
  } catch {
    logs.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function onTabChange() {
  page.value = 1
  fetchLogs()
}

function onTimeChange() {
  page.value = 1
  fetchLogs()
}

watch(page, fetchLogs)
watch(perPage, () => {
  page.value = 1
  fetchLogs()
})

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
        <el-table :data="logs" stripe>
          <el-table-column prop="timestamp" :label="t('common.time')" width="180" />
          <el-table-column prop="src_ip" :label="t('policies.srcIp')" />
          <el-table-column prop="dst_ip" :label="t('policies.dstIp')" />
          <el-table-column prop="src_mac" :label="t('common.mac')" />
          <el-table-column prop="type" :label="t('common.type')" width="120" />
          <el-table-column prop="detail" :label="t('common.description')" min-width="200" />
        </el-table>

        <div class="pagination">
          <el-pagination
            v-model:current-page="page"
            v-model:page-size="perPage"
            :total="total"
            :page-sizes="[10, 20, 50, 100]"
            layout="total, sizes, prev, pager, next"
          />
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
  justify-content: flex-end;
}
</style>
