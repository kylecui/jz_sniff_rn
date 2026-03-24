<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getConfig,
  stageConfig,
  getStaged,
  commitConfig,
  discardConfig,
  getConfigHistory,
  rollbackConfig,
} from '@/api/config'
import type { ConfigHistoryEntry } from '@/api/config'

const { t } = useI18n()

const loading = ref(true)
const configText = ref('')
const editText = ref('')
const isEditing = ref(false)
const hasStaged = ref(false)
const stagedText = ref('')
const history = ref<ConfigHistoryEntry[]>([])

async function fetchAll() {
  loading.value = true
  try {
    const [cfg, staged, hist] = await Promise.all([
      getConfig(),
      getStaged(),
      getConfigHistory(),
    ])
    const json = JSON.stringify(cfg.config, null, 2)
    configText.value = json
    editText.value = json
    hasStaged.value = staged.has_staged
    stagedText.value = staged.staged ? JSON.stringify(staged.staged, null, 2) : ''
    history.value = hist.history
  } catch {
    // keep defaults
  } finally {
    loading.value = false
  }
}

function toggleEdit() {
  if (isEditing.value) {
    // Cancel edit
    editText.value = configText.value
  }
  isEditing.value = !isEditing.value
}

async function handleStage() {
  try {
    const parsed = JSON.parse(editText.value)
    await stageConfig(parsed)
    ElMessage.success(t('common.success'))
    isEditing.value = false
    await fetchAll()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleCommit() {
  try {
    await ElMessageBox.confirm(t('config.confirmCommit'), t('common.confirm'), { type: 'warning' })
    await commitConfig()
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

async function handleDiscard() {
  try {
    await ElMessageBox.confirm(t('config.confirmDiscard'), t('common.confirm'), { type: 'warning' })
    await discardConfig()
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

async function handleRollback(version: number) {
  try {
    await ElMessageBox.confirm(t('config.confirmRollback', { version }), t('common.confirm'), { type: 'warning' })
    await rollbackConfig(version)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

onMounted(fetchAll)
</script>

<template>
  <div>
    <h2>{{ t('config.title') }}</h2>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <!-- Current Config -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.current') }}</span>
              <div>
                <el-button size="small" @click="toggleEdit">
                  {{ isEditing ? t('common.cancel') : t('config.edit') }}
                </el-button>
                <el-button v-if="isEditing" type="primary" size="small" @click="handleStage">
                  {{ t('config.stage') }}
                </el-button>
              </div>
            </div>
          </template>
          <el-input
            v-model="editText"
            type="textarea"
            :rows="14"
            :readonly="!isEditing"
            :class="{ editing: isEditing }"
          />
        </el-card>

        <!-- Staged Changes -->
        <el-card class="section-card">
          <template #header>{{ t('config.staged') }}</template>
          <template v-if="hasStaged">
            <el-input v-model="stagedText" type="textarea" :rows="8" readonly />
            <div class="staged-actions">
              <el-button type="primary" size="small" @click="handleCommit">
                {{ t('config.commit') }}
              </el-button>
              <el-button type="warning" size="small" @click="handleDiscard">
                {{ t('config.discard') }}
              </el-button>
            </div>
          </template>
          <el-empty v-else :description="t('config.noStaged')" :image-size="60" />
        </el-card>

        <!-- History -->
        <el-card class="section-card">
          <template #header>{{ t('config.history') }}</template>
          <el-table :data="history" stripe>
            <el-table-column prop="version" :label="t('config.version')" width="100" />
            <el-table-column prop="applied_at" :label="t('config.appliedAt')" />
            <el-table-column :label="t('common.action')" width="120">
              <template #default="{ row }">
                <el-button type="warning" text size="small" @click="handleRollback(row.version)">
                  {{ t('config.rollback') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>
      </template>
    </el-skeleton>
  </div>
</template>

<style scoped>
.section-card {
  margin-bottom: 16px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.staged-actions {
  margin-top: 12px;
  display: flex;
  gap: 8px;
}
.editing :deep(textarea) {
  border-color: #409eff;
  background: #fafafa;
}
</style>
