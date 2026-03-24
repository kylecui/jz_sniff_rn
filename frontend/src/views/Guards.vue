<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getStaticGuards,
  getDynamicGuards,
  getFrozenGuards,
  getAutoGuardStatus,
  addStaticGuard,
  deleteStaticGuard,
  deleteDynamicGuard,
  addFrozenGuard,
  deleteFrozenGuard,
  updateAutoGuardConfig,
} from '@/api/guards'
import type { Guard, FrozenGuard, AutoGuardStatus } from '@/api/guards'

const { t } = useI18n()

const activeTab = ref('static')
const loading = ref(true)

const staticGuards = ref<Guard[]>([])
const dynamicGuards = ref<Guard[]>([])
const frozenGuards = ref<FrozenGuard[]>([])
const autoStatus = ref<AutoGuardStatus>({
  max_ratio: 0, subnet_total: 0, max_allowed: 0, current_dynamic: 0,
  frozen_count: 0, static_count: 0, online_devices: 0, free_ips: 0,
  enabled: false, scan_interval: 24,
})

// Add static dialog
const showStaticDialog = ref(false)
const staticForm = reactive({ ip: '', mac: '' })
const autoMac = ref(true)

function generateMac(): string {
  const bytes = Array.from({ length: 6 }, () => Math.floor(Math.random() * 256))
  bytes[0] = (bytes[0] | 0x02) & 0xfe
  return bytes.map((b) => b.toString(16).padStart(2, '0')).join(':')
}

function onAutoMacChange(val: boolean) {
  if (val) staticForm.mac = generateMac()
  else staticForm.mac = ''
}

function resetStaticForm() {
  staticForm.ip = ''
  autoMac.value = true
  staticForm.mac = generateMac()
}

// Add frozen dialog
const showFrozenDialog = ref(false)
const frozenForm = reactive({ ip: '' })

// Auto config form
const autoConfigForm = reactive({
  enabled: false,
  max_ratio: 0,
  scan_interval: 24,
})
const savingConfig = ref(false)

function syncAutoConfigForm() {
  autoConfigForm.enabled = autoStatus.value.enabled
  autoConfigForm.max_ratio = autoStatus.value.max_ratio
  autoConfigForm.scan_interval = autoStatus.value.scan_interval
}

async function fetchAll() {
  loading.value = true
  try {
    const [s, d, f, a] = await Promise.all([
      getStaticGuards(),
      getDynamicGuards(),
      getFrozenGuards(),
      getAutoGuardStatus(),
    ])
    staticGuards.value = s.guards
    dynamicGuards.value = d.guards
    frozenGuards.value = f.frozen_ips
    autoStatus.value = a
    syncAutoConfigForm()
  } catch {
    // keep defaults
  } finally {
    loading.value = false
  }
}

async function handleAddStatic() {
  try {
    await addStaticGuard({ ip: staticForm.ip, mac: staticForm.mac || undefined })
    ElMessage.success(t('common.success'))
    showStaticDialog.value = false
    resetStaticForm()
    await fetchAll()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDeleteStatic(ip: string) {
  try {
    await ElMessageBox.confirm(t('guards.confirmDelete', { ip }), t('common.confirm'), { type: 'warning' })
    await deleteStaticGuard(ip)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

async function handleDeleteDynamic(ip: string) {
  try {
    await ElMessageBox.confirm(t('guards.confirmDelete', { ip }), t('common.confirm'), { type: 'warning' })
    await deleteDynamicGuard(ip)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

async function handleAddFrozen() {
  try {
    await addFrozenGuard({ ip: frozenForm.ip })
    ElMessage.success(t('common.success'))
    showFrozenDialog.value = false
    frozenForm.ip = ''
    await fetchAll()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDeleteFrozen(ip: string) {
  try {
    await ElMessageBox.confirm(t('guards.confirmDeleteFrozen', { ip }), t('common.confirm'), { type: 'warning' })
    await deleteFrozenGuard(ip)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

async function handleSaveAutoConfig() {
  savingConfig.value = true
  try {
    const result = await updateAutoGuardConfig({
      enabled: autoConfigForm.enabled,
      max_ratio: autoConfigForm.max_ratio,
      scan_interval: autoConfigForm.scan_interval,
    })
    autoStatus.value = result
    syncAutoConfigForm()
    ElMessage.success(t('common.success'))
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  } finally {
    savingConfig.value = false
  }
}

onMounted(fetchAll)
</script>

<template>
  <div>
    <h2>{{ t('guards.title') }}</h2>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-tabs v-model="activeTab">
          <!-- Static Guards -->
          <el-tab-pane :label="t('guards.static')" name="static">
            <el-button type="primary" class="mb" @click="showStaticDialog = true">
              {{ t('guards.addStatic') }}
            </el-button>
            <el-table :data="staticGuards" stripe>
              <el-table-column prop="ip" :label="t('guards.ip')" />
              <el-table-column prop="mac" :label="t('guards.mac')" />
              <el-table-column prop="source" :label="t('guards.source')" />
              <el-table-column prop="created_at" :label="t('common.time')" />
              <el-table-column :label="t('common.action')" width="120">
                <template #default="{ row }">
                  <el-button type="danger" text size="small" @click="handleDeleteStatic(row.ip)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- Dynamic Guards -->
          <el-tab-pane :label="t('guards.dynamic')" name="dynamic">
            <el-table :data="dynamicGuards" stripe>
              <el-table-column prop="ip" :label="t('guards.ip')" />
              <el-table-column prop="mac" :label="t('guards.mac')" />
              <el-table-column prop="source" :label="t('guards.source')" />
              <el-table-column prop="created_at" :label="t('common.time')" />
              <el-table-column :label="t('common.action')" width="120">
                <template #default="{ row }">
                  <el-button type="danger" text size="small" @click="handleDeleteDynamic(row.ip)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- Frozen IPs -->
          <el-tab-pane :label="t('guards.frozen')" name="frozen">
            <el-button type="primary" class="mb" @click="showFrozenDialog = true">
              {{ t('guards.addFrozen') }}
            </el-button>
            <el-table :data="frozenGuards" stripe>
              <el-table-column prop="ip" :label="t('common.ip')" />
              <el-table-column prop="reason" :label="t('common.description')" />
              <el-table-column prop="created_at" :label="t('common.time')" />
              <el-table-column :label="t('common.action')" width="120">
                <template #default="{ row }">
                  <el-button type="danger" text size="small" @click="handleDeleteFrozen(row.ip)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>

        <!-- Auto-deploy config & status -->
        <el-card class="auto-card">
          <template #header>{{ t('guards.autoStatus') }}</template>
          <el-form label-width="140px" @submit.prevent="handleSaveAutoConfig">
            <el-form-item :label="t('guards.autoEnabled')">
              <el-switch v-model="autoConfigForm.enabled" />
            </el-form-item>
            <el-form-item :label="t('guards.maxRatio')">
              <el-slider v-model="autoConfigForm.max_ratio" :min="0" :max="100" :step="5" show-input />
            </el-form-item>
            <el-form-item :label="t('guards.scanInterval')">
              <el-input-number v-model="autoConfigForm.scan_interval" :min="1" :max="720" />
              <span class="unit-label">{{ t('guards.hours') }}</span>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="savingConfig" @click="handleSaveAutoConfig">
                {{ t('common.save') }}
              </el-button>
            </el-form-item>
          </el-form>
          <el-divider />
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item :label="t('guards.maxAllowed')">
              {{ autoStatus.max_allowed }} / {{ autoStatus.subnet_total }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('guards.currentDynamic')">
              {{ autoStatus.current_dynamic }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('guards.staticCount')">
              {{ autoStatus.static_count }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('guards.frozenCount')">
              {{ autoStatus.frozen_count }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('guards.onlineDevices')">
              {{ autoStatus.online_devices }}
            </el-descriptions-item>
            <el-descriptions-item :label="t('guards.freeIps')">
              {{ autoStatus.free_ips }}
            </el-descriptions-item>
          </el-descriptions>
        </el-card>
      </template>
    </el-skeleton>

    <!-- Add Static Dialog -->
    <el-dialog v-model="showStaticDialog" :title="t('guards.addStatic')" width="420px" @open="resetStaticForm">
      <el-form label-width="100px" @submit.prevent="handleAddStatic">
        <el-form-item :label="t('guards.ip')">
          <el-input v-model="staticForm.ip" placeholder="e.g. 10.0.1.50" />
        </el-form-item>
        <el-form-item :label="t('guards.mac')">
          <el-checkbox v-model="autoMac" :label="t('guards.autoMac')" @change="onAutoMacChange" />
        </el-form-item>
        <el-form-item v-if="autoMac" :label="t('guards.generatedMac')">
          <el-input :model-value="staticForm.mac" readonly>
            <template #append>
              <el-button @click="staticForm.mac = generateMac()">{{ t('guards.regenerate') }}</el-button>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item v-else :label="t('guards.mac')">
          <el-input v-model="staticForm.mac" placeholder="aa:bb:cc:dd:ee:ff" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showStaticDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleAddStatic">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>

    <!-- Add Frozen Dialog -->
    <el-dialog v-model="showFrozenDialog" :title="t('guards.addFrozen')" width="420px">
      <el-form label-width="100px" @submit.prevent="handleAddFrozen">
        <el-form-item :label="t('common.ip')">
          <el-input v-model="frozenForm.ip" placeholder="e.g. 10.0.1.100" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showFrozenDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleAddFrozen">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
.auto-card {
  margin-top: 20px;
}
.unit-label {
  margin-left: 8px;
  color: var(--el-text-color-secondary);
}
</style>
