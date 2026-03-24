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
} from '@/api/guards'
import type { Guard, FrozenGuard, AutoGuardStatus } from '@/api/guards'

const { t } = useI18n()

const activeTab = ref('static')
const loading = ref(true)

const staticGuards = ref<Guard[]>([])
const dynamicGuards = ref<Guard[]>([])
const frozenGuards = ref<FrozenGuard[]>([])
const autoStatus = ref<AutoGuardStatus>({ max_ratio: 0, subnet_total: 0, max_allowed: 0, current_dynamic: 0, frozen_count: 0 })

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

        <!-- Auto-deploy status -->
        <el-card class="auto-card">
          <template #header>{{ t('guards.autoStatus') }}</template>
          <p>
            {{ t('guards.maxRatio') }}: {{ autoStatus.max_ratio }}%
            （{{ t('guards.maxAllowed') }}: {{ autoStatus.max_allowed }} / {{ autoStatus.subnet_total }}）
          </p>
          <p>{{ t('guards.currentDynamic') }}: {{ autoStatus.current_dynamic }}</p>
          <p>{{ t('guards.frozenCount') }}: {{ autoStatus.frozen_count }}</p>
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
</style>
