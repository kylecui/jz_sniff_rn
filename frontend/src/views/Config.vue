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
  getInterfaces,
  updateInterfaces,
  getArpSpoof,
  updateArpSpoof,
  getVlans,
  updateVlans,
} from '@/api/config'
import type { ConfigHistoryEntry, NetworkInterface, ArpSpoofTarget, VlanConfig } from '@/api/config'

const { t } = useI18n()

const loading = ref(true)
const configText = ref('')
const editText = ref('')
const isEditing = ref(false)
const hasStaged = ref(false)
const stagedText = ref('')
const history = ref<ConfigHistoryEntry[]>([])
const interfaces = ref<NetworkInterface[]>([])
const systemMode = ref('bypass')
const interfacesSaving = ref(false)
const arpSpoofEnabled = ref(false)
const arpSpoofInterval = ref(5)
const arpSpoofTargets = ref<ArpSpoofTarget[]>([])
const arpSpoofSaving = ref(false)
const vlans = ref<VlanConfig[]>([])
const vlansSaving = ref(false)

async function fetchAll() {
  loading.value = true
  try {
    const [cfg, staged, hist, ifaces, arpSpoof, vlansData] = await Promise.all([
      getConfig(),
      getStaged(),
      getConfigHistory(),
      getInterfaces(),
      getArpSpoof(),
      getVlans(),
    ])
    const json = JSON.stringify(cfg.config, null, 2)
    configText.value = json
    editText.value = json
    hasStaged.value = staged.has_staged
    stagedText.value = staged.staged ? JSON.stringify(staged.staged, null, 2) : ''
    history.value = hist.history
    interfaces.value = ifaces.interfaces
    systemMode.value = ifaces.mode
    arpSpoofEnabled.value = arpSpoof.enabled
    arpSpoofInterval.value = arpSpoof.interval_sec
    arpSpoofTargets.value = arpSpoof.targets
    vlans.value = vlansData.vlans ?? []
  } catch {
    // keep defaults
  } finally {
    loading.value = false
  }
}

async function handleSaveInterfaces() {
  try {
    await ElMessageBox.confirm(t('config.confirmSaveInterfaces'), t('common.confirm'), { type: 'warning' })
    interfacesSaving.value = true
    const result = await updateInterfaces({ interfaces: interfaces.value, mode: systemMode.value })
    interfaces.value = result.interfaces
    systemMode.value = result.mode
    ElMessage.success(t('common.success'))
  } catch {
    // cancelled or error
  } finally {
    interfacesSaving.value = false
  }
}

function addArpSpoofTarget() {
  arpSpoofTargets.value.push({ target_ip: '', gateway_ip: '' })
}

function removeArpSpoofTarget(index: number) {
  arpSpoofTargets.value.splice(index, 1)
}

async function handleSaveArpSpoof() {
  try {
    await ElMessageBox.confirm(t('config.confirmSaveArpSpoof'), t('common.confirm'), { type: 'warning' })
    arpSpoofSaving.value = true
    const result = await updateArpSpoof({
      enabled: arpSpoofEnabled.value,
      interval_sec: arpSpoofInterval.value,
      targets: arpSpoofTargets.value,
    })
    arpSpoofEnabled.value = result.enabled
    arpSpoofInterval.value = result.interval_sec
    arpSpoofTargets.value = result.targets
    ElMessage.success(t('common.success'))
  } catch {
    // cancelled or error
  } finally {
    arpSpoofSaving.value = false
  }
}

function addVlan() {
  vlans.value.push({ id: 0, name: '', subnet: '' })
}

function removeVlan(index: number) {
  vlans.value.splice(index, 1)
}

async function handleSaveVlans() {
  try {
    await ElMessageBox.confirm(t('config.confirmSaveVlans'), t('common.confirm'), { type: 'warning' })
    vlansSaving.value = true
    const result = await updateVlans({ vlans: vlans.value })
    vlans.value = result.vlans ?? []
    ElMessage.success(t('common.success'))
  } catch {
    // cancelled or error
  } finally {
    vlansSaving.value = false
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
        <!-- Interfaces -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.interfaces') }}</span>
              <el-button type="primary" size="small" :loading="interfacesSaving" @click="handleSaveInterfaces">
                {{ t('common.save') }}
              </el-button>
            </div>
          </template>
          <el-table :data="interfaces" stripe>
            <el-table-column prop="name" :label="t('config.interfaceName')" width="160" />
            <el-table-column :label="t('config.interfaceRole')" width="160">
              <template #default="{ row }">
                <el-select v-model="row.role" size="small">
                  <el-option label="monitor" value="monitor" />
                  <el-option label="manage" value="manage" />
                  <el-option label="mirror" value="mirror" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column :label="t('config.interfaceSubnet')">
              <template #default="{ row }">
                <el-input v-model="row.subnet" size="small" :disabled="row.role === 'mirror'" placeholder="e.g. 10.0.1.0/24" />
              </template>
            </el-table-column>
          </el-table>
          <div class="mode-row">
            <span>{{ t('config.mode') }}:</span>
            <el-select v-model="systemMode" size="small" style="width: 140px; margin-left: 8px;">
              <el-option :label="t('config.modeBypass')" value="bypass" />
              <el-option :label="t('config.modeInline')" value="inline" />
            </el-select>
          </div>
        </el-card>

        <!-- ARP Spoofing -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.arpSpoof') }}</span>
              <el-button type="primary" size="small" :loading="arpSpoofSaving" @click="handleSaveArpSpoof">
                {{ t('common.save') }}
              </el-button>
            </div>
          </template>
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px;">
            <template #title>{{ t('config.arpSpoofWarning') }}</template>
          </el-alert>
          <div class="arp-spoof-controls">
            <el-switch v-model="arpSpoofEnabled" :active-text="t('config.arpSpoofEnabled')" />
            <div class="interval-row">
              <span>{{ t('config.arpSpoofInterval') }}:</span>
              <el-input-number v-model="arpSpoofInterval" :min="1" :max="300" size="small" style="width: 140px; margin-left: 8px;" />
            </div>
          </div>
          <div class="targets-header">
            <span>{{ t('config.arpSpoofTargets') }}</span>
            <el-button type="primary" text size="small" @click="addArpSpoofTarget">
              + {{ t('config.arpSpoofAddTarget') }}
            </el-button>
          </div>
          <el-table :data="arpSpoofTargets" stripe>
            <el-table-column :label="t('config.arpSpoofTargetIp')">
              <template #default="{ row }">
                <el-input v-model="row.target_ip" size="small" placeholder="e.g. 10.0.1.100" />
              </template>
            </el-table-column>
            <el-table-column :label="t('config.arpSpoofGatewayIp')">
              <template #default="{ row }">
                <el-input v-model="row.gateway_ip" size="small" placeholder="e.g. 10.0.1.1" />
              </template>
            </el-table-column>
            <el-table-column :label="t('common.action')" width="80">
              <template #default="{ $index }">
                <el-button type="danger" text size="small" @click="removeArpSpoofTarget($index)">
                  {{ t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

        <!-- VLANs -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.vlans') }}</span>
              <el-button type="primary" size="small" :loading="vlansSaving" @click="handleSaveVlans">
                {{ t('common.save') }}
              </el-button>
            </div>
          </template>
          <div class="targets-header">
            <span />
            <el-button type="primary" text size="small" @click="addVlan">
              + {{ t('config.addVlan') }}
            </el-button>
          </div>
          <el-table :data="vlans" stripe>
            <el-table-column :label="t('config.vlanId')" width="140">
              <template #default="{ row }">
                <el-input-number v-model="row.id" :min="1" :max="4094" size="small" controls-position="right" style="width: 110px;" />
              </template>
            </el-table-column>
            <el-table-column :label="t('config.vlanName')">
              <template #default="{ row }">
                <el-input v-model="row.name" size="small" placeholder="e.g. VLAN10" />
              </template>
            </el-table-column>
            <el-table-column :label="t('config.vlanSubnet')">
              <template #default="{ row }">
                <el-input v-model="row.subnet" size="small" placeholder="e.g. 10.0.10.0/24" />
              </template>
            </el-table-column>
            <el-table-column :label="t('common.action')" width="80">
              <template #default="{ $index }">
                <el-button type="danger" text size="small" @click="removeVlan($index)">
                  {{ t('common.delete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-card>

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
.mode-row {
  margin-top: 12px;
  display: flex;
  align-items: center;
}
.arp-spoof-controls {
  display: flex;
  align-items: center;
  gap: 24px;
  margin-bottom: 12px;
}
.interval-row {
  display: flex;
  align-items: center;
}
.targets-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
</style>
