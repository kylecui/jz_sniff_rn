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
  getCaptures,
  startCapture,
  stopCapture,
  deleteCapture,
  downloadCaptureUrl,
} from '@/api/config'
import type { ConfigHistoryEntry, NetworkInterface, ArpSpoofTarget, CaptureFile } from '@/api/config'

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
const captureActive = ref(false)
const captureFilename = ref('')
const captureBytesWritten = ref(0)
const capturePktCount = ref(0)
const captureMaxBytes = ref(0)
const captureFiles = ref<CaptureFile[]>([])
const captureMaxSizeMB = ref(100)
const captureLoading = ref(false)

/* -- Manage role helpers -- */
interface ManageIpState {
  mode: 'dhcp' | 'static'
  ip: string
  prefix: string
  gateway: string
  dns1: string
  dns2: string
}
const manageIpStates = reactive<Record<string, ManageIpState>>({})

function getManageState(ifName: string): ManageIpState {
  if (!manageIpStates[ifName]) {
    manageIpStates[ifName] = { mode: 'dhcp', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
  }
  return manageIpStates[ifName]
}

function initManageStates(ifaces: NetworkInterface[]) {
  for (const iface of ifaces) {
    if (iface.role !== 'manage') continue
    if (iface.subnet === 'dhcp' || !iface.subnet) {
      manageIpStates[iface.name] = { mode: 'dhcp', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
    } else {
      const parts = iface.subnet.split('/')
      manageIpStates[iface.name] = {
        mode: 'static',
        ip: parts[0] || '',
        prefix: parts[1] || '24',
        gateway: iface.gateway || '',
        dns1: iface.dns1 || '',
        dns2: iface.dns2 || '',
      }
    }
  }
}

function syncManageFields(row: NetworkInterface) {
  const state = getManageState(row.name)
  if (state.mode === 'dhcp') {
    row.subnet = 'dhcp'
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
  } else {
    row.subnet = state.ip && state.prefix ? `${state.ip}/${state.prefix}` : ''
    row.gateway = state.gateway
    row.dns1 = state.dns1
    row.dns2 = state.dns2
  }
}

function onManageModeChange(row: NetworkInterface) {
  syncManageFields(row)
}

function onManageFieldChange(row: NetworkInterface) {
  syncManageFields(row)
}

function onRoleChange(row: NetworkInterface) {
  if (row.role === 'mirror') {
    row.subnet = ''
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
    row.vlans = []
  } else if (row.role === 'manage') {
    const state = getManageState(row.name)
    if (state.mode === 'dhcp') {
      row.subnet = 'dhcp'
      row.gateway = ''
      row.dns1 = ''
      row.dns2 = ''
    }
    row.vlans = []
  } else if (row.role === 'monitor') {
    if (row.subnet === 'dhcp') row.subnet = ''
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
    if (!row.vlans) row.vlans = []
  }
}

const prefixOptions = ['8', '16', '24', '25', '26', '27', '28', '29', '30']

async function fetchAll() {
  loading.value = true
  try {
    const [cfg, staged, hist, ifaces, arpSpoof, captureData] = await Promise.all([
      getConfig(),
      getStaged(),
      getConfigHistory(),
      getInterfaces(),
      getArpSpoof(),
      getCaptures(),
    ])
    const json = JSON.stringify(cfg.config, null, 2)
    configText.value = json
    editText.value = json
    hasStaged.value = staged.has_staged
    stagedText.value = staged.staged ? JSON.stringify(staged.staged, null, 2) : ''
    history.value = hist.history
    interfaces.value = ifaces.interfaces.map(iface => ({
      ...iface,
      vlans: iface.vlans ?? [],
    }))
    systemMode.value = ifaces.mode
    initManageStates(ifaces.interfaces)
    arpSpoofEnabled.value = arpSpoof.enabled
    arpSpoofInterval.value = arpSpoof.interval_sec
    arpSpoofTargets.value = arpSpoof.targets
    captureActive.value = captureData.active
    captureFilename.value = captureData.filename ?? ''
    captureBytesWritten.value = captureData.bytes_written ?? 0
    capturePktCount.value = captureData.pkt_count ?? 0
    captureMaxBytes.value = captureData.max_bytes ?? 0
    captureFiles.value = captureData.captures ?? []
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
    interfaces.value = result.interfaces.map(iface => ({
      ...iface,
      vlans: iface.vlans ?? [],
    }))
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

function addVlan(iface: NetworkInterface) {
  if (!iface.vlans) iface.vlans = []
  iface.vlans.push({ id: 0, name: '', subnet: '' })
}

function removeVlan(iface: NetworkInterface, index: number) {
  iface.vlans.splice(index, 1)
}

async function handleStartCapture() {
  try {
    await ElMessageBox.confirm(t('config.confirmStartCapture'), t('common.confirm'), { type: 'warning' })
    captureLoading.value = true
    await startCapture(captureMaxSizeMB.value * 1024 * 1024)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  } finally {
    captureLoading.value = false
  }
}

async function handleStopCapture() {
  try {
    await ElMessageBox.confirm(t('config.confirmStopCapture'), t('common.confirm'), { type: 'warning' })
    captureLoading.value = true
    await stopCapture()
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  } finally {
    captureLoading.value = false
  }
}

function handleDownloadCapture(filename: string) {
  window.open(downloadCaptureUrl(filename), '_blank')
}

async function handleDeleteCapture(filename: string) {
  try {
    await ElMessageBox.confirm(t('config.confirmDeleteCapture', { filename }), t('common.confirm'), { type: 'warning' })
    await deleteCapture(filename)
    ElMessage.success(t('common.success'))
    await fetchAll()
  } catch {
    // cancelled or error
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleString()
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
            <el-table-column prop="name" :label="t('config.interfaceName')" width="140" />
            <el-table-column :label="t('config.interfaceRole')" width="200">
              <template #default="{ row }">
                <el-select v-model="row.role" size="small" @change="onRoleChange(row)">
                  <el-option value="monitor">
                    <div class="role-option">
                      <span class="role-option-label">{{ t('config.roleMonitor') }}</span>
                      <span class="role-option-hint">{{ t('config.roleMonitorHint') }}</span>
                    </div>
                  </el-option>
                  <el-option value="manage">
                    <div class="role-option">
                      <span class="role-option-label">{{ t('config.roleManage') }}</span>
                      <span class="role-option-hint">{{ t('config.roleManageHint') }}</span>
                    </div>
                  </el-option>
                  <el-option value="mirror">
                    <div class="role-option">
                      <span class="role-option-label">{{ t('config.roleMirror') }}</span>
                      <span class="role-option-hint">{{ t('config.roleMirrorHint') }}</span>
                    </div>
                  </el-option>
                </el-select>
              </template>
            </el-table-column>
            <el-table-column :label="t('config.interfaceSubnet')" min-width="360">
              <template #default="{ row }">
                <!-- Monitor: subnet CIDR -->
                <el-input
                  v-if="row.role === 'monitor'"
                  v-model="row.subnet"
                  size="small"
                  placeholder="e.g. 10.0.1.0/24"
                />
                <!-- Manage: DHCP / Static toggle -->
                <div v-else-if="row.role === 'manage'" class="manage-ip-config">
                  <el-radio-group
                    v-model="getManageState(row.name).mode"
                    size="small"
                    @change="onManageModeChange(row)"
                  >
                    <el-radio-button value="dhcp">{{ t('config.manageIpDhcp') }}</el-radio-button>
                    <el-radio-button value="static">{{ t('config.manageIpStatic') }}</el-radio-button>
                  </el-radio-group>
                  <div v-if="getManageState(row.name).mode === 'static'" class="manage-static-fields">
                    <el-input
                      v-model="getManageState(row.name).ip"
                      size="small"
                      :placeholder="t('config.manageIp')"
                      style="width: 140px;"
                      @input="onManageFieldChange(row)"
                    />
                    <span class="manage-slash">/</span>
                    <el-select
                      v-model="getManageState(row.name).prefix"
                      size="small"
                      style="width: 80px;"
                      @change="onManageFieldChange(row)"
                    >
                      <el-option v-for="p in prefixOptions" :key="p" :label="'/' + p" :value="p" />
                    </el-select>
                    <el-input
                      v-model="getManageState(row.name).gateway"
                      size="small"
                      :placeholder="t('config.manageGateway')"
                      style="width: 140px;"
                      @input="onManageFieldChange(row)"
                    />
                    <el-input
                      v-model="getManageState(row.name).dns1"
                      size="small"
                      :placeholder="t('config.manageDns1')"
                      style="width: 140px;"
                      @input="onManageFieldChange(row)"
                    />
                    <el-input
                      v-model="getManageState(row.name).dns2"
                      size="small"
                      :placeholder="t('config.manageDns2')"
                      style="width: 140px;"
                      @input="onManageFieldChange(row)"
                    />
                  </div>
                </div>
                <!-- Mirror: no config -->
                <span v-else class="mirror-no-config">—</span>
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
          <!-- Per-interface VLANs (monitor only) -->
          <template v-for="iface in interfaces" :key="iface.name + '-vlans'">
            <div v-if="iface.role === 'monitor'" class="vlan-section">
              <div class="targets-header">
                <span>{{ t('config.vlans') }} — {{ iface.name }}</span>
                <el-button type="primary" text size="small" @click="addVlan(iface)">
                  + {{ t('config.addVlan') }}
                </el-button>
              </div>
              <el-table v-if="iface.vlans && iface.vlans.length > 0" :data="iface.vlans" stripe size="small">
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
                    <el-button type="danger" text size="small" @click="removeVlan(iface, $index)">
                      {{ t('common.delete') }}
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>
              <el-empty v-else :description="t('common.noData')" :image-size="40" />
            </div>
          </template>
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

        <!-- Packet Capture -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.capture') }}</span>
              <el-button
                v-if="captureActive"
                type="danger"
                size="small"
                :loading="captureLoading"
                @click="handleStopCapture"
              >
                {{ t('config.captureStop') }}
              </el-button>
              <div v-else class="capture-start-row">
                <el-input-number
                  v-model="captureMaxSizeMB"
                  :min="1"
                  :max="10240"
                  size="small"
                  style="width: 140px;"
                />
                <span class="capture-unit">{{ t('config.captureMaxSize') }}</span>
                <el-button
                  type="primary"
                  size="small"
                  :loading="captureLoading"
                  @click="handleStartCapture"
                >
                  {{ t('config.captureStart') }}
                </el-button>
              </div>
            </div>
          </template>
          <div class="capture-status-row">
            <el-tag :type="captureActive ? 'danger' : 'info'" effect="dark">
              {{ captureActive ? t('config.captureActive') : t('config.captureIdle') }}
            </el-tag>
            <template v-if="captureActive">
              <span class="capture-detail">{{ t('config.capturePktCount') }}: {{ capturePktCount }}</span>
              <span class="capture-detail">{{ t('config.captureBytesWritten') }}: {{ formatBytes(captureBytesWritten) }} / {{ formatBytes(captureMaxBytes) }}</span>
            </template>
          </div>
          <div class="targets-header">
            <span>{{ t('config.captureFiles') }}</span>
          </div>
          <el-table v-if="captureFiles.length > 0" :data="captureFiles" stripe>
            <el-table-column prop="filename" :label="t('config.captureFilename')" />
            <el-table-column :label="t('config.captureSize')" width="120">
              <template #default="{ row }">
                {{ formatBytes(row.size_bytes) }}
              </template>
            </el-table-column>
            <el-table-column :label="t('config.captureCreated')" width="180">
              <template #default="{ row }">
                {{ formatTime(row.created) }}
              </template>
            </el-table-column>
            <el-table-column :label="t('common.action')" width="160">
              <template #default="{ row }">
                <el-button type="primary" text size="small" @click="handleDownloadCapture(row.filename)">
                  {{ t('config.captureDownload') }}
                </el-button>
                <el-button type="danger" text size="small" @click="handleDeleteCapture(row.filename)">
                  {{ t('config.captureDelete') }}
                </el-button>
              </template>
            </el-table-column>
          </el-table>
          <el-empty v-else :description="t('config.captureNoFiles')" :image-size="60" />
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
.capture-start-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.capture-unit {
  font-size: 12px;
  color: #909399;
}
.capture-status-row {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 12px;
}
.capture-detail {
  font-size: 13px;
  color: #606266;
}
.role-option {
  display: flex;
  flex-direction: column;
  line-height: 1.4;
  padding: 2px 0;
}
.role-option-label {
  font-weight: 600;
  font-size: 13px;
}
.role-option-hint {
  font-size: 11px;
  color: #909399;
  white-space: normal;
  line-height: 1.3;
}
.manage-ip-config {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.manage-static-fields {
  display: flex;
  align-items: center;
  gap: 4px;
}
.manage-slash {
  font-size: 14px;
  color: #606266;
  font-weight: 600;
}
.mirror-no-config {
  color: #c0c4cc;
  font-size: 13px;
}
.vlan-section {
  margin-top: 16px;
  padding-top: 12px;
  border-top: 1px solid #ebeef5;
}
</style>
