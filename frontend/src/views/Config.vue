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
  getLogTransport,
  updateLogTransport,
} from '@/api/config'
import type { ConfigHistoryEntry, NetworkInterface, ArpSpoofTarget, CaptureFile, LogTransportConfig } from '@/api/config'
import { getDiscoveredVlans } from '@/api/discovery'
import type { DiscoveredVlan } from '@/api/discovery'

const { t } = useI18n()
const router = useRouter()

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
const discoveredVlans = ref<DiscoveredVlan[]>([])

/* -- Data Server state -- */
type DataServerProtocol = 'none' | 'v1' | 'v2'
const dataServerProtocol = ref<DataServerProtocol>('none')
const dataServerSaving = ref(false)
const syslogServer = ref('')
const syslogPort = ref(514)
const syslogFacility = ref('local0')
const mqttBroker = ref('')
const mqttTopicPrefix = ref('')
const mqttClientId = ref('')
const mqttTls = ref(false)
const mqttTlsCa = ref('')
const mqttQos = ref(1)
const mqttKeepalive = ref(60)

const syslogFacilities = ['local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7', 'user', 'daemon']
/* -- Manage role helpers -- */
interface IpConfigState {
  mode: 'dhcp' | 'static' | 'none'
  ip: string
  prefix: string
  gateway: string
  dns1: string
  dns2: string
}
const manageIpStates = reactive<Record<string, IpConfigState>>({})
const monitorIpStates = reactive<Record<string, IpConfigState>>({})

function getManageState(ifName: string): IpConfigState {
  if (!manageIpStates[ifName]) {
    manageIpStates[ifName] = { mode: 'dhcp', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
  }
  return manageIpStates[ifName]
}

function getMonitorIpState(ifName: string): IpConfigState {
  if (!monitorIpStates[ifName]) {
    monitorIpStates[ifName] = { mode: 'none', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
  }
  return monitorIpStates[ifName]
}

function initManageStates(ifaces: NetworkInterface[]) {
  for (const iface of ifaces) {
    if (iface.role === 'manage') {
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
    } else if (iface.role === 'monitor') {
      const addr = iface.address || ''
      if (!addr) {
        monitorIpStates[iface.name] = { mode: 'none', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
      } else if (addr === 'dhcp') {
        monitorIpStates[iface.name] = { mode: 'dhcp', ip: '', prefix: '24', gateway: iface.gateway || '', dns1: iface.dns1 || '', dns2: iface.dns2 || '' }
      } else {
        const parts = addr.split('/')
        monitorIpStates[iface.name] = {
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

function syncMonitorIpFields(row: NetworkInterface) {
  const state = getMonitorIpState(row.name)
  if (state.mode === 'none') {
    row.address = ''
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
  } else if (state.mode === 'dhcp') {
    row.address = 'dhcp'
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
  } else {
    row.address = state.ip && state.prefix ? `${state.ip}/${state.prefix}` : ''
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

function onMonitorIpModeChange(row: NetworkInterface) {
  syncMonitorIpFields(row)
}

function onMonitorIpFieldChange(row: NetworkInterface) {
  syncMonitorIpFields(row)
}

function onRoleChange(row: NetworkInterface) {
  if (row.role === 'mirror') {
    row.subnet = ''
    row.address = ''
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
    row.vlans = []
    row.dynamic = { auto_discover: -1, max_entries: -1, ttl_hours: -1, max_ratio: -1, warmup_mode: -1 }
  } else if (row.role === 'manage') {
    const state = getManageState(row.name)
    if (state.mode === 'dhcp') {
      row.subnet = 'dhcp'
      row.gateway = ''
      row.dns1 = ''
      row.dns2 = ''
    }
    row.address = ''
    row.vlans = []
    row.dynamic = { auto_discover: -1, max_entries: -1, ttl_hours: -1, max_ratio: -1, warmup_mode: -1 }
  } else if (row.role === 'monitor') {
    if (row.subnet === 'dhcp') row.subnet = ''
    row.address = ''
    row.gateway = ''
    row.dns1 = ''
    row.dns2 = ''
    if (!row.vlans) row.vlans = []
    if (!row.dynamic) row.dynamic = { auto_discover: -1, max_entries: -1, ttl_hours: -1, max_ratio: -1, warmup_mode: -1 }
    monitorIpStates[row.name] = { mode: 'none', ip: '', prefix: '24', gateway: '', dns1: '', dns2: '' }
  }
}

const prefixOptions = ['8', '16', '24', '25', '26', '27', '28', '29', '30']

async function fetchAll() {
  loading.value = true
  try {
    const results = await Promise.allSettled([
      getConfig(),
      getStaged(),
      getConfigHistory(),
      getInterfaces(),
      getArpSpoof(),
      getCaptures(),
      getDiscoveredVlans(),
      getLogTransport(),
    ])

    const val = <T>(r: PromiseSettledResult<T>): T | null =>
      r.status === 'fulfilled' ? r.value : null

    const cfg = val(results[0])
    const staged = val(results[1]) as Record<string, unknown> | null
    const hist = val(results[2]) as Record<string, unknown> | null
    const ifaces = val(results[3]) as { interfaces: NetworkInterface[]; mode: string } | null
    const arpSpoof = val(results[4]) as { enabled: boolean; interval_sec: number; targets: ArpSpoofTarget[] } | null
    const captureData = val(results[5]) as Record<string, unknown> | null
    const vlansData = val(results[6]) as { vlans: DiscoveredVlan[] } | null
    const logData = val(results[7]) as LogTransportConfig | null

    if (cfg) {
      const json = JSON.stringify(cfg, null, 2)
      configText.value = json
      editText.value = json
    }
    if (staged) {
      hasStaged.value = (staged.count as number ?? 0) > 0
      stagedText.value = hasStaged.value ? JSON.stringify(staged.changes, null, 2) : ''
    }
    if (hist) {
      history.value = (hist.rows ?? hist.history ?? []) as ConfigHistoryEntry[]
    }
    if (ifaces) {
      interfaces.value = ifaces.interfaces.map(iface => ({
        ...iface,
        address: iface.address ?? '',
        vlans: iface.vlans ?? [],
        dynamic: iface.dynamic ?? { auto_discover: -1, max_entries: -1, ttl_hours: -1, max_ratio: -1, warmup_mode: -1 },
      }))
      systemMode.value = ifaces.mode
      initManageStates(ifaces.interfaces)
    }
    if (arpSpoof) {
      arpSpoofEnabled.value = arpSpoof.enabled
      arpSpoofInterval.value = arpSpoof.interval_sec
      arpSpoofTargets.value = arpSpoof.targets
    }
    if (captureData) {
      captureActive.value = captureData.active as boolean ?? false
      captureFilename.value = captureData.filename as string ?? ''
      captureBytesWritten.value = captureData.bytes_written as number ?? 0
      capturePktCount.value = captureData.pkt_count as number ?? 0
      captureMaxBytes.value = captureData.max_bytes as number ?? 0
      captureFiles.value = captureData.captures as CaptureFile[] ?? []
    }
    if (vlansData) {
      discoveredVlans.value = vlansData.vlans ?? []
    }
    if (logData) {
      if (logData.mqtt.enabled) {
        dataServerProtocol.value = 'v2'
      } else if (logData.syslog.enabled) {
        dataServerProtocol.value = 'v1'
      } else {
        dataServerProtocol.value = 'none'
      }
      syslogFacility.value = logData.syslog.facility || 'local0'
      const clean = (s: string) => s === 'null' ? '' : (s || '')
      syslogServer.value = clean(logData.syslog.server)
      syslogPort.value = logData.syslog.port || 514
      mqttBroker.value = clean(logData.mqtt.broker)
      mqttTopicPrefix.value = clean(logData.mqtt.topic_prefix)
      mqttClientId.value = clean(logData.mqtt.client_id)
      mqttTls.value = logData.mqtt.tls
      mqttTlsCa.value = clean(logData.mqtt.tls_ca)
      mqttQos.value = logData.mqtt.qos
      mqttKeepalive.value = logData.mqtt.keepalive_sec
    }
  } catch {
    // unexpected error — keep defaults
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

function vlanAlreadyConfigured(iface: NetworkInterface, vlanId: number): boolean {
  return iface.vlans.some(v => v.id === vlanId)
}

function importVlan(iface: NetworkInterface, vlan: DiscoveredVlan) {
  if (!iface.vlans) iface.vlans = []
  if (vlanAlreadyConfigured(iface, vlan.id)) return
  iface.vlans.push({ id: vlan.id, name: `VLAN${vlan.id}`, subnet: '' })
}

function importAllVlans(iface: NetworkInterface) {
  if (!iface.vlans) iface.vlans = []
  for (const vlan of discoveredVlans.value) {
    if (!vlanAlreadyConfigured(iface, vlan.id)) {
      iface.vlans.push({ id: vlan.id, name: `VLAN${vlan.id}`, subnet: '' })
    }
  }
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

async function handleSaveDataServer() {
  try {
    await ElMessageBox.confirm(t('config.confirmSaveDataServer'), t('common.confirm'), { type: 'warning' })
    dataServerSaving.value = true
    const payload: Record<string, unknown> = {}
    if (dataServerProtocol.value === 'none') {
      payload.syslog = { enabled: false }
      payload.mqtt = { enabled: false }
    } else if (dataServerProtocol.value === 'v1') {
      payload.syslog = { enabled: true, server: syslogServer.value, port: syslogPort.value, facility: syslogFacility.value }
      payload.mqtt = { enabled: false }
    } else {
      payload.syslog = { enabled: false }
      payload.mqtt = {
        enabled: true,
        broker: mqttBroker.value,
        topic_prefix: mqttTopicPrefix.value,
        client_id: mqttClientId.value,
        tls: mqttTls.value,
        tls_ca: mqttTlsCa.value,
        qos: mqttQos.value,
        keepalive_sec: mqttKeepalive.value,
      }
    }
    await updateLogTransport(payload as Partial<LogTransportConfig>)
    ElMessage.success(t('common.success'))
  } catch {
    // cancelled or error
  } finally {
    dataServerSaving.value = false
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
          <div v-for="iface in interfaces" :key="iface.name" class="iface-card">
            <div class="iface-header">
              <span class="iface-name">{{ iface.name }}</span>
              <el-select v-model="iface.role" size="small" style="width: 180px;" @change="onRoleChange(iface)">
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
            </div>

            <!-- Monitor: subnet + VLANs + dynamic guard config -->
            <template v-if="iface.role === 'monitor'">
              <div class="native-vlan-section">
                <div class="targets-header">
                  <span class="native-vlan-title">
                    <el-tooltip :content="t('config.nativeVlanHint')" placement="top">
                      <span style="cursor: help;">{{ t('config.nativeVlan') }} ⓘ</span>
                    </el-tooltip>
                  </span>
                </div>
                <el-input
                  v-model="iface.subnet"
                  size="small"
                  placeholder="e.g. 10.0.1.0/24"
                  style="max-width: 300px;"
                />
              </div>
              <!-- Monitor interface IP configuration -->
              <div class="monitor-ip-section">
                <div class="targets-header">
                  <span class="native-vlan-title">
                    <el-tooltip :content="t('config.monitorIpHint')" placement="top">
                      <span style="cursor: help;">{{ t('config.monitorIp') }} ⓘ</span>
                    </el-tooltip>
                  </span>
                </div>
                <el-radio-group
                  v-model="getMonitorIpState(iface.name).mode"
                  size="small"
                  @change="onMonitorIpModeChange(iface)"
                >
                  <el-radio-button value="none">{{ t('config.monitorIpNone') }}</el-radio-button>
                  <el-radio-button value="dhcp">{{ t('config.manageIpDhcp') }}</el-radio-button>
                  <el-radio-button value="static">{{ t('config.manageIpStatic') }}</el-radio-button>
                </el-radio-group>
                <el-alert
                  v-if="getMonitorIpState(iface.name).mode === 'none'"
                  type="warning"
                  :closable="false"
                  show-icon
                  style="margin-top: 8px;"
                >
                  {{ t('config.monitorIpNoneWarning') }}
                </el-alert>
                <div v-if="getMonitorIpState(iface.name).mode === 'static'" class="manage-static-fields" style="margin-top: 8px;">
                  <el-input
                    v-model="getMonitorIpState(iface.name).ip"
                    size="small"
                    :placeholder="t('config.manageIp')"
                    style="width: 140px;"
                    @input="onMonitorIpFieldChange(iface)"
                  />
                  <span class="manage-slash">/</span>
                  <el-select
                    v-model="getMonitorIpState(iface.name).prefix"
                    size="small"
                    style="width: 80px;"
                    @change="onMonitorIpFieldChange(iface)"
                  >
                    <el-option v-for="p in prefixOptions" :key="p" :label="'/' + p" :value="p" />
                  </el-select>
                  <el-input
                    v-model="getMonitorIpState(iface.name).gateway"
                    size="small"
                    :placeholder="t('config.manageGateway')"
                    style="width: 140px;"
                    @input="onMonitorIpFieldChange(iface)"
                  />
                </div>
              </div>
              <div class="targets-header" style="margin-top: 16px;">
                <span>{{ t('config.taggedVlans') }}</span>
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
              <!-- Auto-detected VLANs -->
              <div v-if="discoveredVlans.length > 0" class="discovered-vlans-section">
                <div class="targets-header">
                  <span class="discovered-vlans-title">
                    <el-tooltip :content="t('config.discoveredVlansHint')" placement="top">
                      <span style="cursor: help;">{{ t('config.discoveredVlans') }} ⓘ</span>
                    </el-tooltip>
                  </span>
                  <el-button type="success" text size="small" @click="importAllVlans(iface)">
                    {{ t('config.importAllVlans') }}
                  </el-button>
                </div>
                <el-table :data="discoveredVlans" stripe size="small">
                  <el-table-column :label="t('config.vlanId')" prop="id" width="140" />
                  <el-table-column :label="t('config.deviceCount')" prop="device_count" width="120" />
                  <el-table-column :label="t('discovery.lastSeen')">
                    <template #default="{ row }">
                      {{ formatTime(row.last_seen) }}
                    </template>
                  </el-table-column>
                  <el-table-column :label="t('common.action')" width="100">
                    <template #default="{ row }">
                      <el-button
                        type="success"
                        text
                        size="small"
                        :disabled="vlanAlreadyConfigured(iface, row.id)"
                        @click="importVlan(iface, row)"
                      >
                        {{ t('config.importVlan') }}
                      </el-button>
                    </template>
                  </el-table-column>
                </el-table>
              </div>
              <!-- Per-NIC dynamic guard settings -->
              <el-divider />
              <div class="dynamic-guard-section">
                <span class="dynamic-guard-title">{{ t('config.dynamicGuard') }}</span>
                <div class="dynamic-guard-row">
                  <span class="dynamic-guard-label">{{ t('config.dynamicAutoDiscover') }}</span>
                  <el-select v-model="iface.dynamic!.auto_discover" size="small" style="width: 200px;">
                    <el-option :label="t('config.dynamicUseGlobal')" :value="-1" />
                    <el-option :label="t('common.disabled')" :value="0" />
                    <el-option :label="t('common.enabled')" :value="1" />
                  </el-select>
                </div>
                <div class="dynamic-guard-row">
                  <span class="dynamic-guard-label">{{ t('config.warmupMode') }}</span>
                  <el-select v-model="iface.dynamic!.warmup_mode" size="small" style="width: 200px;">
                    <el-option :label="t('config.dynamicUseGlobal')" :value="-1" />
                    <el-option :label="t('config.warmupNormal')" :value="0" />
                    <el-option :label="t('config.warmupFast')" :value="1" />
                    <el-option :label="t('config.warmupBurst')" :value="2" />
                  </el-select>
                  <span class="dynamic-guard-hint">
                    {{ iface.dynamic!.warmup_mode === 2 ? t('config.warmupBurstDesc')
                     : iface.dynamic!.warmup_mode === 1 ? t('config.warmupFastDesc')
                     : iface.dynamic!.warmup_mode === 0 ? t('config.warmupNormalDesc')
                     : '' }}
                  </span>
                </div>
                <template v-if="iface.dynamic!.auto_discover !== -1">
                  <div class="dynamic-guard-row">
                    <span class="dynamic-guard-label">{{ t('config.dynamicMaxRatio') }}</span>
                    <el-input-number v-model="iface.dynamic!.max_ratio" :min="-1" :max="100" :step="5" size="small" style="width: 160px;" />
                  </div>
                  <div class="dynamic-guard-row">
                    <span class="dynamic-guard-label">{{ t('config.dynamicMaxEntries') }}</span>
                    <el-input-number v-model="iface.dynamic!.max_entries" :min="-1" size="small" style="width: 160px;" />
                  </div>
                  <div class="dynamic-guard-row">
                    <span class="dynamic-guard-label">{{ t('config.dynamicTtlHours') }}</span>
                    <el-input-number v-model="iface.dynamic!.ttl_hours" :min="-1" :max="720" size="small" style="width: 160px;" />
                  </div>
                </template>
              </div>
              <el-alert type="info" :closable="false" show-icon style="margin-top: 12px;">
                <template #title>
                  {{ t('config.dhcpExemptionHint') }}
                  <el-link type="primary" :underline="false" style="margin-left: 8px; vertical-align: baseline;" @click="router.push('/whitelist')">
                    {{ t('config.dhcpExemptionLink') }} →
                  </el-link>
                </template>
              </el-alert>
            </template>

            <!-- Manage: DHCP / Static config -->
            <div v-else-if="iface.role === 'manage'" class="manage-ip-config" style="margin-top: 12px;">
              <el-radio-group
                v-model="getManageState(iface.name).mode"
                size="small"
                @change="onManageModeChange(iface)"
              >
                <el-radio-button value="dhcp">{{ t('config.manageIpDhcp') }}</el-radio-button>
                <el-radio-button value="static">{{ t('config.manageIpStatic') }}</el-radio-button>
              </el-radio-group>
              <div v-if="getManageState(iface.name).mode === 'static'" class="manage-static-fields">
                <el-input
                  v-model="getManageState(iface.name).ip"
                  size="small"
                  :placeholder="t('config.manageIp')"
                  style="width: 140px;"
                  @input="onManageFieldChange(iface)"
                />
                <span class="manage-slash">/</span>
                <el-select
                  v-model="getManageState(iface.name).prefix"
                  size="small"
                  style="width: 80px;"
                  @change="onManageFieldChange(iface)"
                >
                  <el-option v-for="p in prefixOptions" :key="p" :label="'/' + p" :value="p" />
                </el-select>
                <el-input
                  v-model="getManageState(iface.name).gateway"
                  size="small"
                  :placeholder="t('config.manageGateway')"
                  style="width: 140px;"
                  @input="onManageFieldChange(iface)"
                />
                <el-input
                  v-model="getManageState(iface.name).dns1"
                  size="small"
                  :placeholder="t('config.manageDns1')"
                  style="width: 140px;"
                  @input="onManageFieldChange(iface)"
                />
                <el-input
                  v-model="getManageState(iface.name).dns2"
                  size="small"
                  :placeholder="t('config.manageDns2')"
                  style="width: 140px;"
                  @input="onManageFieldChange(iface)"
                />
              </div>
            </div>

            <!-- Mirror: no extra config -->
            <div v-else class="mirror-no-config" style="margin-top: 8px;">—</div>
          </div>
          <div class="mode-row">
            <span>{{ t('config.mode') }}:</span>
            <el-select v-model="systemMode" size="small" style="width: 140px; margin-left: 8px;">
              <el-option :label="t('config.modeBypass')" value="bypass" />
              <el-option :label="t('config.modeInline')" value="inline" />
            </el-select>
          </div>
        </el-card>

        <!-- Data Server -->
        <el-card class="section-card">
          <template #header>
            <div class="card-header">
              <span>{{ t('config.dataServer') }}</span>
              <el-button type="primary" size="small" :loading="dataServerSaving" @click="handleSaveDataServer">
                {{ t('common.save') }}
              </el-button>
            </div>
          </template>
          <p class="data-server-desc">{{ t('config.dataServerDesc') }}</p>
          <div class="data-server-protocol">
            <span class="data-server-label">{{ t('config.dataServerProtocol') }}</span>
            <el-radio-group v-model="dataServerProtocol" size="small">
              <el-radio-button value="none">{{ t('config.dataServerNone') }}</el-radio-button>
              <el-radio-button value="v1">{{ t('config.dataServerV1') }}</el-radio-button>
              <el-radio-button value="v2">{{ t('config.dataServerV2') }}</el-radio-button>
            </el-radio-group>
          </div>
          <div class="data-server-hint">
            {{ dataServerProtocol === 'v1' ? t('config.dataServerV1Desc')
             : dataServerProtocol === 'v2' ? t('config.dataServerV2Desc')
             : t('config.dataServerNoneDesc') }}
          </div>

          <!-- V1: Syslog settings -->
          <template v-if="dataServerProtocol === 'v1'">
            <el-divider />
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerSyslogServer') }}</span>
              <el-input v-model="syslogServer" size="small" :placeholder="t('config.dataServerSyslogServerPlaceholder')" style="max-width: 280px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerSyslogPort') }}</span>
              <el-input-number v-model="syslogPort" :min="1" :max="65535" size="small" style="width: 140px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerFacility') }}</span>
              <el-select v-model="syslogFacility" size="small" style="width: 160px;">
                <el-option v-for="f in syslogFacilities" :key="f" :label="f" :value="f" />
              </el-select>
            </div>
          </template>

          <!-- V2: MQTT settings -->
          <template v-if="dataServerProtocol === 'v2'">
            <el-divider />
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerBroker') }}</span>
              <el-input v-model="mqttBroker" size="small" :placeholder="t('config.dataServerBrokerPlaceholder')" style="max-width: 360px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerTopicPrefix') }}</span>
              <el-input v-model="mqttTopicPrefix" size="small" :placeholder="t('config.dataServerTopicPrefixPlaceholder')" style="max-width: 260px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerClientId') }}</span>
              <el-input v-model="mqttClientId" size="small" :placeholder="t('config.dataServerClientIdPlaceholder')" style="max-width: 260px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerQos') }}</span>
              <el-select v-model="mqttQos" size="small" style="width: 100px;">
                <el-option :label="'0'" :value="0" />
                <el-option :label="'1'" :value="1" />
                <el-option :label="'2'" :value="2" />
              </el-select>
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerKeepalive') }}</span>
              <el-input-number v-model="mqttKeepalive" :min="10" :max="3600" size="small" style="width: 140px;" />
            </div>
            <div class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerTls') }}</span>
              <el-switch v-model="mqttTls" />
            </div>
            <div v-if="mqttTls" class="data-server-field">
              <span class="data-server-label">{{ t('config.dataServerTlsCa') }}</span>
              <el-input v-model="mqttTlsCa" size="small" placeholder="/etc/jz/ca.pem" style="max-width: 360px;" />
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
.discovered-vlans-section {
  margin-top: 12px;
  padding: 10px;
  background: #f0f9eb;
  border-radius: 4px;
}
.discovered-vlans-title {
  font-size: 13px;
  color: #67c23a;
  font-weight: 600;
}
.native-vlan-section {
  margin-bottom: 8px;
}
.native-vlan-title {
  font-size: 13px;
  font-weight: 600;
  color: #409eff;
}
.iface-card {
  padding: 16px;
  border: 1px solid #ebeef5;
  border-radius: 6px;
  margin-bottom: 12px;
  background: #fafafa;
}
.iface-header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 12px;
}
.iface-name {
  font-size: 15px;
  font-weight: 600;
  color: #303133;
  min-width: 80px;
}
.dynamic-guard-section {
  padding: 8px 0;
}
.dynamic-guard-title {
  font-size: 13px;
  font-weight: 600;
  color: #e6a23c;
}
.dynamic-guard-row {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 8px;
}
.dynamic-guard-label {
  font-size: 13px;
  color: #606266;
  min-width: 130px;
}
.dynamic-guard-hint {
  font-size: 12px;
  color: #909399;
  font-style: italic;
}
.monitor-ip-section {
  margin-top: 12px;
  margin-bottom: 8px;
}
.data-server-desc {
  font-size: 13px;
  color: #909399;
  margin-bottom: 12px;
}
.data-server-protocol {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}
.data-server-label {
  font-size: 13px;
  color: #606266;
  min-width: 150px;
}
.data-server-hint {
  font-size: 12px;
  color: #909399;
  font-style: italic;
  margin-bottom: 8px;
}
.data-server-field {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-top: 8px;
}
</style>
