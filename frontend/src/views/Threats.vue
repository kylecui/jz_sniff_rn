<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  getThreatPatterns, addThreatPattern, updateThreatPattern, deleteThreatPattern,
  getRedirectTargets, addRedirectTarget, updateRedirectTarget, deleteRedirectTarget,
  reorderPatterns,
} from '@/api/threats'
import type { ThreatPattern, ThreatPatternCreate, RedirectTarget } from '@/api/threats'

const { t } = useI18n()

const loading = ref(true)
const patterns = ref<ThreatPattern[]>([])
const targets = ref<RedirectTarget[]>([])

const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref('')
const form = reactive<ThreatPatternCreate>({
  id: '',
  priority: 1,
  src_ip: '',
  src_mac: '',
  dst_port: 0,
  proto: 'tcp',
  threat_level: 'medium',
  action: 'log',
  redirect_target: 0,
  continue_matching: false,
  capture_packet: false,
  description: '',
})

const showTargetDialog = ref(false)
const isTargetEdit = ref(false)
const targetForm = reactive<RedirectTarget>({
  id: 0,
  name: '',
  interface: '',
})

const protocols = ['tcp', 'udp', 'icmp', 'any']
const threatLevels = ['low', 'medium', 'high', 'critical']
const threatActions: string[] = ['log', 'log_drop', 'log_redirect', 'log_mirror']

const needsTarget = computed(() => form.action === 'log_redirect' || form.action === 'log_mirror')

function targetName(targetId: number): string {
  const t = targets.value.find(x => x.id === targetId)
  return t ? t.name : '-'
}

function levelTag(level: string) {
  const map: Record<string, string> = { low: 'info', medium: 'warning', high: 'danger', critical: 'danger' }
  return map[level] ?? ''
}

function actionTag(action: string) {
  const map: Record<string, string> = { log: '', log_drop: 'danger', log_redirect: 'warning', log_mirror: 'info' }
  return map[action] ?? ''
}

async function fetchData() {
  loading.value = true
  try {
    const [pRes, tRes] = await Promise.all([getThreatPatterns(), getRedirectTargets()])
    patterns.value = pRes.patterns
    targets.value = tRes.targets
  } catch {
    // keep empty
  } finally {
    loading.value = false
  }
}

function openAdd() {
  isEdit.value = false
  form.id = ''
  form.priority = patterns.value.length + 1
  form.src_ip = ''
  form.src_mac = ''
  form.dst_port = 0
  form.proto = 'tcp'
  form.threat_level = 'medium'
  form.action = 'log'
  form.redirect_target = 0
  form.continue_matching = false
  form.capture_packet = false
  form.description = ''
  showDialog.value = true
}

function openEdit(row: ThreatPattern) {
  isEdit.value = true
  editId.value = row.id
  form.id = row.id
  form.priority = row.priority
  form.src_ip = row.src_ip ?? ''
  form.src_mac = row.src_mac ?? ''
  form.dst_port = row.dst_port
  form.proto = row.proto
  form.threat_level = row.threat_level
  form.action = row.action
  form.redirect_target = row.redirect_target ?? 0
  form.continue_matching = row.continue_matching ?? false
  form.capture_packet = row.capture_packet ?? false
  form.description = row.description
  showDialog.value = true
}

async function handleSubmit() {
  try {
    if (isEdit.value) {
      await updateThreatPattern(editId.value, { ...form })
    } else {
      await addThreatPattern({ ...form })
    }
    ElMessage.success(t('common.success'))
    showDialog.value = false
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDelete(row: ThreatPattern) {
  try {
    await ElMessageBox.confirm(
      t('threats.confirmDelete', { id: row.id, desc: row.description }),
      t('common.confirm'),
      { type: 'warning' },
    )
    await deleteThreatPattern(row.id)
    ElMessage.success(t('common.success'))
    await fetchData()
  } catch {
    // cancelled or error
  }
}

function nextTargetId(): number {
  const used = new Set(targets.value.map(t => t.id))
  for (let i = 0; i < 16; i++) {
    if (!used.has(i)) return i
  }
  return 0
}

function openTargetAdd() {
  isTargetEdit.value = false
  targetForm.id = nextTargetId()
  targetForm.name = ''
  targetForm.interface = ''
  showTargetDialog.value = true
}

function openTargetEdit(row: RedirectTarget) {
  isTargetEdit.value = true
  targetForm.id = row.id
  targetForm.name = row.name
  targetForm.interface = row.interface
  showTargetDialog.value = true
}

async function handleTargetSubmit() {
  try {
    if (isTargetEdit.value) {
      await updateRedirectTarget(targetForm.id, { name: targetForm.name, interface: targetForm.interface })
    } else {
      await addRedirectTarget({ ...targetForm })
    }
    ElMessage.success(t('common.success'))
    showTargetDialog.value = false
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleTargetDelete(row: RedirectTarget) {
  try {
    await ElMessageBox.confirm(
      t('threats.confirmDeleteTarget', { name: row.name }),
      t('common.confirm'),
      { type: 'warning' },
    )
    await deleteRedirectTarget(row.id)
    ElMessage.success(t('common.success'))
    await fetchData()
  } catch {
    // cancelled or error
  }
}

async function moveUp(row: ThreatPattern) {
  const idx = patterns.value.findIndex(p => p.id === row.id)
  if (idx <= 0) return
  const prev = patterns.value[idx - 1]
  const curPriority = row.priority
  row.priority = prev.priority
  prev.priority = curPriority
  patterns.value.sort((a, b) => a.priority - b.priority)
  try {
    await reorderPatterns(patterns.value.map(p => p.id))
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function moveDown(row: ThreatPattern) {
  const idx = patterns.value.findIndex(p => p.id === row.id)
  if (idx < 0 || idx >= patterns.value.length - 1) return
  const next = patterns.value[idx + 1]
  const curPriority = row.priority
  row.priority = next.priority
  next.priority = curPriority
  patterns.value.sort((a, b) => a.priority - b.priority)
  try {
    await reorderPatterns(patterns.value.map(p => p.id))
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

onMounted(fetchData)
</script>

<template>
  <div>
    <h2>{{ t('threats.title') }}</h2>

    <el-alert
      v-if="!loading && targets.length === 0"
      :title="t('threats.noTargets')"
      type="warning"
      show-icon
      :closable="false"
      class="mb"
    />
    <el-alert
      v-else-if="!loading && targets.length > 0"
      :title="t('threats.targetsConfigured', { count: targets.length })"
      :description="targets.map(t => `${t.name} (${t.interface})`).join(', ')"
      type="success"
      show-icon
      :closable="false"
      class="mb"
    />

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-collapse class="mb">
          <el-collapse-item :title="t('threats.redirectTargets')">
            <el-button type="primary" size="small" class="mb" :disabled="targets.length >= 16" @click="openTargetAdd">
              {{ t('threats.addTarget') }}
            </el-button>
            <el-table :data="targets" stripe size="small">
              <el-table-column prop="id" label="ID" width="60" />
              <el-table-column prop="name" :label="t('threats.targetName')" />
              <el-table-column prop="interface" :label="t('threats.targetInterface')" />
              <el-table-column :label="t('common.action')" width="140">
                <template #default="{ row }">
                  <el-button text size="small" @click="openTargetEdit(row)">
                    {{ t('common.edit') }}
                  </el-button>
                  <el-button type="danger" text size="small" @click="handleTargetDelete(row)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-collapse-item>
        </el-collapse>

        <el-button type="primary" class="mb" @click="openAdd">
          {{ t('threats.addPattern') }}
        </el-button>

        <el-table :data="patterns" stripe>
          <el-table-column prop="priority" :label="t('threats.priority')" width="80" />
          <el-table-column prop="id" label="ID" width="60" />
          <el-table-column :label="t('threats.srcIp')" width="140">
            <template #default="{ row }">
              {{ row.src_ip || '-' }}
            </template>
          </el-table-column>
          <el-table-column :label="t('threats.srcMac')" width="160">
            <template #default="{ row }">
              {{ row.src_mac || '-' }}
            </template>
          </el-table-column>
          <el-table-column prop="dst_port" :label="t('threats.dstPort')" width="100" />
          <el-table-column prop="proto" :label="t('threats.protocol')" width="100" />
          <el-table-column :label="t('threats.threatLevel')" width="120">
            <template #default="{ row }">
              <el-tag :type="levelTag(row.threat_level)" size="small">
                {{ t(`threats.level_${row.threat_level}`, row.threat_level) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('threats.action')" width="130">
            <template #default="{ row }">
              <el-tag :type="actionTag(row.action)" size="small">
                {{ t(`threats.action_${row.action}`, row.action) }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column :label="t('threats.redirectTarget')" width="140">
            <template #default="{ row }">
              <span v-if="row.action === 'log_redirect' || row.action === 'log_mirror'">
                {{ targetName(row.redirect_target) }}
              </span>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('threats.continueMatching')" width="80">
            <template #default="{ row }">
              <el-icon v-if="row.continue_matching" color="#67c23a"><svg viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M406.656 706.944 195.84 496.256a32 32 0 1 0-45.248 45.248l233.6 233.6c12.48 12.48 32.768 12.48 45.248 0l502.08-502.08A32 32 0 1 0 886.272 228L406.592 707.008z"/></svg></el-icon>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column :label="t('threats.capturePacket')" width="80">
            <template #default="{ row }">
              <el-icon v-if="row.capture_packet" color="#67c23a"><svg viewBox="0 0 1024 1024" xmlns="http://www.w3.org/2000/svg"><path fill="currentColor" d="M406.656 706.944 195.84 496.256a32 32 0 1 0-45.248 45.248l233.6 233.6c12.48 12.48 32.768 12.48 45.248 0l502.08-502.08A32 32 0 1 0 886.272 228L406.592 707.008z"/></svg></el-icon>
              <span v-else>-</span>
            </template>
          </el-table-column>
          <el-table-column prop="description" :label="t('common.description')" />
          <el-table-column :label="t('common.action')" width="240">
            <template #default="{ row, $index }">
              <el-button text size="small" :disabled="$index === 0" @click="moveUp(row)">
                {{ t('threats.moveUp') }}
              </el-button>
              <el-button text size="small" :disabled="$index === patterns.length - 1" @click="moveDown(row)">
                {{ t('threats.moveDown') }}
              </el-button>
              <el-button text size="small" @click="openEdit(row)">
                {{ t('common.edit') }}
              </el-button>
              <el-button type="danger" text size="small" @click="handleDelete(row)">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-skeleton>

    <el-dialog
      v-model="showDialog"
      :title="isEdit ? t('threats.editPattern') : t('threats.addPattern')"
      width="500px"
    >
      <el-form label-width="120px" @submit.prevent="handleSubmit">
        <el-form-item v-if="!isEdit" label="ID">
          <el-input v-model="form.id" :placeholder="t('threats.idAutoHint')" />
        </el-form-item>
        <el-form-item :label="t('threats.priority')">
          <el-input-number v-model="form.priority" :min="1" :max="128" />
        </el-form-item>
        <el-form-item :label="t('threats.srcIp')">
          <el-input v-model="form.src_ip" placeholder="e.g. 10.0.1.0/24 or empty for any" />
        </el-form-item>
        <el-form-item :label="t('threats.srcMac')">
          <el-input v-model="form.src_mac" placeholder="e.g. aa:bb:cc:dd:ee:ff or empty for any" />
        </el-form-item>
        <el-form-item :label="t('threats.dstPort')">
          <el-input-number v-model="form.dst_port" :min="0" :max="65535" />
        </el-form-item>
        <el-form-item :label="t('threats.protocol')">
          <el-select v-model="form.proto">
            <el-option v-for="p in protocols" :key="p" :label="p.toUpperCase()" :value="p" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('threats.threatLevel')">
          <el-select v-model="form.threat_level">
            <el-option
              v-for="l in threatLevels"
              :key="l"
              :label="t(`threats.level_${l}`, l)"
              :value="l"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('threats.action')">
          <el-select v-model="form.action">
            <el-option
              v-for="a in threatActions"
              :key="a"
              :label="t(`threats.action_${a}`, a)"
              :value="a"
            />
          </el-select>
        </el-form-item>
        <el-form-item v-if="needsTarget" :label="t('threats.redirectTarget')">
          <el-select v-model="form.redirect_target">
            <el-option :label="t('threats.targetNone')" :value="0" />
            <el-option
              v-for="tgt in targets"
              :key="tgt.id"
              :label="`${tgt.id} - ${tgt.name} (${tgt.interface})`"
              :value="tgt.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('threats.continueMatching')">
          <el-switch v-model="form.continue_matching" />
        </el-form-item>
        <el-form-item :label="t('threats.capturePacket')">
          <el-switch v-model="form.capture_packet" />
        </el-form-item>
        <el-form-item :label="t('common.description')">
          <el-input v-model="form.description" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog
      v-model="showTargetDialog"
      :title="isTargetEdit ? t('threats.editTarget') : t('threats.addTarget')"
      width="450px"
    >
      <el-form label-width="120px" @submit.prevent="handleTargetSubmit">
        <el-form-item :label="t('threats.targetId')">
          <el-input-number v-model="targetForm.id" :min="0" :max="15" :disabled="isTargetEdit" />
        </el-form-item>
        <el-form-item :label="t('threats.targetName')">
          <el-input v-model="targetForm.name" placeholder="e.g. honeypot-vm" />
        </el-form-item>
        <el-form-item :label="t('threats.targetInterface')">
          <el-input v-model="targetForm.interface" placeholder="e.g. ens34, veth-hp" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showTargetDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleTargetSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
</style>
