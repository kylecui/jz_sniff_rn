<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { getPolicies, addPolicy, updatePolicy, deletePolicy } from '@/api/policies'
import type { Policy, PolicyCreate } from '@/api/policies'

const { t } = useI18n()

const activeTab = ref('manual')
const loading = ref(true)
const policies = ref<Policy[]>([])

const manualPolicies = computed(() => policies.value.filter((p) => !p.auto))
const autoPolicies = computed(() => policies.value.filter((p) => p.auto))

// Dialog state
const showDialog = ref(false)
const isEdit = ref(false)
const editId = ref(0)
const form = reactive<PolicyCreate>({
  action: 'pass',
  src_ip: '',
  dst_ip: '',
  src_port: undefined,
  dst_port: undefined,
  protocol: '',
  priority: 100,
})

const protocols = ['TCP', 'UDP', 'ICMP', 'ANY']
const actions: PolicyCreate['action'][] = ['pass', 'drop', 'redirect', 'mirror']

function actionTag(action: string) {
  const map: Record<string, string> = { pass: 'success', drop: 'danger', redirect: 'warning', mirror: '' }
  return map[action] ?? ''
}

function actionLabel(action: string) {
  const map: Record<string, string> = {
    pass: t('policies.actionPass'),
    drop: t('policies.actionDrop'),
    redirect: t('policies.actionRedirect'),
    mirror: t('policies.actionMirror'),
  }
  return map[action] ?? action
}

async function fetchData() {
  loading.value = true
  try {
    const res = await getPolicies()
    policies.value = res.policies
  } catch {
    // keep empty
  } finally {
    loading.value = false
  }
}

function openAdd() {
  isEdit.value = false
  form.action = 'pass'
  form.src_ip = ''
  form.dst_ip = ''
  form.src_port = undefined
  form.dst_port = undefined
  form.protocol = ''
  form.priority = 100
  showDialog.value = true
}

function openEdit(row: Policy) {
  isEdit.value = true
  editId.value = row.id
  form.action = row.action
  form.src_ip = row.src_ip ?? ''
  form.dst_ip = row.dst_ip ?? ''
  form.src_port = row.src_port
  form.dst_port = row.dst_port
  form.protocol = row.protocol ?? ''
  form.priority = row.priority ?? 100
  showDialog.value = true
}

async function handleSubmit() {
  try {
    if (isEdit.value) {
      await updatePolicy(editId.value, { ...form })
    } else {
      await addPolicy({ ...form })
    }
    ElMessage.success(t('common.success'))
    showDialog.value = false
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDelete(id: number) {
  try {
    await ElMessageBox.confirm(t('policies.confirmDelete', { id }), t('common.confirm'), { type: 'warning' })
    await deletePolicy(id)
    ElMessage.success(t('common.success'))
    await fetchData()
  } catch {
    // cancelled or error
  }
}

onMounted(fetchData)
</script>

<template>
  <div>
    <h2>{{ t('policies.title') }}</h2>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-tabs v-model="activeTab">
          <!-- Manual Policies -->
          <el-tab-pane :label="t('policies.manual')" name="manual">
            <el-button type="primary" class="mb" @click="openAdd">
              {{ t('policies.addPolicy') }}
            </el-button>
            <el-table :data="manualPolicies" stripe>
              <el-table-column prop="id" label="ID" width="60" />
              <el-table-column prop="src_ip" :label="t('policies.srcIp')" />
              <el-table-column prop="dst_ip" :label="t('policies.dstIp')" />
              <el-table-column prop="src_port" :label="t('policies.srcPort')" width="100" />
              <el-table-column prop="dst_port" :label="t('policies.dstPort')" width="100" />
              <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" />
              <el-table-column :label="t('common.action')" width="100">
                <template #default="{ row }">
                  <el-tag :type="actionTag(row.action)" size="small">
                    {{ actionLabel(row.action) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="priority" :label="t('policies.priority')" width="80" />
              <el-table-column :label="t('common.action')" width="140">
                <template #default="{ row }">
                  <el-button text size="small" @click="openEdit(row)">
                    {{ t('common.edit') }}
                  </el-button>
                  <el-button type="danger" text size="small" @click="handleDelete(row.id)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>

          <!-- Auto Policies -->
          <el-tab-pane :label="t('policies.auto')" name="auto">
            <el-alert :title="t('policies.autoReadonly')" type="info" show-icon :closable="false" class="mb" />
            <el-table :data="autoPolicies" stripe>
              <el-table-column prop="id" label="ID" width="60" />
              <el-table-column prop="src_ip" :label="t('policies.srcIp')" />
              <el-table-column prop="dst_ip" :label="t('policies.dstIp')" />
              <el-table-column prop="src_port" :label="t('policies.srcPort')" width="100" />
              <el-table-column prop="dst_port" :label="t('policies.dstPort')" width="100" />
              <el-table-column prop="protocol" :label="t('policies.protocol')" width="100" />
              <el-table-column :label="t('common.action')" width="100">
                <template #default="{ row }">
                  <el-tag :type="actionTag(row.action)" size="small">
                    {{ actionLabel(row.action) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="priority" :label="t('policies.priority')" width="80" />
              <el-table-column width="80">
                <template #default>
                  <el-tag type="info" size="small">{{ t('policies.autoTag') }}</el-tag>
                </template>
              </el-table-column>
            </el-table>
          </el-tab-pane>
        </el-tabs>
      </template>
    </el-skeleton>

    <!-- Add / Edit Dialog -->
    <el-dialog
      v-model="showDialog"
      :title="isEdit ? t('policies.editPolicy') : t('policies.addPolicy')"
      width="500px"
    >
      <el-form label-width="100px" @submit.prevent="handleSubmit">
        <el-form-item :label="t('policies.srcIp')">
          <el-input v-model="form.src_ip" placeholder="0.0.0.0/0" />
        </el-form-item>
        <el-form-item :label="t('policies.dstIp')">
          <el-input v-model="form.dst_ip" placeholder="0.0.0.0/0" />
        </el-form-item>
        <el-form-item :label="t('policies.srcPort')">
          <el-input-number v-model="form.src_port" :min="0" :max="65535" />
        </el-form-item>
        <el-form-item :label="t('policies.dstPort')">
          <el-input-number v-model="form.dst_port" :min="0" :max="65535" />
        </el-form-item>
        <el-form-item :label="t('policies.protocol')">
          <el-select v-model="form.protocol" placeholder="ANY">
            <el-option v-for="p in protocols" :key="p" :label="p" :value="p" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('common.action')">
          <el-select v-model="form.action">
            <el-option v-for="a in actions" :key="a" :label="actionLabel(a)" :value="a" />
          </el-select>
        </el-form-item>
        <el-form-item :label="t('policies.priority')">
          <el-input-number v-model="form.priority" :min="0" :max="9999" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleSubmit">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
</style>
