<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { getWhitelist, addWhitelistEntry, deleteWhitelistEntry } from '@/api/whitelist'
import type { WhitelistEntry } from '@/api/whitelist'

const { t } = useI18n()

const loading = ref(true)
const list = ref<WhitelistEntry[]>([])
const showDialog = ref(false)
const form = reactive({ ip: '' })

async function fetchData() {
  loading.value = true
  try {
    const res = await getWhitelist()
    list.value = res.whitelist
  } catch {
    // keep empty
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  try {
    await addWhitelistEntry({ ip: form.ip })
    ElMessage.success(t('common.success'))
    showDialog.value = false
    form.ip = ''
    await fetchData()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDelete(ip: string) {
  try {
    await ElMessageBox.confirm(t('whitelist.confirmDelete', { ip }), t('common.confirm'), { type: 'warning' })
    await deleteWhitelistEntry(ip)
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
    <h2>{{ t('whitelist.title') }}</h2>

    <el-button type="primary" class="mb" @click="showDialog = true">
      {{ t('whitelist.addEntry') }}
    </el-button>

    <el-skeleton :loading="loading" animated>
      <template #default>
        <el-table :data="list" stripe>
          <el-table-column prop="ip" :label="t('whitelist.ip')" />
          <el-table-column prop="mac" :label="t('common.mac')" />
          <el-table-column prop="created_at" :label="t('common.time')" />
          <el-table-column :label="t('common.action')" width="120">
            <template #default="{ row }">
              <el-button type="danger" text size="small" @click="handleDelete(row.ip)">
                {{ t('common.delete') }}
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>
    </el-skeleton>

    <el-dialog v-model="showDialog" :title="t('whitelist.addEntry')" width="420px">
      <el-form label-width="100px">
        <el-form-item :label="t('whitelist.ip')">
          <el-input v-model="form.ip" placeholder="e.g. 10.0.1.200" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleAdd">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
</style>
