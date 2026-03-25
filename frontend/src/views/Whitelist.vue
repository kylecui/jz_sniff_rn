<script setup lang="ts">
import { ElMessage, ElMessageBox } from 'element-plus'
import { getWhitelist, addWhitelistEntry, deleteWhitelistEntry } from '@/api/whitelist'
import type { WhitelistEntry } from '@/api/whitelist'
import { getDhcpExceptions, addDhcpException, deleteDhcpException } from '@/api/dhcp'
import type { DhcpException } from '@/api/dhcp'

const { t } = useI18n()

const activeTab = ref('whitelist')

const loading = ref(true)
const list = ref<WhitelistEntry[]>([])
const showDialog = ref(false)
const form = reactive({ ip: '' })

const dhcpLoading = ref(true)
const dhcpList = ref<DhcpException[]>([])
const showDhcpDialog = ref(false)
const dhcpForm = reactive({ ip: '' })

async function fetchWhitelist() {
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

async function fetchDhcpExceptions() {
  dhcpLoading.value = true
  try {
    const res = await getDhcpExceptions()
    dhcpList.value = res.exceptions
  } catch {
    // keep empty
  } finally {
    dhcpLoading.value = false
  }
}

async function handleAdd() {
  try {
    await addWhitelistEntry({ ip: form.ip })
    ElMessage.success(t('common.success'))
    showDialog.value = false
    form.ip = ''
    await fetchWhitelist()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDelete(ip: string) {
  try {
    await ElMessageBox.confirm(t('whitelist.confirmDelete', { ip }), t('common.confirm'), { type: 'warning' })
    await deleteWhitelistEntry(ip)
    ElMessage.success(t('common.success'))
    await fetchWhitelist()
  } catch {
    // cancelled or error
  }
}

async function handleDhcpAdd() {
  try {
    await addDhcpException({ ip: dhcpForm.ip })
    ElMessage.success(t('common.success'))
    showDhcpDialog.value = false
    dhcpForm.ip = ''
    await fetchDhcpExceptions()
  } catch (e: unknown) {
    ElMessage.error((e as Error).message)
  }
}

async function handleDhcpDelete(mac: string) {
  try {
    await ElMessageBox.confirm(t('dhcp.confirmDelete', { mac }), t('common.confirm'), { type: 'warning' })
    await deleteDhcpException(mac)
    ElMessage.success(t('common.success'))
    await fetchDhcpExceptions()
  } catch {
    // cancelled or error
  }
}

function onTabChange(tab: string) {
  if (tab === 'whitelist') fetchWhitelist()
  else fetchDhcpExceptions()
}

onMounted(() => {
  fetchWhitelist()
  fetchDhcpExceptions()
})
</script>

<template>
  <div>
    <h2>{{ t('whitelist.title') }}</h2>

    <el-tabs v-model="activeTab" @tab-change="onTabChange">
      <el-tab-pane :label="t('dhcp.tabWhitelist')" name="whitelist">
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
      </el-tab-pane>

      <el-tab-pane :label="t('dhcp.tabDhcp')" name="dhcp">
        <el-button type="primary" class="mb" @click="showDhcpDialog = true">
          {{ t('dhcp.addException') }}
        </el-button>

        <el-skeleton :loading="dhcpLoading" animated>
          <template #default>
            <el-table :data="dhcpList" stripe>
              <el-table-column prop="ip" :label="t('dhcp.serverIp')" />
              <el-table-column prop="mac" :label="t('dhcp.serverMac')" />
              <el-table-column :label="t('common.time')">
                <template #default="{ row }">
                  {{ row.created_at_ns ? new Date(row.created_at_ns / 1e6).toLocaleString() : '-' }}
                </template>
              </el-table-column>
              <el-table-column :label="t('common.action')" width="120">
                <template #default="{ row }">
                  <el-button type="danger" text size="small" @click="handleDhcpDelete(row.mac)">
                    {{ t('common.delete') }}
                  </el-button>
                </template>
              </el-table-column>
            </el-table>
          </template>
        </el-skeleton>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="showDialog" :title="t('whitelist.addEntry')" width="420px">
      <el-form label-width="100px" @submit.prevent="handleAdd">
        <el-form-item :label="t('whitelist.ip')">
          <el-input v-model="form.ip" placeholder="e.g. 10.0.1.200" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleAdd">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showDhcpDialog" :title="t('dhcp.addException')" width="420px">
      <el-form label-width="100px" @submit.prevent="handleDhcpAdd">
        <el-form-item :label="t('dhcp.serverIp')">
          <el-input v-model="dhcpForm.ip" placeholder="e.g. 10.174.254.1" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showDhcpDialog = false">{{ t('common.cancel') }}</el-button>
        <el-button type="primary" @click="handleDhcpAdd">{{ t('common.confirm') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.mb {
  margin-bottom: 12px;
}
</style>
