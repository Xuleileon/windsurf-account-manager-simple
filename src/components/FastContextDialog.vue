<template>
  <el-dialog v-model="visible" title="Fast Context 自动账号调度" width="540px" @open="load">
    <p>已登录且 API key 就绪的账号会自动加入调度。优先选择冷却已结束、最久未使用的账号；一次检索使用同一个账号。</p>
    <el-table :data="accounts" empty-text="请先添加账号并登录，再刷新账号信息">
      <el-table-column prop="label" label="账号" />
      <el-table-column label="凭据状态"><template #default="{ row }">{{ row.ready ? '已就绪' : '需登录或刷新' }}</template></el-table-column>
    </el-table>
    <p>实际可用性以检索响应为准。认证失效后请重新登录；服务端限流触发全局冷却，不换号重放失败请求。密钥仅通过本机进程管道传递。</p>
    <template #footer><el-button @click="load" :loading="busy">刷新列表</el-button></template>
  </el-dialog>
</template>
<script setup lang="ts">
import { ref } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import { ElMessage } from 'element-plus';
const visible = defineModel<boolean>({ default: false });
const accounts = ref<{ id: string; label: string; ready: boolean }[]>([]);
const busy = ref(false);
async function load() {
  busy.value = true;
  try { accounts.value = (await invoke<{ accounts: typeof accounts.value }>('fast_context_accounts')).accounts; }
  catch { ElMessage.error('无法读取账号，请检查 WAM 状态'); }
  finally { busy.value = false; }
}
</script>
