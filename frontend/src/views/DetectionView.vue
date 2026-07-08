<template>
  <div class="det-wrap">
    <h2 class="page-title">🔍 基于大模型的攻击行为检测 <small>LLM + RAG Enhanced · Multi-Source Data Fusion</small></h2>

    <!-- Stats Row -->
    <n-grid :cols="4" :x-gap="12" :y-gap="12" responsive="screen" class="mb-3">
      <n-grid-item><n-card size="small" class="stat-card stat-red"><n-statistic label="高危告警" :value="stats.high" /></n-card></n-grid-item>
      <n-grid-item><n-card size="small" class="stat-card stat-orange"><n-statistic label="中危告警" :value="stats.medium" /></n-card></n-grid-item>
      <n-grid-item><n-card size="small" class="stat-card stat-cyan"><n-statistic label="低危告警" :value="stats.low" /></n-card></n-grid-item>
      <n-grid-item><n-card size="small" class="stat-card stat-blue"><n-statistic label="分析事件总数" :value="stats.total_events" /></n-card></n-grid-item>
    </n-grid>

    <n-grid :cols="8" :x-gap="16" :y-gap="16" responsive="screen">
      <!-- Alerts Panel -->
      <n-grid-item :span="5">
        <n-card :bordered="false" class="section-card">
          <template #header>
            <div class="section-header">
              <span>🔔 实时告警流</span>
              <n-space>
                <n-input v-model:value="alertTimeStart" type="text" placeholder="开始时间" size="tiny" style="width:160px" />
                <n-input v-model:value="alertTimeEnd" type="text" placeholder="结束时间" size="tiny" style="width:160px" />
                <n-button type="primary" size="small" @click="runAnalysis" :loading="analyzing">▶ 全管线分析</n-button>
                <n-button size="small" @click="pollAll">🔄 刷新</n-button>
              </n-space>
            </div>
          </template>
          <div class="alerts-box">
            <n-empty v-if="alerts.length === 0" description="暂无告警数据" style="padding: 60px 0">
              <template #extra>
                <p style="font-size:12px;color:#6b7280">请先在「场景管理」启动攻击场景，再点击「执行全管线分析」</p>
              </template>
            </n-empty>
            <div v-for="a in filteredAlerts" :key="a.id" class="alert-item" :class="'alert-' + a.severity">
              <div class="alert-top">
                <strong>{{ a.title || 'Alert' }}</strong>
                <n-space>
                  <n-tag :type="a.severity === 'high' ? 'error' : (a.severity === 'medium' ? 'warning' : 'info')" size="tiny">{{ (a.severity || '').toUpperCase() }}</n-tag>
                  <n-tag :type="a.source === 'llm_deep_analysis' ? 'info' : 'default'" size="tiny">{{ a.source || 'rule' }}</n-tag>
                  <n-tag v-if="a.ai_specific" type="info" size="tiny">AI</n-tag>
                </n-space>
              </div>
              <div class="alert-desc">{{ a.description }}</div>
              <div class="alert-meta">
                <span class="text-muted" style="font-size:10px">{{ toBeijingTime(a.timestamp || a.created_at) }}</span>
                <n-tag size="tiny">{{ a.technique_id || '?' }}</n-tag>
                <span class="text-muted">{{ a.technique_name }}</span>
                <span class="text-muted">| {{ ((a.confidence || 0) * 100).toFixed(0) }}%</span>
              </div>
            </div>
          </div>
        </n-card>
      </n-grid-item>

      <!-- Right Panel -->
      <n-grid-item :span="3">
        <!-- Tactic Distribution -->
        <n-card title="☰ MITRE ATT&CK 战术分布" size="small" :bordered="false" class="mb-3 section-card">
          <n-empty v-if="!tacticKeys.length" description="等待数据..." style="font-size: 12px" />
          <div v-for="k in tacticKeys" :key="k" class="tactic-row">
            <span>{{ k }}</span><n-tag type="info" size="tiny">{{ tactics[k] }}</n-tag>
          </div>
        </n-card>

        <!-- RAG Search -->
        <n-card title="🔍 RAG 知识库检索" size="small" :bordered="false" class="mb-3 section-card">
          <n-space vertical>
            <n-input-group>
              <n-input v-model:value="ragQuery" placeholder="搜索攻击模式、TTP、APT组织..." size="small" @keyup.enter="doRagSearch" />
              <n-button type="primary" size="small" @click="doRagSearch">搜索</n-button>
            </n-input-group>
            <n-spin :show="ragSearching">
              <n-empty v-if="!ragResults.length && !ragSearching" description="输入关键词检索 MITRE ATT&CK 知识库" style="font-size: 11px" />
              <div v-for="r in ragResults" :key="r.title" class="rag-item">
                <strong>{{ r.title }}</strong>
                <n-space>
                  <n-tag type="info" size="tiny">{{ r.category }}</n-tag>
                  <n-tag size="tiny">{{ (r.similarity * 100).toFixed(0) }}%</n-tag>
                </n-space>
                <div class="rag-snippet">{{ (r.content || '').substring(0, 120) }}...</div>
              </div>
            </n-spin>
          </n-space>
        </n-card>

        <!-- Engine Info -->
        <n-card title="⚙ 检测引擎技术栈" size="small" :bordered="false" class="section-card">
          <div class="info-row"><span>规则引擎</span><n-tag type="success" size="tiny">9条内置规则</n-tag></div>
          <div class="info-row"><span>RAG知识增强</span><n-tag type="info" size="tiny">37篇安全文档</n-tag></div>
          <div class="info-row"><span>LLM深度分析</span><n-tag type="info" size="tiny">Qwen-Flash</n-tag></div>
          <div class="info-row"><span>数据源</span><n-tag type="info" size="tiny">3类 (日志+行为+流量)</n-tag></div>
          <div class="info-row"><span>威胁建模</span><n-tag type="warning" size="tiny">MITRE ATT&CK v15</n-tag></div>
        </n-card>
      </n-grid-item>
    </n-grid>

    <!-- Report Modal -->
    <n-modal v-model:show="showReport" title="📋 综合分析报告" style="max-width: 960px" preset="card">
      <n-spin :show="analyzing">
        <n-space v-if="evidenceCaseId" align="center" style="margin-bottom: 12px; flex-wrap: wrap">
          <n-tag size="small">case_id: <code>{{ evidenceCaseId }}</code></n-tag>
          <n-tag size="small">chain_id: <code>{{ evidenceChainId || '-' }}</code></n-tag>
          <n-tag size="small">final_hash: <code>{{ evidenceFinalHash || '-' }}</code></n-tag>
          <n-tag v-if="evidenceVerified !== null" :type="evidenceVerified ? 'success' : 'error'" size="small">
            {{ evidenceVerified ? 'hash 校验通过' : 'hash 校验失败' }}
          </n-tag>
        </n-space>
        <pre class="report-pre">{{ reportText }}</pre>
      </n-spin>
      <template #footer>
        <n-button v-if="evidenceCaseId" size="small" :loading="verifyingEvidence" @click="runEvidenceVerify">🔐 校验证据</n-button>
        <n-button v-if="evidenceCaseId" size="small" @click="downloadEvidence('json')">⬇ 导出JSON</n-button>
        <n-button v-if="evidenceCaseId" size="small" @click="downloadEvidence('markdown')">⬇ 导出Markdown</n-button>
        <n-button type="primary" size="small" @click="copyReport">📋 复制报告</n-button>
        <n-button size="small" @click="showReport = false">关闭</n-button>
      </template>
    </n-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useMessage } from 'naive-ui'
import { getDetectionStats, getAlerts, runFullAnalysis, ragSearch, verifyEvidenceCase, exportEvidenceCase } from '@/api/detection'
import { toBeijingTime } from '@/utils/time'

const message = useMessage()
const stats = ref({ high: 0, medium: 0, low: 0, total_events: 0, by_tactic: {} as Record<string, number> })
const alerts = ref<any[]>([])
const analyzing = ref(false)
const showReport = ref(false)
const alertTimeStart = ref('')
const alertTimeEnd = ref('')
const reportText = ref('')
const evidenceCaseId = ref('')
const evidenceChainId = ref('')
const evidenceFinalHash = ref('')
const evidenceVerified = ref<boolean | null>(null)
const verifyingEvidence = ref(false)
const ragQuery = ref('')
const ragResults = ref<any[]>([])
const ragSearching = ref(false)
let pollTimer: ReturnType<typeof setInterval> | null = null

const filteredAlerts = computed(() => {
  let result = alerts.value
  if (alertTimeStart.value) {
    result = result.filter((a: any) => (a.timestamp || a.created_at || '') >= alertTimeStart.value)
  }
  if (alertTimeEnd.value) {
    result = result.filter((a: any) => (a.timestamp || a.created_at || '') <= alertTimeEnd.value)
  }
  return result
})

const tactics = computed(() => stats.value.by_tactic || {})
const tacticKeys = computed(() => Object.keys(tactics.value).sort((a, b) => tactics.value[b] - tactics.value[a]))

async function fetchStats() {
  try {
    const res = await getDetectionStats()
    if (res.data?.ok) {
      const d = res.data.data
      stats.value = {
        high: d.by_severity?.high || 0,
        medium: d.by_severity?.medium || 0,
        low: d.by_severity?.low || 0,
        total_events: d.total_events || 0,
        by_tactic: d.by_tactic || {},
      }
    }
  } catch {}
}

async function fetchAlerts() {
  try {
    const res = await getAlerts(30)
    if (res.data?.ok) alerts.value = res.data.data || []
  } catch {}
}

function pollAll() { fetchStats(); fetchAlerts() }

async function runAnalysis() {
  analyzing.value = true
  try {
    const res = await runFullAnalysis()
    if (res.data?.ok) {
      reportText.value = res.data.data?.report || '(空报告)'
      const ec = res.data.data?.evidence_case
      evidenceCaseId.value = ec?.case_id || ''
      evidenceChainId.value = ec?.chain_id || ''
      evidenceFinalHash.value = ec?.final_hash || ''
      evidenceVerified.value = null
      showReport.value = true
      pollAll()
      message.success('全管线分析完成！')
    } else {
      message.error('分析失败: ' + (res.data?.error || '未知错误'))
    }
  } catch { message.error('请求失败') }
  finally { analyzing.value = false }
}

async function doRagSearch() {
  if (!ragQuery.value.trim()) return
  ragSearching.value = true
  try {
    const res = await ragSearch(ragQuery.value.trim())
    ragResults.value = res.data?.data || []
  } catch {}
  finally { ragSearching.value = false }
}

function copyReport() {
  navigator.clipboard?.writeText(reportText.value).then(() => message.success('报告已复制'))
}

async function runEvidenceVerify() {
  if (!evidenceCaseId.value) return
  verifyingEvidence.value = true
  try {
    const res = await verifyEvidenceCase(evidenceCaseId.value)
    if (res.data?.ok) {
      const all = !!res.data.data?.all_matched
      evidenceVerified.value = all
      message[all ? 'success' : 'error'](all ? '证据 hash 校验通过' : '证据 hash 校验失败')
    } else {
      message.error(res.data?.error || '校验失败')
    }
  } catch (e: any) {
    message.error('校验失败: ' + (e?.response?.data?.error || e?.message || ''))
  } finally {
    verifyingEvidence.value = false
  }
}

async function downloadEvidence(format: 'json' | 'markdown') {
  if (!evidenceCaseId.value) return
  try {
    const res = await exportEvidenceCase(evidenceCaseId.value, format)
    const blob = res.data instanceof Blob
      ? res.data
      : new Blob([res.data], {
        type: format === 'markdown' ? 'text/markdown;charset=utf-8' : 'application/json;charset=utf-8',
      })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `evidence_${evidenceCaseId.value}.${format === 'markdown' ? 'md' : 'json'}`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  } catch (e: any) {
    message.error('导出失败: ' + (e?.response?.data?.error || e?.message || ''))
  }
}

onMounted(() => {
  pollAll()
  pollTimer = setInterval(pollAll, 3000)
})
onUnmounted(() => { if (pollTimer) clearInterval(pollTimer) })
</script>

<style scoped>
.det-wrap { max-width: 1200px; margin: 0 auto; }
.page-title { font-size: 20px; margin-bottom: 16px; }
.page-title small { font-size: 13px; color: #6b7280; font-weight: 400; }
.mb-3 { margin-bottom: 16px; }
.stat-card { border-radius: 14px; text-align: center; }
.section-card { border-radius: 14px; }
.section-header { display: flex; align-items: center; justify-content: space-between; width: 100%; }
.alerts-box { max-height: 500px; overflow-y: auto; }
.alert-item { padding: 12px; border-bottom: 1px solid #f0f0f0; }
.alert-item.alert-high { border-left: 4px solid #e74c3c; background: #fdecea; }
.alert-item.alert-medium { border-left: 4px solid #f59e0b; background: #fff8e6; }
.alert-item.alert-low { border-left: 4px solid #3b6df0; background: #e8f0ff; }
.alert-top { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.alert-desc { font-size: 12px; color: #6b7280; margin-bottom: 6px; }
.alert-meta { display: flex; gap: 8px; align-items: center; font-size: 11px; }
.text-muted { color: #6b7280; }
.tactic-row { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; font-size: 12px; }
.rag-item { padding: 8px 0; border-bottom: 1px solid #f0f0f0; }
.rag-snippet { font-size: 11px; color: #6b7280; margin-top: 4px; }
.info-row { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; font-size: 12px; }
.report-pre { background: #f8fafc; padding: 20px; border-radius: 8px; max-height: 500px; overflow: auto; font-size: 13px; line-height: 1.8; white-space: pre-wrap; }
</style>
