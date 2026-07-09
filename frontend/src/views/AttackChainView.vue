<template>
  <div class="ac-wrap">
    <div class="ac-header">
      <div>
        <h2>攻击链分析</h2>
        <p class="text-muted">AttackReports（SQL Server）+ Neo4j（AttackEvent/Technique/NEXT_STAGE）联合展示</p>
      </div>
      <n-space vertical size="small" style="width:100%">
        <n-space>
          <n-button size="small" @click="fetchReports">刷新列表</n-button>
          <n-button type="primary" size="small" @click="startEngine" :loading="engineRunning">启动分析引擎</n-button>
          <n-button size="small" @click="stopEngine">停止分析引擎</n-button>
          <n-tag :type="engineRunning ? 'error' : 'success'" size="small">{{ engineRunning ? '运行中' : '已停止' }}</n-tag>
          <span v-if="statusText" class="text-muted" style="font-size:12px; max-width:300px">{{ statusText }}</span>
        </n-space>
        <n-space align="center">
          <span class="text-muted" style="font-size:12px">时间范围(可选):</span>
          <n-input v-model:value="timeStart" type="text" placeholder="开始时间 如 2026-07-07T14:00" size="tiny" style="width:200px" />
          <span class="text-muted">~</span>
          <n-input v-model:value="timeEnd" type="text" placeholder="结束时间(留空=现在)" size="tiny" style="width:200px" />
          <n-button size="tiny" type="info" @click="runUnified" :loading="unifying">🤖 多源LLM分析</n-button>
          <n-tag v-if="graphMode" size="small" :type="graphMode === 'neo4j' ? 'success' : 'warning'">
            {{ graphMode === 'neo4j' ? 'Neo4j' : 'DataBridge' }}
          </n-tag>
        </n-space>
      </n-space>
    </div>

    <n-grid :cols="12" :x-gap="16" :y-gap="16" responsive="screen">
      <n-grid-item :span="3">
        <n-card title="AttackReports 列表" :bordered="false" class="section-card">
          <n-data-table :columns="columns" :data="reports" :bordered="false" size="small" max-height="500"
            :row-props="(row: any) => ({ style: 'cursor:pointer', onClick: () => selectReport(row) })" />
          <n-pagination v-if="total > pageSize" :page="page" :page-size="pageSize" :item-count="total"
            @update:page="(p: any) => { page = Number(p); fetchReports() }" class="mt-2" />
        </n-card>
      </n-grid-item>

      <n-grid-item :span="6">
        <n-card :title="'攻击链详情 — ' + (selectedId || '请选择报告')" :bordered="false" class="section-card">
          <n-tabs type="line" size="small" v-model:value="activeTab">
            <n-tab-pane name="summary" tab="拓扑概览">
              <div ref="graphBox" class="graph-box">
                <n-empty v-if="!graphData" description="请选择一个攻击报告" />
                <div v-else class="graph-visual">
                  <p class="graph-summary">节点数: {{ graphData.nodes?.length || 0 }} | 边数: {{ graphData.edges?.length || 0 }}</p>
                  <!-- SVG Attack Chain Visualization -->
                  <svg :width="svgW" :height="svgH" class="chain-svg" @click="onSvgClick">
                    <!-- Edges (arrows) -->
                    <defs>
                      <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#e74c3c" />
                      </marker>
                      <marker id="arrowhead-green" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#27ae60" />
                      </marker>
                      <marker id="arrowhead-blue" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
                        <polygon points="0 0, 10 3.5, 0 7" fill="#2980b9" />
                      </marker>
                    </defs>
                    <!-- Edge lines with clickable areas -->
                    <g v-for="(edge, ei) in svgEdges" :key="'e'+ei" class="edge-group" @click.stop="onEdgeClick(edge, ei)">
                      <line :x1="edge.x1" :y1="edge.y1" :x2="edge.x2" :y2="edge.y2"
                        :stroke="edge.color || '#e74c3c'" stroke-width="3" 
                        :marker-end="'url(#arrowhead' + (edge.colorSuffix || '') + ')'"
                        class="edge-line" />
                      <!-- Edge label -->
                      <text :x="(edge.x1 + edge.x2) / 2" :y="(edge.y1 + edge.y2) / 2 - 6"
                        text-anchor="middle" font-size="9" fill="#7f8c8d"
                        class="edge-label">{{ edge.label || '' }}</text>
                      <!-- Invisible wider click target -->
                      <line :x1="edge.x1" :y1="edge.y1" :x2="edge.x2" :y2="edge.y2"
                        stroke="transparent" stroke-width="20"
                        style="cursor:pointer" />
                    </g>
                    <!-- Nodes -->
                    <g v-for="(node, ni) in svgNodes" :key="'n'+ni" class="node-group" @click.stop="onNodeClick(node)">
                      <rect :x="node.x - node.w/2" :y="node.y - 20" :width="node.w" height="36"
                        :rx="node.type === 'threat' ? 4 : (node.type === 'host' ? 4 : 18)"
                        :fill="node.color || (node.type === 'threat' ? '#e74c3c' : (node.type === 'host' ? '#3b6df0' : '#f39c12'))"
                        stroke="#fff" stroke-width="2" class="node-rect" />
                      <text :x="node.x" :y="node.y - 2" text-anchor="middle" fill="#fff"
                        font-size="10" font-weight="bold">{{ node.shortLabel }}</text>
                      <text :x="node.x" :y="node.y + 28" text-anchor="middle" fill="#6b7280"
                        font-size="9">{{ node.label }}</text>
                    </g>
                  </svg>
                  <!-- mode indicator -->
                  <n-alert v-if="graphMode === 'simulation'" type="warning" :bordered="false" class="mt-2">
                    <template #header>降级模式</template>
                    Neo4j 不可用，攻击链基于 DataBridge 内存数据构建。因果推理和实体拓扑受限。
                  </n-alert>
                </div>
              </div>
            </n-tab-pane>
            <n-tab-pane name="edges" tab="边详情">
              <div v-if="graphData?.edges?.length" class="edge-detail-panel">
                <n-table :bordered="true" :single-line="false" size="small">
                  <thead>
                    <tr>
                      <th>来源</th><th>目标</th><th>类型</th><th>置信度</th><th>证据来源</th><th>时间间隔(s)</th><th>操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="(edge, idx) in graphData.edges" :key="idx" :class="{ 'edge-selected': selectedEdgeIdx === idx }">
                      <td>{{ getNodeLabel(edge.from || edge.source) }}</td>
                      <td>{{ getNodeLabel(edge.to || edge.target) }}</td>
                      <td><n-tag size="tiny" :type="edgeTypeTag(edge.edge_type || edge.label)">{{ edge.edge_type || edge.label }}</n-tag></td>
                      <td>{{ edge.confidence || 'N/A' }}</td>
                      <td><code style="font-size:10px">{{ edge.evidence_source || '-' }}</code></td>
                      <td>{{ edge.time_interval ?? '-' }}</td>
                      <td>
                        <n-button size="tiny" @click="showEdgeEvidence(edge, idx)">查看证据</n-button>
                      </td>
                    </tr>
                  </tbody>
                </n-table>
              </div>
              <n-empty v-else description="该报告没有边数据" />
            </n-tab-pane>
            <n-tab-pane name="lateral" tab="横向移动">
              <div v-if="lateralPaths.length > 0">
                <n-table :bordered="true" size="small">
                  <thead>
                    <tr><th>源主机</th><th>目标主机</th><th>凭据</th><th>技术</th><th>时间</th><th>描述</th></tr>
                  </thead>
                  <tbody>
                    <tr v-for="(lp, i) in lateralPaths" :key="i">
                      <td><n-tag type="error">{{ lp.source_host }}</n-tag></td>
                      <td><n-tag type="warning">{{ lp.target_host }}</n-tag></td>
                      <td>{{ lp.credential || '-' }}</td>
                      <td>{{ lp.technique }}</td>
                      <td>{{ lp.timestamp?.substring(0, 19) || '-' }}</td>
                      <td><span style="font-size:11px">{{ lp.description }}</span></td>
                    </tr>
                  </tbody>
                </n-table>
              </div>
              <n-empty v-else description="未检测到横向移动路径" />
            </n-tab-pane>
            <n-tab-pane name="evidence" tab="证据详情">
              <div v-if="edgeEvidence">
                <n-descriptions bordered size="small" :column="1">
                  <n-descriptions-item label="来源事件">
                    {{ edgeEvidence.fromId }} → {{ edgeEvidence.toId }}
                  </n-descriptions-item>
                  <n-descriptions-item label="边类型">
                    <n-tag :type="edgeTypeTag(edgeEvidence.evidence?.type)">{{ edgeEvidence.evidence?.type }}</n-tag>
                  </n-descriptions-item>
                  <n-descriptions-item label="置信度">
                    <n-tag :type="edgeEvidence.evidence?.confidence === 'High' ? 'success' : (edgeEvidence.evidence?.confidence === 'Medium' ? 'warning' : 'default')">
                      {{ edgeEvidence.evidence?.confidence }}
                    </n-tag>
                  </n-descriptions-item>
                  <n-descriptions-item label="证据来源">{{ edgeEvidence.evidence?.evidence_source || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="时间间隔">{{ edgeEvidence.evidence?.time_interval }} 秒</n-descriptions-item>
                  <n-descriptions-item label="描述">{{ edgeEvidence.evidence?.description || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="证据实体">{{ edgeEvidence.evidence?.evidence_entity || '-' }}</n-descriptions-item>
                </n-descriptions>
                <n-button size="small" @click="edgeEvidence = null" class="mt-2">关闭</n-button>
              </div>
              <n-empty v-else description="请在图谱或边详情中点击「查看证据」" />
            </n-tab-pane>
            <n-tab-pane name="llm" tab="LLM分析">
              <div v-if="reportDetail?.llm_analysis" class="llm-box">
                <n-alert type="info" :bordered="false">
                  <template #header>
                    🤖 DeepSeek {{ reportDetail.llm_model || '' }} 威胁分析报告
                  </template>
                  <div class="llm-text">{{ reportDetail.llm_analysis }}</div>
                </n-alert>
                <n-descriptions v-if="reportDetail" bordered size="small" :column="2" class="mt-2">
                  <n-descriptions-item label="报告ID">{{ reportDetail.report_id || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="置信度">{{ reportDetail.confidence || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="事件总数">{{ reportDetail.total_events || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="检测技术数">{{ reportDetail.techniques_found || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="数据源">{{ reportDetail.data_sources || '-' }}</n-descriptions-item>
                  <n-descriptions-item label="LLM模型">{{ reportDetail.llm_model || '-' }}</n-descriptions-item>
                </n-descriptions>
              </div>
              <n-empty v-else description="该报告不包含 LLM 分析，请使用「多源LLM分析」按钮生成" />
            </n-tab-pane>
            <n-tab-pane name="detail" tab="报告详情">
              <pre class="report-pre">{{ JSON.stringify(reportDetail, null, 2) || '暂无详情' }}</pre>
            </n-tab-pane>
          </n-tabs>
        </n-card>
      </n-grid-item>

      <n-grid-item :span="3">
        <n-card title="节点/边信息" :bordered="false" class="section-card">
          <div v-if="selectedNodeInfo">
            <n-descriptions bordered size="small" :column="1">
              <n-descriptions-item label="ID">{{ selectedNodeInfo.id }}</n-descriptions-item>
              <n-descriptions-item label="标签">{{ selectedNodeInfo.label }}</n-descriptions-item>
              <n-descriptions-item label="类型">{{ selectedNodeInfo.group || selectedNodeInfo.type }}</n-descriptions-item>
              <n-descriptions-item v-if="selectedNodeInfo.stage" label="阶段">{{ selectedNodeInfo.stage }}</n-descriptions-item>
              <n-descriptions-item v-if="selectedNodeInfo.victim_ip" label="受害IP">{{ selectedNodeInfo.victim_ip }}</n-descriptions-item>
              <n-descriptions-item v-if="selectedNodeInfo.attacker_ip" label="攻击者IP">{{ selectedNodeInfo.attacker_ip }}</n-descriptions-item>
            </n-descriptions>
            <n-divider />
            <div class="node-title" v-if="selectedNodeInfo.title">
              <pre class="title-pre">{{ selectedNodeInfo.title }}</pre>
            </div>
          </div>
          <n-empty v-else description="点击节点查看详情" />
        </n-card>
      </n-grid-item>
    </n-grid>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, h } from 'vue'
import { NButton, useMessage } from 'naive-ui'
import { getAttackReports, getAttackReportDetail, getGraphSummary, getSystemStatus, startPipeline, stopPipeline, unifiedAnalysis, listAnalysisReports, getGraphLateral, getEdgeEvidence, getScenarioEdges } from '@/api/attack'

const message = useMessage()
const reports = ref<any[]>([])
const page = ref(1)
const pageSize = ref(10)
const total = ref(0)
const selectedId = ref('')
const graphData = ref<any>(null)
const reportDetail = ref<any>(null)
const activeTab = ref('summary')
const engineRunning = ref(false)
const statusText = ref('')
const timeStart = ref('')
const timeEnd = ref('')
const unifying = ref(false)
const graphMode = ref('')
const lateralPaths = ref<any[]>([])
const edgeEvidence = ref<any>(null)
const selectedEdgeIdx = ref<number | null>(null)
const selectedNodeInfo = ref<any>(null)

// ---- Unified multi-source LLM analysis ----
async function runUnified() {
  unifying.value = true
  try {
    const payload: any = {}
    if (timeStart.value) payload.time_start = timeStart.value
    if (timeEnd.value) payload.time_end = timeEnd.value
    const axios = (await import('axios')).default
    const res = await axios.post('/attack/api/analyze/unified', payload, { timeout: 120000 })
    if (res.data?.ok) {
      const rpt = res.data.report
      message.success(`多源LLM分析完成：${res.data.techniques_count || rpt?.techniques_found || '?'} 个攻击技术已识别`)
      setTimeout(() => {
        fetchReports()
        if (reports.value.length > 0) {
          selectReport(reports.value[0])
          activeTab.value = 'llm'
        }
      }, 500)
    } else {
      message.error(res.data?.error || '分析失败')
    }
  } catch (e: any) {
    const msg = e?.response?.data?.error || e?.message || '请求失败'
    message.error('分析失败: ' + String(msg).substring(0, 200))
  }
  finally { unifying.value = false }
}

// ---- Helper: get node label by ID ----
function getNodeLabel(id: string): string {
  if (!graphData.value?.nodes) return id || '?'
  const node = graphData.value.nodes.find((n: any) => n.id === id || n.id === id)
  return node?.label || node?.id || id || '?'
}

// ---- Edge type tag color ----
function edgeTypeTag(type: string): string {
  if (!type) return 'default'
  const t = type.toLowerCase()
  if (t.includes('causal') || t.includes('lateral')) return 'error'
  if (t.includes('temporal')) return 'info'
  if (t.includes('shared')) return 'warning'
  return 'default'
}

// ---- SVG Attack Chain Layout ----
interface SvgNode { x: number; y: number; w: number; label: string; shortLabel: string; type: string; color?: string; id?: string; group?: string; stage?: number; victim_ip?: string; attacker_ip?: string; title?: string }
interface SvgEdge { x1: number; y1: number; x2: number; y2: number; label?: string; color?: string; colorSuffix?: string; id?: string; from?: string; to?: string; source?: string; target?: string; confidence?: string; evidence_source?: string; time_interval?: number; edge_type?: string }

const NODE_W = 60; const NODE_GAP = 50; const ROW_H = 56; const PAD = 30

const svgLayout = computed(() => {
  const nodes = graphData.value?.nodes || []
  const edges = graphData.value?.edges || []
  if (!nodes.length) return { nodes: [], edges: [], w: 800, h: 140 }

  const techNodes = nodes.filter((n: any) => n.type === 'technique' || n.group === 'technique')
  const attacker = nodes.find((n: any) => n.type === 'threat')
  const victim = nodes.find((n: any) => n.type === 'host' || n.group === 'IP')

  const svgNodes: SvgNode[] = []
  const svgEdges: SvgEdge[] = []

  const maxPerRow = Math.max(4, Math.ceil(techNodes.length / 2))
  const rows: any[][] = []
  for (let i = 0; i < techNodes.length; i += maxPerRow) {
    rows.push(techNodes.slice(i, i + maxPerRow))
  }
  const nRows = rows.length || 1
  const totalW = Math.max(techNodes.length, maxPerRow) * (NODE_W + NODE_GAP) + PAD * 2 + NODE_W * 2 + NODE_GAP * 2

  const attackerX = PAD + NODE_W / 2
  const centerY = PAD + (nRows - 1) * ROW_H / 2
  if (attacker) {
    svgNodes.push({ x: attackerX, y: centerY, w: NODE_W, label: (attacker as any).label || 'Attacker', shortLabel: 'Attacker', type: 'threat', id: (attacker as any).id, group: (attacker as any).group, title: (attacker as any).title })
  }

  let lastTechX = attackerX
  let lastTechY = centerY
  rows.forEach((row, ri) => {
    const y = PAD + ri * ROW_H
    row.forEach((tn: any, ci: number) => {
      const x = attackerX + NODE_W / 2 + NODE_GAP + ci * (NODE_W + NODE_GAP) + NODE_W / 2
      const short = (tn.label || '').split(':')[0] || tn.label?.substring(0, 8) || '?'
      svgNodes.push({ x, y, w: NODE_W, label: (tn as any).label, shortLabel: short, type: 'technique', id: (tn as any).id, group: (tn as any).group, stage: (tn as any).stage, victim_ip: (tn as any).victim_ip, attacker_ip: (tn as any).attacker_ip, title: (tn as any).title })
      lastTechX = x
      lastTechY = y
    })
  })

  const victimX = lastTechX + NODE_W / 2 + NODE_GAP
  if (victim) {
    svgNodes.push({ x: victimX, y: lastTechY, w: NODE_W, label: (victim as any).label || 'Target', shortLabel: 'Victim', type: 'host', id: (victim as any).id, group: (victim as any).group, title: (victim as any).title })
  }

  const nodeMap = new Map<string, SvgNode>()
  const origNodes = nodes
  svgNodes.forEach((sn, i) => {
    if (i < origNodes.length) {
      const origLabel = (origNodes[i] as any)?.label || ''
      nodeMap.set(origLabel, sn)
    }
  })

  // Build edges
  edges.forEach((e: any) => {
    let srcLabel = ''
    let tgtLabel = ''
    const srcId = e.from || e.source || ''
    const tgtId = e.to || e.target || ''
    const srcNode = nodes.find((n: any) => n.id === srcId)
    const tgtNode = nodes.find((n: any) => n.id === tgtId)
    srcLabel = srcNode?.label || srcId
    tgtLabel = tgtNode?.label || tgtId

    const src = svgNodes.find(sn => sn.label === srcLabel || sn.id === srcId)
    const tgt = svgNodes.find(sn => sn.label === tgtLabel || sn.id === tgtId)
    if (src && tgt) {
      const edgeType = (e.edge_type || e.label || '').toLowerCase()
      let color = '#e74c3c'
      let colorSuffix = ''
      if (edgeType.includes('causal') || edgeType.includes('lateral')) { color = '#27ae60'; colorSuffix = '-green' }
      else if (edgeType.includes('temporal')) { color = '#2980b9'; colorSuffix = '-blue' }
      else if (edgeType.includes('shared')) { color = '#f39c12'; colorSuffix = '' }

      svgEdges.push({
        x1: src.x + src.w / 2, y1: src.y,
        x2: tgt.x - tgt.w / 2, y2: tgt.y,
        label: e.label || e.edge_type || '',
        color, colorSuffix,
        from: srcId, to: tgtId,
        source: srcId, target: tgtId,
        confidence: e.confidence,
        evidence_source: e.evidence_source,
        time_interval: e.time_interval,
        edge_type: e.edge_type,
      })
    }
  })

  // If no edges from graph data, chain sequentially
  if (!svgEdges.length && svgNodes.length > 1) {
    for (let i = 1; i < svgNodes.length; i++) {
      const prev = svgNodes[i - 1]
      const curr = svgNodes[i]
      svgEdges.push({ x1: prev.x + prev.w / 2, y1: prev.y, x2: curr.x - curr.w / 2, y2: curr.y, label: 'NEXT' })
    }
  }

  return { nodes: svgNodes, edges: svgEdges, w: totalW, h: PAD * 2 + nRows * ROW_H + 20 }
})

const svgNodes = computed(() => svgLayout.value.nodes)
const svgEdges = computed(() => svgLayout.value.edges)
const svgW = computed(() => svgLayout.value.w)
const svgH = computed(() => svgLayout.value.h)

// ---- Click handlers ----
function onNodeClick(node: any) {
  // Find full node data from original graph data
  const orig = graphData.value?.nodes?.find((n: any) => n.id === node.id || n.label === node.label)
  selectedNodeInfo.value = orig || node
}

function onEdgeClick(edge: any, idx: number) {
  selectedEdgeIdx.value = idx
  showEdgeEvidence(edge, idx)
}

async function showEdgeEvidence(edge: any, idx: string | number) {
  const fromId = edge.from || edge.source || ''
  const toId = edge.to || edge.target || ''
  if (!fromId || !toId) {
    edgeEvidence.value = {
      fromId: fromId || '?',
      toId: toId || '?',
      evidence: { type: edge.edge_type || edge.label || '?', confidence: edge.confidence || 'Medium', evidence_source: edge.evidence_source || '-', time_interval: edge.time_interval, description: edge.description || 'No detail' }
    }
    return
  }
  try {
    const relType = edge.edge_type || undefined
    const res = await getEdgeEvidence(fromId, toId, relType)
    const ev = res.data?.data?.evidence || null
    edgeEvidence.value = {
      fromId,
      toId,
      evidence: ev || { type: edge.edge_type || 'NEXT_STAGE', confidence: edge.confidence || 'Medium', evidence_source: edge.evidence_source || '-', time_interval: edge.time_interval, description: edge.description || 'No evidence details available' }
    }
    activeTab.value = 'evidence'
  } catch {
    edgeEvidence.value = {
      fromId, toId,
      evidence: { type: edge.edge_type || 'NEXT_STAGE', confidence: edge.confidence || 'Medium', evidence_source: edge.evidence_source || 'api_fallback', time_interval: edge.time_interval, description: 'Failed to fetch evidence details' }
    }
    activeTab.value = 'evidence'
  }
}

function onSvgClick() {
  // Deselect if clicking empty space
  selectedNodeInfo.value = null
  selectedEdgeIdx.value = null
}

const columns = [
  { title: '时间', key: 'created_at', width: 150 },
  { title: 'ID', key: 'display_id', width: 140, ellipsis: { tooltip: true },
    render: (r: any) => h('code', {}, r.scenario_id || r.report_id || r.id || '') },
  { title: 'Victim IP', key: 'victim_ip', width: 140 },
  { title: 'Attacker IP', key: 'attacker_ip', width: 140 },
  { title: 'Confidence', key: 'confidence', width: 80 },
  { title: '归因', key: 'attribution_name', ellipsis: { tooltip: true } },
]

async function fetchReports() {
  try {
    const [attackRes, analysisRes] = await Promise.allSettled([
      getAttackReports({ page: page.value, limit: pageSize.value }),
      listAnalysisReports(),
    ])
    const allData: any[] = []
    if (attackRes.status === 'fulfilled' && attackRes.value.data?.ok) {
      allData.push(...(attackRes.value.data.data || []))
    }
    if (analysisRes.status === 'fulfilled' && analysisRes.value.data?.ok) {
      for (const r of (analysisRes.value.data.data || [])) {
        let victim_ip = ''
        try { const iocs = JSON.parse(r.iocs || '[]'); victim_ip = iocs[0] || '' } catch {}
        allData.push({
          id: r.id || '', scenario_id: r.report_id || '', report_id: r.report_id || '',
          victim_ip, attacker_ip: '',
          start_time: r.time_start || '', end_time: r.time_end || '',
          confidence: r.confidence || '', attribution_type: 'LLM Analysis',
          attribution_name: r.data_sources || 'Multi-Source + DeepSeek',
          created_at: r.created_at || '',
          llm_analysis: r.llm_analysis || '',
        })
      }
    }
    allData.sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))
    reports.value = allData
    total.value = allData.length
  } catch { message.error('获取报告失败') }
}

async function selectReport(row: any) {
  const rid = row.scenario_id || row.report_id || ''
  if (!rid) { message.warning('报告ID为空'); return }
  selectedId.value = rid
  graphData.value = null
  reportDetail.value = null
  lateralPaths.value = []
  edgeEvidence.value = null
  selectedNodeInfo.value = null
  graphMode.value = ''
  try {
    const [graphRes, detailRes, lateralRes] = await Promise.allSettled([
      getGraphSummary(rid),
      getAttackReportDetail(rid),
      getGraphLateral(rid),
    ])
    if (detailRes.status === 'fulfilled' && detailRes.value.data?.ok) {
      const rpt = detailRes.value.data.report
      reportDetail.value = typeof rpt === 'string' ? JSON.parse(rpt) : rpt
    } else {
      reportDetail.value = row
    }
    // Graph: prefer Neo4j, fall back to building from attack_chain
    const neoData = (graphRes.status === 'fulfilled') ? graphRes.value.data?.data : null
    if (neoData && (neoData.nodes?.length || neoData.edges?.length)) {
      graphData.value = neoData
      const graphResValue = graphRes.status === 'fulfilled' ? graphRes.value : null
      graphMode.value = graphResValue?.data?.mode || 'neo4j'
    } else {
      const chain = reportDetail.value?.attack_chain || []
      const nodes: any[] = []; const edges: any[] = []
      if (chain.length > 0) {
        nodes.push({ id: 'attacker', label: 'Attacker', type: 'threat' })
        chain.forEach((tech: string, i: number) => {
          let label = tech; let title = ''
          if (tech.includes(': ')) {
            const parts = tech.split(': ', 1)
            label = parts[1] || parts[0]
            title = `TID: ${parts[0]}\nTechnique: ${label}`
          }
          nodes.push({ id: `tech_${i}`, label, type: 'technique', title })
          edges.push({ source: i === 0 ? 'attacker' : `tech_${i-1}`, target: `tech_${i}`, label: 'NEXT', edge_type: 'temporal', confidence: 'Low', evidence_source: 'simulation' })
        })
        nodes.push({ id: 'victim', label: `Target: ${reportDetail.value?.victim_ip || '?'}`, type: 'host' })
        edges.push({ source: `tech_${chain.length-1}`, target: 'victim', label: 'TARGETS', edge_type: 'target', confidence: 'High' })
      }
      graphData.value = { nodes, edges }
      const graphResValue = graphRes.status === 'fulfilled' ? graphRes.value : null
      graphMode.value = graphResValue?.data?.mode || 'simulation'
    }
    // Lateral movement paths
    if (lateralRes.status === 'fulfilled' && lateralRes.value.data?.ok) {
      lateralPaths.value = lateralRes.value.data.data?.lateral_paths || []
    }
  } catch { /* keep existing */ }
}

async function checkStatus() {
  try {
    const res = await getSystemStatus()
    engineRunning.value = res.data?.status === 'running'
    const failures = res.data?.consecutive_failures || 0
    const evtCount = res.data?.events_available || 0
    const rptCount = res.data?.reports_available || 0
    if (failures > 0 && !engineRunning.value) {
      message.warning(`引擎已停止：连续失败 ${failures} 次。请先在「场景管理」页面启动攻击场景`)
    }
    if (!engineRunning.value && evtCount === 0) {
      statusText.value = '无事件数据，请先到「场景管理」启动攻击场景'
    } else if (!engineRunning.value && rptCount > 0) {
      statusText.value = `已有 ${rptCount} 条报告，点击「启动分析引擎」重新分析`
    } else {
      statusText.value = engineRunning.value ? '运行中' : '已停止'
    }
  } catch {}
}

let pollTimer: ReturnType<typeof setInterval> | null = null

function startPolling() {
  if (pollTimer) clearInterval(pollTimer)
  pollTimer = setInterval(async () => {
    await fetchReports()
    await checkStatus()
    if (!engineRunning.value) {
      stopPolling()
      await fetchReports()
      if (reports.value.length > 0 && !selectedId.value) {
        selectReport(reports.value[0])
      }
    }
  }, 3000)
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
}

async function startEngine() {
  try {
    const payload: any = {}
    if (timeStart.value) payload.time_start = timeStart.value
    if (timeEnd.value) payload.time_end = timeEnd.value
    const axios = (await import('axios')).default
    const res = await axios.post('/attack/api/system/start', payload)
    message[res.data?.ok ? 'success' : 'error'](res.data?.message || '已启动')
    startPolling()
  } catch { message.error('启动失败') }
}

async function stopEngine() {
  stopPolling()
  try {
    const res = await stopPipeline()
    message.success(res.data?.message || '正在停止')
    await fetchReports()
    checkStatus()
  } catch { message.error('停止失败') }
}

onMounted(() => { fetchReports(); checkStatus() })
onUnmounted(() => { stopPolling() })
</script>

<style scoped>
.ac-wrap { max-width: 1400px; margin: 0 auto; }
.ac-header { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; }
.ac-header h2 { margin: 0 0 6px 0; }
.text-muted { color: #6b7280; font-size: 13px; }
.section-card { border-radius: 14px; }
.mt-2 { margin-top: 12px; }
.mb-2 { margin-bottom: 10px; }
.graph-box { min-height: 300px; overflow-x: auto; }
.graph-visual { padding: 8px; }
.graph-summary { font-size: 12px; color: #6b7280; margin-bottom: 8px; }
.chain-svg { display: block; min-width: 600px; background: #fafbfd; border: 1px solid #e5e7eb; border-radius: 8px; cursor: default; }
.node-rect { cursor: pointer; }
.node-rect:hover { filter: brightness(1.2); }
.edge-line { cursor: pointer; }
.edge-line:hover { stroke-width: 4; }
.edge-label { pointer-events: none; user-select: none; }
.edge-selected { background: #fff3cd !important; }
.report-pre { background: #f8fafc; padding: 16px; border-radius: 8px; max-height: 450px; overflow: auto; font-size: 12px; line-height: 1.6; }
.llm-box { max-height: 500px; overflow-y: auto; }
.llm-text { white-space: pre-wrap; font-size: 14px; line-height: 1.8; margin: 12px 0 0 0; color: #1e3a5f; }
.edge-detail-panel { max-height: 450px; overflow-y: auto; }
.title-pre { white-space: pre-wrap; font-size: 11px; color: #555; }
.node-title { max-height: 200px; overflow-y: auto; }
</style>