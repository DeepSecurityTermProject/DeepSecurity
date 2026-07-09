import client from './client'

export function getAttackReports(params?: { page?: number; limit?: number; ip?: string; confidence?: string }) {
  return client.get('/attack/api/reports', { params })
}

export function getAttackReportDetail(scenarioId: string) {
  return client.get(`/attack/api/report/${scenarioId}`)
}

export function getGraphSummary(scenarioId: string) {
  return client.get(`/attack/api/graph/${scenarioId}/summary`)
}

export function getGraphTopology(scenarioId: string) {
  return client.get(`/attack/api/graph/${scenarioId}/topology`)
}

export function getGraphLateral(scenarioId: string) {
  return client.get(`/attack/api/graph/${scenarioId}/lateral`)
}

export function getEdgeEvidence(fromId: string, toId: string, relType?: string) {
  const params: any = { from_id: fromId, to_id: toId }
  if (relType) params.rel_type = relType
  return client.get('/attack/api/graph/edge/evidence', { params })
}

export function getScenarioEdges(scenarioId: string) {
  return client.get(`/attack/api/graph/${scenarioId}/edges`)
}

export function getSystemStatus() {
  return client.get('/attack/api/system/status')
}

export function startPipeline(payload?: { time_start?: string; time_end?: string }) {
  return client.post('/attack/api/system/start', payload || {})
}

export function stopPipeline() {
  return client.post('/attack/api/system/stop')
}

export function unifiedAnalysis(payload?: { time_start?: string; time_end?: string }) {
  return client.post('/attack/api/analyze/unified', payload || {})
}

export function listAnalysisReports() {
  return client.get('/attack/api/analyze/reports')
}