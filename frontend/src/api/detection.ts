import client from './client'

export function getDetectionStats() {
  return client.get('/detection/api/stats')
}

export function getAlerts(limit = 50, severity?: string, scenario?: string) {
  return client.get('/detection/api/alerts', { params: { limit, severity, scenario } })
}

export function getAlertsLive() {
  return client.get('/detection/api/alerts/live')
}

export function getEventsLive() {
  return client.get('/detection/api/events/live')
}

export function runFullAnalysis() {
  return client.post('/detection/api/analyze')
}

export function getReport() {
  return client.get('/detection/api/report')
}

export function ragSearch(q: string) {
  return client.get('/detection/api/rag/search', { params: { q } })
}

export function getKnowledgeBase() {
  return client.get('/detection/api/knowledge')
}

export function listEvidenceCases(limit = 50) {
  return client.get('/detection/api/evidence/cases', { params: { limit } })
}

export function getEvidenceCase(caseId: string) {
  return client.get(`/detection/api/evidence/case/${caseId}`)
}

export function verifyEvidenceCase(caseId: string) {
  return client.get(`/detection/api/evidence/case/${caseId}/verify`)
}

export function exportEvidenceCase(caseId: string, format: 'json' | 'markdown' = 'json') {
  return client.get(`/detection/api/evidence/case/${caseId}/export`, {
    params: { format },
    responseType: 'blob',
  })
}
