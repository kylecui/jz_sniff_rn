import { get } from './request'

export interface LogEntry {
  id?: number
  timestamp: string
  src_ip?: string
  dst_ip?: string
  src_mac?: string
  dst_mac?: string
  type?: string
  detail?: string
  event_type?: number
  guard_type?: string
  protocol?: string
  threat_level?: number
  src_port?: number
  dst_port?: number
  details?: string
  action?: string
  actor?: string
  target?: string
  result?: string
  data?: Record<string, unknown>
  [key: string]: unknown
}

export interface LogsResponse {
  rows: LogEntry[]
  limit: number
  offset: number
}

export type LogType = 'attacks' | 'sniffers' | 'background' | 'threats' | 'audit' | 'heartbeat'

export interface LogQueryParams {
  limit?: number
  offset?: number
  since?: string
  until?: string
  src_ip?: string
  dst_ip?: string
  protocol?: string
  src_port?: number
  dst_port?: number
  ip?: string
  mac?: string
  action?: string
}

function buildQuery(params: LogQueryParams): string {
  const qs = new URLSearchParams()
  if (params.limit) qs.set('limit', String(params.limit))
  if (params.offset !== undefined) qs.set('offset', String(params.offset))
  if (params.since) qs.set('since', params.since)
  if (params.until) qs.set('until', params.until)
  if (params.src_ip) qs.set('src_ip', params.src_ip)
  if (params.dst_ip) qs.set('dst_ip', params.dst_ip)
  if (params.protocol) qs.set('protocol', params.protocol)
  if (params.src_port) qs.set('src_port', String(params.src_port))
  if (params.dst_port) qs.set('dst_port', String(params.dst_port))
  if (params.ip) qs.set('ip', params.ip)
  if (params.mac) qs.set('mac', params.mac)
  if (params.action) qs.set('action', params.action)
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export const getLogs = (
  type: LogType,
  params: LogQueryParams = {},
) => get<LogsResponse>(`/logs/${type}${buildQuery(params)}`)

export function exportLogsToCSV(rows: LogEntry[], type: LogType): void {
  if (!rows.length) return

  const keys = Object.keys(rows[0])
  const escape = (val: unknown): string => {
    if (val === null || val === undefined) return ''
    const s = typeof val === 'object' ? JSON.stringify(val) : String(val)
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s
  }

  const header = keys.join(',')
  const body = rows.map((row) => keys.map((k) => escape(row[k])).join(',')).join('\n')
  const csv = header + '\n' + body

  const blob = new Blob(['\uFEFF' + csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `${type}_${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
