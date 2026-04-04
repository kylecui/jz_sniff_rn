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

function buildQuery(params: {
  limit?: number
  offset?: number
  since?: string
  until?: string
}): string {
  const qs = new URLSearchParams()
  if (params.limit) qs.set('limit', String(params.limit))
  if (params.offset !== undefined) qs.set('offset', String(params.offset))
  if (params.since) qs.set('since', params.since)
  if (params.until) qs.set('until', params.until)
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export const getLogs = (
  type: LogType,
  params: {
    limit?: number
    offset?: number
    since?: string
    until?: string
  } = {},
) => get<LogsResponse>(`/logs/${type}${buildQuery(params)}`)
