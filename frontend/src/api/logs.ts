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
  [key: string]: unknown
}

export interface LogsResponse {
  logs: LogEntry[]
  total: number
  page: number
  per_page: number
}

export type LogType = 'attacks' | 'sniffers' | 'background' | 'threats' | 'audit'

function buildQuery(params: {
  page?: number
  per_page?: number
  start_time?: string
  end_time?: string
}): string {
  const qs = new URLSearchParams()
  if (params.page) qs.set('page', String(params.page))
  if (params.per_page) qs.set('per_page', String(params.per_page))
  if (params.start_time) qs.set('start_time', params.start_time)
  if (params.end_time) qs.set('end_time', params.end_time)
  const s = qs.toString()
  return s ? `?${s}` : ''
}

export const getLogs = (
  type: LogType,
  params: {
    page?: number
    per_page?: number
    start_time?: string
    end_time?: string
  } = {},
) => get<LogsResponse>(`/logs/${type}${buildQuery(params)}`)
