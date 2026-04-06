import { get, post, put, del } from './request'

export interface ThreatPattern {
  id: string
  priority: number
  src_ip: string
  src_mac: string
  dst_port: number
  proto: string
  threat_level: string
  action: string
  redirect_target: number
  continue_matching: boolean
  capture_packet: boolean
  description: string
}

export interface RedirectTarget {
  id: number
  name: string
  interface: string
}

export type ThreatPatternCreate = Omit<ThreatPattern, 'id'> & { id?: string }

export const getThreatPatterns = () =>
  get<{ patterns: ThreatPattern[]; count: number }>('/threats/patterns')
export const addThreatPattern = (data: ThreatPatternCreate) =>
  post<{ status: string; id: string }>('/threats/patterns', data)
export const updateThreatPattern = (id: string, data: Partial<ThreatPattern>) =>
  put<{ status: string; id: string }>(`/threats/patterns/${id}`, data)
export const deleteThreatPattern = (id: string) =>
  del<{ status: string; id: string }>(`/threats/patterns/${id}`)

export const reorderPatterns = (order: string[]) =>
  put<{ status: string }>('/threats/patterns/reorder', { order })

export const getRedirectTargets = () =>
  get<{ targets: RedirectTarget[]; count: number }>('/threats/redirect_targets')
export const addRedirectTarget = (data: RedirectTarget) =>
  post<{ status: string; id: number }>('/threats/redirect_targets', data)
export const updateRedirectTarget = (id: number, data: Partial<RedirectTarget>) =>
  put<{ status: string; id: number }>(`/threats/redirect_targets/${id}`, data)
export const deleteRedirectTarget = (id: number) =>
  del<{ status: string; id: number }>(`/threats/redirect_targets/${id}`)
