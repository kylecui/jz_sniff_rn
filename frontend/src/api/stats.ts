import { get } from './request'

export interface Stats {
  guards_total?: number
  guards_static?: number
  guards_dynamic?: number
  whitelist_total?: number
  attacks_total?: number
  attacks_today?: number
  [key: string]: unknown
}

export interface GuardStats {
  [key: string]: unknown
}

export interface TrafficStats {
  [key: string]: unknown
}

export interface ThreatStats {
  [key: string]: unknown
}

export interface BgStats {
  [key: string]: unknown
}

export const getStats = () => get<Stats>('/stats')
export const getGuardStats = () => get<GuardStats>('/stats/guards')
export const getTrafficStats = () => get<TrafficStats>('/stats/traffic')
export const getThreatStats = () => get<ThreatStats>('/stats/threats')
export const getBgStats = () => get<BgStats>('/stats/background')
