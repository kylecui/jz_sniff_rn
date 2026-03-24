import { get, post, put } from './request'

export interface ConfigData {
  config: Record<string, unknown>
}

export interface StagedConfig {
  staged: Record<string, unknown> | null
  has_staged: boolean
}

export interface ConfigHistoryEntry {
  version: number
  applied_at: string
  diff?: string
}

export interface ConfigHistory {
  history: ConfigHistoryEntry[]
}

export interface NetworkInterface {
  name: string
  role: 'monitor' | 'manage' | 'mirror'
  subnet: string
}

export interface InterfacesData {
  interfaces: NetworkInterface[]
  mode: string
}

export const getConfig = () => get<ConfigData>('/config')
export const applyConfig = (data: Record<string, unknown>) =>
  post<void>('/config', data)
export const getStaged = () => get<StagedConfig>('/config/staged')
export const stageConfig = (data: Record<string, unknown>) =>
  post<void>('/config/stage', data)
export const commitConfig = () => post<void>('/config/commit')
export const discardConfig = () => post<void>('/config/discard')
export const getConfigHistory = () => get<ConfigHistory>('/config/history')
export const rollbackConfig = (version?: number) =>
  post<void>('/config/rollback', version !== undefined ? { version } : undefined)

export const getInterfaces = () => get<InterfacesData>('/config/interfaces')
export const updateInterfaces = (data: InterfacesData) =>
  put<InterfacesData>('/config/interfaces', data)

export interface ArpSpoofTarget {
  target_ip: string
  gateway_ip: string
}

export interface ArpSpoofConfig {
  enabled: boolean
  interval_sec: number
  targets: ArpSpoofTarget[]
}

export const getArpSpoof = () => get<ArpSpoofConfig>('/config/arp_spoof')
export const updateArpSpoof = (data: ArpSpoofConfig) =>
  put<ArpSpoofConfig>('/config/arp_spoof', data)

export interface VlanConfig {
  id: number
  name: string
  subnet: string
}

export interface VlansData {
  vlans: VlanConfig[]
}

export const getVlans = () => get<VlansData>('/config/vlans')
export const updateVlans = (data: VlansData) =>
  put<VlansData>('/config/vlans', data)
