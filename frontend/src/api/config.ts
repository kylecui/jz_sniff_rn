import { get, post, put, del } from './request'

export type ConfigData = Record<string, unknown>

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

export interface DynamicGuardConfig {
  auto_discover: number   // 0=off, 1=on, -1=use global default
  max_entries: number     // -1=use global default
  ttl_hours: number       // -1=use global default
  max_ratio: number       // -1=use global default
  warmup_mode: number     // 0=normal, 1=fast, 2=burst, -1=use global default
}

export interface NetworkInterface {
  name: string
  role: 'monitor' | 'manage' | 'mirror'
  subnet: string
  address: string
  gateway: string
  dns1: string
  dns2: string
  vlans: VlanConfig[]
  dynamic?: DynamicGuardConfig
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

export interface CaptureFile {
  filename: string
  size_bytes: number
  created: number
}

export interface CaptureStatus {
  active: boolean
  filename?: string
  bytes_written?: number
  pkt_count?: number
  max_bytes?: number
  captures: CaptureFile[]
}

export const getCaptures = () => get<CaptureStatus>('/captures')
export const startCapture = (maxBytes?: number) =>
  post<{ status: string; filename: string }>('/captures/start', maxBytes ? { max_bytes: maxBytes } : undefined)
export const stopCapture = () => post<{ status: string }>('/captures/stop')
export const deleteCapture = (filename: string) =>
  del<{ status: string; filename: string }>(`/captures/${filename}`)
export const downloadCaptureUrl = (filename: string) =>
  `/api/v1/captures/${encodeURIComponent(filename)}/download`
