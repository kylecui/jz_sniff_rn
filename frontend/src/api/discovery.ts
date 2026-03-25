import { get, put } from './request'

export interface Device {
  ip: string
  mac: string
  vlan?: number
  hostname?: string
  vendor?: string
  os_class?: string
  device_class?: string
  confidence?: number
  signals?: number
  first_seen?: number
  last_seen?: number
  fingerprint?: Record<string, unknown>
}

export interface DevicesResponse {
  devices: Device[]
  total: number
}

export interface DiscoveryConfig {
  aggressive_mode: boolean
  dhcp_probe_interval_sec: number
}

export const getDevices = () => get<DevicesResponse>('/discovery/devices')
export const getDevice = (mac: string) =>
  get<Device>(`/discovery/devices/${mac}`)

export const getDiscoveryConfig = () => get<DiscoveryConfig>('/discovery/config')
export const setDiscoveryConfig = (data: Partial<DiscoveryConfig>) =>
  put<DiscoveryConfig>('/discovery/config', data)

export interface DiscoveredVlan {
  id: number
  device_count: number
  last_seen: number
}

export interface DiscoveredVlansResponse {
  vlans: DiscoveredVlan[]
  total: number
}

export const getDiscoveredVlans = () => get<DiscoveredVlansResponse>('/discovery/vlans')
