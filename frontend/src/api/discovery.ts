import { get } from './request'

export interface Device {
  ip: string
  mac: string
  vlan?: number
  hostname?: string
  vendor?: string
  os_guess?: string
  first_seen?: string
  last_seen?: string
  fingerprint?: Record<string, unknown>
}

export interface DevicesResponse {
  devices: Device[]
  total: number
}

export const getDevices = () => get<DevicesResponse>('/discovery/devices')
export const getDevice = (mac: string) =>
  get<Device>(`/discovery/devices/${mac}`)
