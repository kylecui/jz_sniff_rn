import { get, post, del } from './request'

export interface DhcpException {
  ip: string
  mac: string
  created_at_ns?: number
}

export interface DhcpAlert {
  ip: string
  mac: string
  vendor: string
  first_seen: number
  protected: boolean
  ifindex: number
  interface: string
}

export const getDhcpExceptions = () =>
  get<{ exceptions: DhcpException[]; count: number }>('/dhcp_exceptions')
export const addDhcpException = (data: { ip: string }) =>
  post<{ ip: string; mac: string; status: string }>('/dhcp_exceptions', data)
export const deleteDhcpException = (mac: string) =>
  del<void>(`/dhcp_exceptions/${mac}`)
export const getDhcpAlerts = () =>
  get<{ servers: DhcpAlert[]; total: number }>('/alerts/dhcp')
