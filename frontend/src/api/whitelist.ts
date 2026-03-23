import { get, post, del } from './request'

export interface WhitelistEntry {
  ip: string
  mac?: string
  created_at?: string
}

export const getWhitelist = () =>
  get<{ whitelist: WhitelistEntry[] }>('/whitelist')
export const addWhitelistEntry = (data: { ip: string }) =>
  post<WhitelistEntry>('/whitelist', data)
export const deleteWhitelistEntry = (ip: string) =>
  del<void>(`/whitelist/${ip}`)
