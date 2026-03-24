import { get, post, del } from './request'

export interface Guard {
  ip: string
  mac?: string
  source?: string
  created_at?: string
}

export interface FrozenGuard {
  ip: string
  reason?: string
  created_at?: string
}

export interface AutoGuardStatus {
  max_ratio: number
  subnet_total: number
  max_allowed: number
  current_dynamic: number
  frozen_count: number
}

export const getGuards = () => get<{ guards: Guard[] }>('/guards')
export const getStaticGuards = () => get<{ guards: Guard[] }>('/guards/static')
export const addStaticGuard = (data: { ip: string; mac?: string }) =>
  post<Guard>('/guards/static', data)
export const deleteStaticGuard = (ip: string) =>
  del<void>(`/guards/static/${ip}`)

export const getDynamicGuards = () =>
  get<{ guards: Guard[] }>('/guards/dynamic')
export const deleteDynamicGuard = (ip: string) =>
  del<void>(`/guards/dynamic/${ip}`)

export const getFrozenGuards = () =>
  get<{ guards: FrozenGuard[] }>('/guards/frozen')
export const addFrozenGuard = (data: { ip: string }) =>
  post<FrozenGuard>('/guards/frozen', data)
export const deleteFrozenGuard = (ip: string) =>
  del<void>(`/guards/frozen/${ip}`)

export const getAutoGuardStatus = () =>
  get<AutoGuardStatus>('/guards/auto/config')
