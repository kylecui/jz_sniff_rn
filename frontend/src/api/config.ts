import { get, post } from './request'

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
