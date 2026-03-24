import { get, post } from './request'

export interface BpfModule {
  name: string
  stage: number
  loaded: boolean
  prog_fd?: number
}

export interface NetworkInterface {
  name: string
  ifindex: number
  role?: string
}

export interface ModulesResponse {
  modules: BpfModule[]
  interfaces?: NetworkInterface[]
}

export interface DaemonStatus {
  name: string
  pid: number
  running: boolean
}

export interface DaemonsResponse {
  daemons: DaemonStatus[]
}

export interface HealthResponse {
  status: string
}

export interface StatusResponse {
  status: string
  uptime?: number
  version?: string
  [key: string]: unknown
}

export const getHealth = () => get<HealthResponse>('/health')
export const getStatus = () => get<StatusResponse>('/status')
export const getModules = () => get<ModulesResponse>('/modules')
export const getDaemons = () => get<DaemonsResponse>('/system/daemons')
export const reloadModule = (name: string) =>
  post<void>(`/modules/${name}/reload`)
export const restartDaemon = (name: string) =>
  post<{ status: string; daemon: string }>(`/system/restart/${name}`)
