import { get, post, put, del } from './request'

export interface Policy {
  id: number
  src_ip?: string
  dst_ip?: string
  src_port?: number
  dst_port?: number
  protocol?: string
  action: 'pass' | 'drop' | 'redirect' | 'mirror'
  priority?: number
  auto?: boolean
  created_at?: string
}

export type PolicyCreate = Omit<Policy, 'id' | 'auto' | 'created_at'>

export const getPolicies = () => get<{ policies: Policy[] }>('/policies')
export const addPolicy = (data: PolicyCreate) =>
  post<Policy>('/policies', data)
export const updatePolicy = (id: number, data: PolicyCreate) =>
  put<Policy>(`/policies/${id}`, data)
export const deletePolicy = (id: number) => del<void>(`/policies/${id}`)
