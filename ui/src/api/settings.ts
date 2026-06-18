import { apiRequest } from '@/api/client'

export interface ACLRule {
  id: number
  subnet: string
  description?: string
}

export interface ACLRulesResponse {
  rules: ACLRule[]
}

export interface ACLMutationResponse {
  status: string
  message: string
  rule?: ACLRule
}

export function fetchACLRules(): Promise<ACLRulesResponse> {
  return apiRequest<ACLRulesResponse>('/api/v1/settings/acl')
}

export function createACLRule(
  subnet: string,
  description?: string,
): Promise<ACLMutationResponse> {
  return apiRequest<ACLMutationResponse>('/api/v1/settings/acl', {
    method: 'POST',
    body: { subnet, description: description?.trim() || undefined },
  })
}

export function deleteACLRule(id: number): Promise<ACLMutationResponse> {
  return apiRequest<ACLMutationResponse>(`/api/v1/settings/acl/${id}`, {
    method: 'DELETE',
  })
}
