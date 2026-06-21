import { apiRequest } from '@/api/client'

export type ACLAction = 'allow' | 'block'

export interface ACLRule {
  id: number
  subnet: string
  description?: string
  action: ACLAction
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
  action: ACLAction = 'allow',
): Promise<ACLMutationResponse> {
  return apiRequest<ACLMutationResponse>('/api/v1/settings/acl', {
    method: 'POST',
    body: {
      subnet,
      description: description?.trim() || undefined,
      action,
    },
  })
}

export function updateACLRule(
  id: number,
  subnet: string,
  description?: string,
  action: ACLAction = 'allow',
): Promise<ACLMutationResponse> {
  return apiRequest<ACLMutationResponse>(`/api/v1/settings/acl/${id}`, {
    method: 'PUT',
    body: {
      subnet,
      description: description?.trim() || undefined,
      action,
    },
  })
}

export function deleteACLRule(id: number): Promise<ACLMutationResponse> {
  return apiRequest<ACLMutationResponse>(`/api/v1/settings/acl/${id}`, {
    method: 'DELETE',
  })
}
