export const RECORD_TYPES = [
  'A',
  'AAAA',
  'CAA',
  'CERT',
  'CNAME',
  'DNSKEY',
  'DS',
  'HTTPS',
  'LOC',
  'MX',
  'NAPTR',
  'NS',
  'OPENPGPKEY',
  'PTR',
  'SMIMEA',
  'SRV',
  'SSHFP',
  'SVCB',
  'TLSA',
  'TXT',
  'URI',
] as const

export type EditableRecordType = (typeof RECORD_TYPES)[number]
export type RecordType = EditableRecordType | 'SOA'

export type SelectOption<T extends string | number = string> = {
  value: T
  label: string
}

export const CAA_TAGS: SelectOption[] = [
  { value: 'issue', label: 'issue' },
  { value: 'issuewild', label: 'issuewild' },
  { value: 'iodef', label: 'iodef' },
]

export const DNSSEC_ALGORITHMS: SelectOption<number>[] = [
  { value: 1, label: '1 — RSA/MD5' },
  { value: 2, label: '2 — DH' },
  { value: 3, label: '3 — DSA/SHA1' },
  { value: 4, label: '4 — ECC' },
  { value: 5, label: '5 — RSA/SHA1' },
  { value: 6, label: '6 — DSA-NSEC3-SHA1' },
  { value: 7, label: '7 — RSASHA1-NSEC3-SHA1' },
  { value: 8, label: '8 — RSA/SHA256' },
  { value: 10, label: '10 — RSA/SHA512' },
  { value: 12, label: '12 — GOST R 34.10-2001' },
  { value: 13, label: '13 — ECDSAP256SHA256' },
  { value: 14, label: '14 — ECDSAP384SHA384' },
  { value: 15, label: '15 — Ed25519' },
  { value: 16, label: '16 — Ed448' },
]

export const DS_DIGEST_TYPES: SelectOption<number>[] = [
  { value: 1, label: '1 — SHA-1' },
  { value: 2, label: '2 — SHA-256' },
  { value: 4, label: '4 — SHA-384' },
]

export const SSHFP_ALGORITHMS: SelectOption<number>[] = [
  { value: 1, label: '1 — RSA' },
  { value: 2, label: '2 — DSA' },
  { value: 3, label: '3 — ECDSA' },
  { value: 4, label: '4 — Ed25519' },
]

export const SSHFP_TYPES: SelectOption<number>[] = [
  { value: 1, label: '1 — SHA-1' },
  { value: 2, label: '2 — SHA-256' },
]

export const DANE_USAGES: SelectOption<number>[] = [
  { value: 0, label: '0 — PKIX-TA' },
  { value: 1, label: '1 — PKIX-EE' },
  { value: 2, label: '2 — DANE-TA' },
  { value: 3, label: '3 — DANE-EE' },
]

export const DANE_SELECTORS: SelectOption<number>[] = [
  { value: 0, label: '0 — Cert' },
  { value: 1, label: '1 — SPKI' },
]

export const DANE_MATCHING_TYPES: SelectOption<number>[] = [
  { value: 0, label: '0 — Full' },
  { value: 1, label: '1 — SHA-256' },
  { value: 2, label: '2 — SHA-512' },
]

export const DNSKEY_FLAGS: SelectOption<number>[] = [
  { value: 256, label: '256 — Zone Key' },
  { value: 257, label: '257 — SEP' },
]

export const DNSKEY_PROTOCOLS: SelectOption<number>[] = [
  { value: 3, label: '3 — DNSSEC' },
]

export const CERT_TYPES: SelectOption<number>[] = [
  { value: 1, label: '1 — PKIX' },
  { value: 2, label: '2 — SPKI' },
  { value: 3, label: '3 — PGP' },
  { value: 4, label: '4 — IPKIX' },
  { value: 5, label: '5 — ISPKI' },
  { value: 6, label: '6 — IPGP' },
  { value: 7, label: '7 — Fingerprint' },
  { value: 8, label: '8 — SSH' },
]

export const LOC_HEMISPHERES: SelectOption<'N' | 'S' | 'E' | 'W'>[] = [
  { value: 'N', label: 'N — North' },
  { value: 'S', label: 'S — South' },
  { value: 'E', label: 'E — East' },
  { value: 'W', label: 'W — West' },
]

const BIND_TTL_UNITS = 'wdhms'

export type RecordFormState = {
  name: string
  type: RecordType
  ttl: string
  content: string
  mxPriority: number
  mxTarget: string
  srvPriority: number
  srvWeight: number
  srvPort: number
  srvTarget: string
  caaFlags: number
  caaTag: string
  caaValue: string
  dsKeyTag: number
  dsAlgorithm: number
  dsDigestType: number
  dsDigest: string
  sshfpAlgorithm: number
  sshfpType: number
  sshfpFingerprint: string
  daneUsage: number
  daneSelector: number
  daneMatchingType: number
  daneCertificate: string
  dnskeyFlags: number
  dnskeyProtocol: number
  dnskeyAlgorithm: number
  dnskeyPublicKey: string
  svcPriority: number
  svcTarget: string
  svcParams: string
  certType: number
  certKeyTag: number
  certAlgorithm: number
  certData: string
  naptrOrder: number
  naptrPreference: number
  naptrFlags: string
  naptrService: string
  naptrRegexp: string
  naptrReplacement: string
  locLatDeg: number
  locLatMin: number
  locLatSec: string
  locLatHem: 'N' | 'S'
  locLonDeg: number
  locLonMin: number
  locLonSec: string
  locLonHem: 'E' | 'W'
  locAltitude: string
  locSize: string
  locHorizPre: string
  locVertPre: string
  uriPriority: number
  uriWeight: number
  uriTarget: string
  soaPrimaryNS: string
  soaAdminEmail: string
  soaSerial: number
  soaRefresh: string
  soaRetry: string
  soaExpire: string
  soaMinimumTTL: string
}

export type RecordFormErrors = Partial<
  Record<
    | keyof RecordFormState
    | 'value'
    | 'mxPriority'
    | 'mxTarget'
    | 'srvPriority'
    | 'srvWeight'
    | 'srvPort'
    | 'srvTarget'
    | 'caaValue'
    | 'dsDigest'
    | 'sshfpFingerprint'
    | 'daneCertificate'
    | 'dnskeyPublicKey'
    | 'svcTarget'
    | 'certData'
    | 'naptrFlags'
    | 'naptrService'
    | 'naptrRegexp'
    | 'naptrReplacement'
    | 'uriTarget'
    | 'soaPrimaryNS'
    | 'soaAdminEmail'
    | 'soaRefresh'
    | 'soaRetry'
    | 'soaExpire'
    | 'soaMinimumTTL',
    string
  >
>

const SIMPLE_CONTENT_TYPES = new Set<RecordType>([
  'A',
  'AAAA',
  'CNAME',
  'TXT',
  'PTR',
  'NS',
  'OPENPGPKEY',
])

const MULTILINE_CONTENT_TYPES = new Set<RecordType>(['TXT', 'OPENPGPKEY'])

export function isValidBindTTL(raw: string): boolean {
  const value = raw.trim()
  if (!value) {
    return false
  }
  if (/^\d+$/.test(value)) {
    return Number(value) >= 1
  }
  if (!/^\d+[wdhms](\d+[wdhms])*$/.test(value)) {
    return false
  }
  return [...value].some((ch) => BIND_TTL_UNITS.includes(ch))
}

export function stripTrailingDot(host: string): string {
  return host.replace(/\.$/, '')
}

export function createDefaultFormState(): RecordFormState {
  return {
    name: '',
    type: 'A',
    ttl: '3600',
    content: '',
    mxPriority: 10,
    mxTarget: '',
    srvPriority: 0,
    srvWeight: 0,
    srvPort: 5060,
    srvTarget: '',
    caaFlags: 0,
    caaTag: 'issue',
    caaValue: '',
    dsKeyTag: 0,
    dsAlgorithm: 13,
    dsDigestType: 2,
    dsDigest: '',
    sshfpAlgorithm: 1,
    sshfpType: 1,
    sshfpFingerprint: '',
    daneUsage: 3,
    daneSelector: 1,
    daneMatchingType: 1,
    daneCertificate: '',
    dnskeyFlags: 256,
    dnskeyProtocol: 3,
    dnskeyAlgorithm: 13,
    dnskeyPublicKey: '',
    svcPriority: 1,
    svcTarget: '.',
    svcParams: '',
    certType: 1,
    certKeyTag: 0,
    certAlgorithm: 13,
    certData: '',
    naptrOrder: 100,
    naptrPreference: 10,
    naptrFlags: 'u',
    naptrService: 'sip+E2U',
    naptrRegexp: '',
    naptrReplacement: '.',
    locLatDeg: 0,
    locLatMin: 0,
    locLatSec: '0.000',
    locLatHem: 'N',
    locLonDeg: 0,
    locLonMin: 0,
    locLonSec: '0.000',
    locLonHem: 'E',
    locAltitude: '0.00m',
    locSize: '1m',
    locHorizPre: '10000m',
    locVertPre: '10m',
    uriPriority: 10,
    uriWeight: 0,
    uriTarget: '',
    soaPrimaryNS: '',
    soaAdminEmail: '',
    soaSerial: 0,
    soaRefresh: '3600',
    soaRetry: '600',
    soaExpire: '86400',
    soaMinimumTTL: '300',
  }
}

export function isSimpleContentType(type: RecordType): boolean {
  return SIMPLE_CONTENT_TYPES.has(type)
}

export function isMultilineContentType(type: RecordType): boolean {
  return MULTILINE_CONTENT_TYPES.has(type)
}

export function isDaneType(type: RecordType): boolean {
  return type === 'TLSA' || type === 'SMIMEA'
}

function splitRecordValue(value: string): string[] {
  return value.trim().split(/\s+/).filter(Boolean)
}

function quoteNaptrToken(token: string): string {
  const trimmed = token.trim()
  if (!trimmed) {
    return '""'
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
  }
  if (/^[A-Za-z0-9+._-]+$/.test(trimmed)) {
    return trimmed
  }
  return `"${trimmed.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

function formatCaaValue(value: string): string {
  const trimmed = value.trim()
  if (!trimmed) {
    return '""'
  }
  if (/[\s"]/.test(trimmed)) {
    return `"${trimmed.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  }
  return trimmed
}

function ensureLocSuffix(value: string, fallback: string): string {
  const trimmed = value.trim()
  if (!trimmed) {
    return fallback
  }
  return trimmed.endsWith('m') ? trimmed : `${trimmed}m`
}

export function buildRecordValue(form: RecordFormState): string {
  switch (form.type) {
    case 'MX':
      return `${form.mxPriority} ${form.mxTarget.trim()}`
    case 'SRV':
      return `${form.srvPriority} ${form.srvWeight} ${form.srvPort} ${form.srvTarget.trim()}`
    case 'CAA':
      return `${form.caaFlags} ${form.caaTag} ${formatCaaValue(form.caaValue)}`
    case 'DS':
      return `${form.dsKeyTag} ${form.dsAlgorithm} ${form.dsDigestType} ${form.dsDigest.trim()}`
    case 'SSHFP':
      return `${form.sshfpAlgorithm} ${form.sshfpType} ${form.sshfpFingerprint.trim()}`
    case 'TLSA':
    case 'SMIMEA':
      return `${form.daneUsage} ${form.daneSelector} ${form.daneMatchingType} ${form.daneCertificate.trim()}`
    case 'DNSKEY':
      return `${form.dnskeyFlags} ${form.dnskeyProtocol} ${form.dnskeyAlgorithm} ${form.dnskeyPublicKey.trim()}`
    case 'HTTPS':
    case 'SVCB': {
      const base = `${form.svcPriority} ${form.svcTarget.trim()}`
      const params = form.svcParams.trim()
      return params ? `${base} ${params}` : base
    }
    case 'CERT':
      return `${form.certType} ${form.certKeyTag} ${form.certAlgorithm} ${form.certData.trim()}`
    case 'NAPTR':
      return [
        form.naptrOrder,
        form.naptrPreference,
        quoteNaptrToken(form.naptrFlags),
        quoteNaptrToken(form.naptrService),
        quoteNaptrToken(form.naptrRegexp),
        quoteNaptrToken(form.naptrReplacement),
      ].join(' ')
    case 'LOC':
      return [
        form.locLatDeg,
        form.locLatMin,
        form.locLatSec,
        form.locLatHem,
        form.locLonDeg,
        form.locLonMin,
        form.locLonSec,
        form.locLonHem,
        ensureLocSuffix(form.locAltitude, '0.00m'),
        ensureLocSuffix(form.locSize, '1m'),
        ensureLocSuffix(form.locHorizPre, '10000m'),
        ensureLocSuffix(form.locVertPre, '10m'),
      ].join(' ')
    case 'URI':
      return `${form.uriPriority} ${form.uriWeight} ${form.uriTarget.trim()}`
    case 'SOA':
      return [
        form.soaPrimaryNS.trim(),
        form.soaAdminEmail.trim(),
        form.soaSerial,
        form.soaRefresh.trim(),
        form.soaRetry.trim(),
        form.soaExpire.trim(),
        form.soaMinimumTTL.trim(),
      ].join(' ')
    default:
      return form.content.trim()
  }
}

function resetTypeSpecificFields(form: RecordFormState): void {
  const defaults = createDefaultFormState()
  form.content = defaults.content
  form.mxPriority = defaults.mxPriority
  form.mxTarget = defaults.mxTarget
  form.srvPriority = defaults.srvPriority
  form.srvWeight = defaults.srvWeight
  form.srvPort = defaults.srvPort
  form.srvTarget = defaults.srvTarget
  form.caaFlags = defaults.caaFlags
  form.caaTag = defaults.caaTag
  form.caaValue = defaults.caaValue
  form.dsKeyTag = defaults.dsKeyTag
  form.dsAlgorithm = defaults.dsAlgorithm
  form.dsDigestType = defaults.dsDigestType
  form.dsDigest = defaults.dsDigest
  form.sshfpAlgorithm = defaults.sshfpAlgorithm
  form.sshfpType = defaults.sshfpType
  form.sshfpFingerprint = defaults.sshfpFingerprint
  form.daneUsage = defaults.daneUsage
  form.daneSelector = defaults.daneSelector
  form.daneMatchingType = defaults.daneMatchingType
  form.daneCertificate = defaults.daneCertificate
  form.dnskeyFlags = defaults.dnskeyFlags
  form.dnskeyProtocol = defaults.dnskeyProtocol
  form.dnskeyAlgorithm = defaults.dnskeyAlgorithm
  form.dnskeyPublicKey = defaults.dnskeyPublicKey
  form.svcPriority = defaults.svcPriority
  form.svcTarget = defaults.svcTarget
  form.svcParams = defaults.svcParams
  form.certType = defaults.certType
  form.certKeyTag = defaults.certKeyTag
  form.certAlgorithm = defaults.certAlgorithm
  form.certData = defaults.certData
  form.naptrOrder = defaults.naptrOrder
  form.naptrPreference = defaults.naptrPreference
  form.naptrFlags = defaults.naptrFlags
  form.naptrService = defaults.naptrService
  form.naptrRegexp = defaults.naptrRegexp
  form.naptrReplacement = defaults.naptrReplacement
  form.locLatDeg = defaults.locLatDeg
  form.locLatMin = defaults.locLatMin
  form.locLatSec = defaults.locLatSec
  form.locLatHem = defaults.locLatHem
  form.locLonDeg = defaults.locLonDeg
  form.locLonMin = defaults.locLonMin
  form.locLonSec = defaults.locLonSec
  form.locLonHem = defaults.locLonHem
  form.locAltitude = defaults.locAltitude
  form.locSize = defaults.locSize
  form.locHorizPre = defaults.locHorizPre
  form.locVertPre = defaults.locVertPre
  form.uriPriority = defaults.uriPriority
  form.uriWeight = defaults.uriWeight
  form.uriTarget = defaults.uriTarget
  form.soaPrimaryNS = defaults.soaPrimaryNS
  form.soaAdminEmail = defaults.soaAdminEmail
  form.soaSerial = defaults.soaSerial
  form.soaRefresh = defaults.soaRefresh
  form.soaRetry = defaults.soaRetry
  form.soaExpire = defaults.soaExpire
  form.soaMinimumTTL = defaults.soaMinimumTTL
}

function unquoteToken(token: string): string {
  const trimmed = token.trim()
  if (trimmed.startsWith('"') && trimmed.endsWith('"') && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')
  }
  return trimmed
}

function parseNaptrValue(value: string, form: RecordFormState): void {
  const tokens: string[] = []
  let current = ''
  let inQuotes = false
  let escaped = false

  for (const ch of value.trim()) {
    if (escaped) {
      current += ch
      escaped = false
      continue
    }
    if (ch === '\\') {
      current += ch
      escaped = true
      continue
    }
    if (ch === '"') {
      current += ch
      inQuotes = !inQuotes
      continue
    }
    if (!inQuotes && /\s/.test(ch)) {
      if (current) {
        tokens.push(current)
        current = ''
      }
      continue
    }
    current += ch
  }
  if (current) {
    tokens.push(current)
  }

  form.naptrOrder = Number(tokens[0]) || 0
  form.naptrPreference = Number(tokens[1]) || 0
  form.naptrFlags = unquoteToken(tokens[2] ?? '')
  form.naptrService = unquoteToken(tokens[3] ?? '')
  form.naptrRegexp = unquoteToken(tokens[4] ?? '')
  form.naptrReplacement = unquoteToken(tokens[5] ?? '.')
}

export function populateFormFromRecord(
  form: RecordFormState,
  record: { type: string; value: string; name: string; ttl: string },
): void {
  form.name = record.name
  form.type = record.type as RecordType
  form.ttl = record.ttl
  resetTypeSpecificFields(form)

  const value = record.value.trim()
  const parts = splitRecordValue(value)

  switch (record.type) {
    case 'SOA':
      form.soaPrimaryNS = stripTrailingDot(parts[0] ?? '')
      form.soaAdminEmail = stripTrailingDot(parts[1] ?? '')
      form.soaSerial = Number(parts[2]) || 0
      form.soaRefresh = parts[3] ?? '3600'
      form.soaRetry = parts[4] ?? '600'
      form.soaExpire = parts[5] ?? '86400'
      form.soaMinimumTTL = parts[6] ?? '300'
      break
    case 'MX':
      form.mxPriority = Number(parts[0]) || 10
      form.mxTarget = parts.slice(1).join(' ')
      break
    case 'SRV':
      form.srvPriority = Number(parts[0]) || 0
      form.srvWeight = Number(parts[1]) || 0
      form.srvPort = Number(parts[2]) || 0
      form.srvTarget = parts.slice(3).join(' ')
      break
    case 'CAA':
      form.caaFlags = Number(parts[0]) || 0
      form.caaTag = parts[1] ?? 'issue'
      form.caaValue = parts.slice(2).join(' ').replace(/^"|"$/g, '')
      break
    case 'DS':
      form.dsKeyTag = Number(parts[0]) || 0
      form.dsAlgorithm = Number(parts[1]) || 13
      form.dsDigestType = Number(parts[2]) || 2
      form.dsDigest = parts.slice(3).join('')
      break
    case 'SSHFP':
      form.sshfpAlgorithm = Number(parts[0]) || 1
      form.sshfpType = Number(parts[1]) || 1
      form.sshfpFingerprint = parts.slice(2).join('')
      break
    case 'TLSA':
    case 'SMIMEA':
      form.daneUsage = Number(parts[0]) || 0
      form.daneSelector = Number(parts[1]) || 0
      form.daneMatchingType = Number(parts[2]) || 0
      form.daneCertificate = parts.slice(3).join('')
      break
    case 'DNSKEY':
      form.dnskeyFlags = Number(parts[0]) || 256
      form.dnskeyProtocol = Number(parts[1]) || 3
      form.dnskeyAlgorithm = Number(parts[2]) || 13
      form.dnskeyPublicKey = parts.slice(3).join('')
      break
    case 'HTTPS':
    case 'SVCB':
      form.svcPriority = Number(parts[0]) || 1
      form.svcTarget = parts[1] ?? '.'
      form.svcParams = parts.slice(2).join(' ')
      break
    case 'CERT':
      form.certType = Number(parts[0]) || 1
      form.certKeyTag = Number(parts[1]) || 0
      form.certAlgorithm = Number(parts[2]) || 13
      form.certData = parts.slice(3).join('')
      break
    case 'NAPTR':
      parseNaptrValue(value, form)
      break
    case 'LOC':
      form.locLatDeg = Number(parts[0]) || 0
      form.locLatMin = Number(parts[1]) || 0
      form.locLatSec = parts[2] ?? '0.000'
      form.locLatHem = (parts[3] as 'N' | 'S') ?? 'N'
      form.locLonDeg = Number(parts[4]) || 0
      form.locLonMin = Number(parts[5]) || 0
      form.locLonSec = parts[6] ?? '0.000'
      form.locLonHem = (parts[7] as 'E' | 'W') ?? 'E'
      form.locAltitude = parts[8] ?? '0.00m'
      form.locSize = parts[9] ?? '1m'
      form.locHorizPre = parts[10] ?? '10000m'
      form.locVertPre = parts[11] ?? '10m'
      break
    case 'URI':
      form.uriPriority = Number(parts[0]) || 0
      form.uriWeight = Number(parts[1]) || 0
      form.uriTarget = parts.slice(2).join(' ')
      break
    default:
      form.content = value
      break
  }
}

function validateName(name: string): string | undefined {
  if (!name) {
    return 'Name is required. Use @ for the zone apex.'
  }
  if (name === '@') {
    return undefined
  }
  if (name.includes('..')) {
    return 'Name cannot contain consecutive dots.'
  }
  if (!/^[a-zA-Z0-9_*.-]+$/.test(name)) {
    return 'Name contains invalid characters.'
  }
  for (const label of name.split('.')) {
    if (!label) {
      return 'Name cannot contain empty labels.'
    }
    if (label.length > 63) {
      return 'Each label must be 63 characters or fewer.'
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return 'Labels cannot start or end with a hyphen.'
    }
  }
  return undefined
}

export function validateRecordForm(form: RecordFormState): RecordFormErrors {
  const errors: RecordFormErrors = {}
  const nameError = validateName(form.name.trim())
  if (nameError) {
    errors.name = nameError
  }

  if (!isValidBindTTL(form.ttl)) {
    errors.ttl = 'Enter a valid TTL (e.g. 3600, 5m, 1h, 1d).'
  }

  switch (form.type) {
    case 'MX':
      if (!Number.isFinite(form.mxPriority) || form.mxPriority < 0) {
        errors.mxPriority = 'Priority must be 0 or greater.'
      }
      if (!form.mxTarget.trim()) {
        errors.mxTarget = 'Mail server target is required.'
      }
      break
    case 'SRV':
      if (!Number.isFinite(form.srvPriority) || form.srvPriority < 0) {
        errors.srvPriority = 'Priority must be 0 or greater.'
      }
      if (!Number.isFinite(form.srvWeight) || form.srvWeight < 0) {
        errors.srvWeight = 'Weight must be 0 or greater.'
      }
      if (
        !Number.isFinite(form.srvPort) ||
        form.srvPort < 1 ||
        form.srvPort > 65535
      ) {
        errors.srvPort = 'Port must be between 1 and 65535.'
      }
      if (!form.srvTarget.trim()) {
        errors.srvTarget = 'Target is required.'
      }
      break
    case 'CAA':
      if (!form.caaValue.trim()) {
        errors.caaValue = 'CAA value is required.'
      }
      break
    case 'DS':
      if (!form.dsDigest.trim()) {
        errors.dsDigest = 'Digest is required.'
      }
      break
    case 'SSHFP':
      if (!form.sshfpFingerprint.trim()) {
        errors.sshfpFingerprint = 'Fingerprint is required.'
      }
      break
    case 'TLSA':
    case 'SMIMEA':
      if (!form.daneCertificate.trim()) {
        errors.daneCertificate = 'Certificate data is required.'
      }
      break
    case 'DNSKEY':
      if (!form.dnskeyPublicKey.trim()) {
        errors.dnskeyPublicKey = 'Public key is required.'
      }
      break
    case 'HTTPS':
    case 'SVCB':
      if (!form.svcTarget.trim()) {
        errors.svcTarget = 'Target is required.'
      }
      break
    case 'CERT':
      if (!form.certData.trim()) {
        errors.certData = 'Certificate data is required.'
      }
      break
    case 'NAPTR':
      if (!form.naptrFlags.trim()) {
        errors.naptrFlags = 'Flags are required.'
      }
      if (!form.naptrService.trim()) {
        errors.naptrService = 'Service is required.'
      }
      if (!form.naptrRegexp.trim()) {
        errors.naptrRegexp = 'Regular expression is required.'
      }
      if (!form.naptrReplacement.trim()) {
        errors.naptrReplacement = 'Replacement is required.'
      }
      break
    case 'URI':
      if (!form.uriTarget.trim()) {
        errors.uriTarget = 'Target URI is required.'
      }
      break
    case 'SOA':
      if (!form.soaPrimaryNS.trim()) {
        errors.soaPrimaryNS = 'Primary nameserver is required.'
      }
      if (!form.soaAdminEmail.trim()) {
        errors.soaAdminEmail = 'Admin email is required.'
      }
      if (!isValidBindTTL(form.soaRefresh)) {
        errors.soaRefresh = 'Enter a valid TTL (e.g. 3600, 1h).'
      }
      if (!isValidBindTTL(form.soaRetry)) {
        errors.soaRetry = 'Enter a valid TTL (e.g. 600, 10m).'
      }
      if (!isValidBindTTL(form.soaExpire)) {
        errors.soaExpire = 'Enter a valid TTL (e.g. 86400, 1d).'
      }
      if (!isValidBindTTL(form.soaMinimumTTL)) {
        errors.soaMinimumTTL = 'Enter a valid TTL (e.g. 300, 5m).'
      }
      break
    default:
      if (!form.content.trim()) {
        errors.value = 'Value is required.'
      }
      break
  }

  return errors
}

export function contentPlaceholder(type: RecordType): string {
  switch (type) {
    case 'A':
      return '192.0.2.1'
    case 'AAAA':
      return '2001:db8::1'
    case 'TXT':
      return 'Text value or quoted string'
    case 'CNAME':
    case 'PTR':
    case 'NS':
      return 'Target hostname'
    case 'OPENPGPKEY':
      return 'Base64-encoded OpenPGP key'
    default:
      return 'Record content'
  }
}
