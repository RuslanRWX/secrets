import { useEffect, useState } from 'react'
import { ApiError, api, type AuditEntry } from '../lib/api'
import { PageHeader } from '../components/Layout'
import { Empty, Notice, Spinner, formatDate } from '../components/ui'

/** Actions that touch plaintext are highlighted; the rest are routine. */
const NOTABLE = new Set(['secret.revealed', 'auth.login_failed', 'token.created', 'user.password_reset'])

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .audit()
      .then((result) => setEntries(result.entries))
      .catch((caught) =>
        setError(caught instanceof ApiError ? caught.message : 'The audit log could not be loaded.'),
      )
      .finally(() => setLoading(false))
  }, [])

  return (
    <>
      <PageHeader
        title="Audit"
        description="Who did what, and when. Every decryption of a secret is recorded here."
      />

      {error && <Notice kind="error">{error}</Notice>}
      {loading && <Spinner label="Loading the audit log" />}
      {!loading && entries.length === 0 && <Empty title="Nothing has been recorded yet." />}

      {entries.length > 0 && (
        <ol className="panel divide-y divide-edge">
          {entries.map((entry) => (
            <li key={entry.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-2.5 text-sm">
              <time className="w-40 shrink-0 font-mono text-[11px] text-muted">
                {formatDate(entry.createdAt)}
              </time>
              <code className={NOTABLE.has(entry.action) ? 'text-brass' : 'text-chalk'}>{entry.action}</code>
              <span className="text-muted">{entry.actorLabel}</span>
              {entry.targetId && (
                <code className="ml-auto truncate text-muted">{entry.targetId.slice(0, 8)}</code>
              )}
            </li>
          ))}
        </ol>
      )}
    </>
  )
}
