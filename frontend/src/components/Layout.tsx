import { NavLink, useNavigate } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from '../lib/auth'

interface NavItem {
  to: string
  label: string
  visible: boolean
}

/**
 * Layout is the fixed rail plus content column. The rail stays narrow so the
 * ledger of secrets keeps the width it needs.
 */
export function Layout({ children }: { children: ReactNode }) {
  const { user, isAdmin, can, signOut } = useAuth()
  const navigate = useNavigate()

  const items: NavItem[] = [
    { to: '/secrets', label: 'Secrets', visible: true },
    { to: '/groups', label: 'Groups', visible: true },
    { to: '/tokens', label: 'API tokens', visible: true },
    { to: '/users', label: 'Users', visible: can('users:manage') },
    { to: '/audit', label: 'Audit', visible: isAdmin },
  ]

  return (
    <div className="flex min-h-screen flex-col lg:flex-row">
      <nav className="flex shrink-0 flex-col gap-1 border-b border-edge bg-plate/60 px-4 py-4 lg:w-56 lg:border-b-0 lg:border-r lg:px-4 lg:py-6">
        <div className="mb-4 flex items-center gap-2.5 px-1">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden>
            <circle cx="16" cy="13" r="5" fill="none" stroke="#C79A3C" strokeWidth="2.5" />
            <path d="M16 18v7" stroke="#C79A3C" strokeWidth="2.5" strokeLinecap="round" />
            <path d="M16 22h4" stroke="#C79A3C" strokeWidth="2.5" strokeLinecap="round" />
          </svg>
          <span className="font-display text-sm font-bold uppercase tracking-[0.2em] text-chalk">
            Secrets
          </span>
        </div>

        <div className="flex gap-1 overflow-x-auto lg:flex-col lg:overflow-visible">
          {items
            .filter((item) => item.visible)
            .map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  [
                    'relative shrink-0 rounded-md px-3 py-2 text-sm transition-colors',
                    isActive
                      ? 'bg-raised text-brass-bright'
                      : 'text-muted hover:bg-raised/60 hover:text-chalk',
                  ].join(' ')
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive && (
                      <span
                        className="absolute left-0 top-1/2 hidden h-4 w-0.5 -translate-y-1/2 rounded-r bg-brass lg:block"
                        aria-hidden
                      />
                    )}
                    {item.label}
                  </>
                )}
              </NavLink>
            ))}
        </div>

        <div className="mt-auto hidden border-t border-edge pt-4 lg:block">
          <p className="px-1 text-sm text-chalk">{user?.displayName || user?.username}</p>
          <p className="px-1 font-mono text-[11px] text-muted">
            {isAdmin ? 'administrator' : `${user?.permissions.length ?? 0} permissions`}
          </p>
          <button
            className="btn-ghost mt-3 w-full px-3 py-1.5 text-xs"
            onClick={() => {
              signOut()
              navigate('/login')
            }}
          >
            Sign out
          </button>
        </div>

        <button
          className="btn-ghost ml-auto shrink-0 px-3 py-1.5 text-xs lg:hidden"
          onClick={() => {
            signOut()
            navigate('/login')
          }}
        >
          Sign out
        </button>
      </nav>

      <main className="min-w-0 flex-1 px-4 py-6 sm:px-8 sm:py-10">
        <div className="mx-auto max-w-5xl">{children}</div>
      </main>
    </div>
  )
}

/** PageHeader keeps the title, one line of orientation, and the primary action together. */
export function PageHeader({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <header className="mb-7 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="font-display text-2xl font-medium tracking-tight text-chalk">{title}</h1>
        <p className="mt-1 max-w-xl text-sm text-muted">{description}</p>
      </div>
      {action}
    </header>
  )
}
