import { NavLink } from 'react-router-dom';

const nav = [
  { to: '/',        icon: '◈', label: 'Overview'  },
  { to: '/agents',  icon: '◎', label: 'Agents'    },
  { to: '/log',     icon: '≡', label: 'Trust Log' },
  { to: '/keys',    icon: '⚿', label: 'API Keys'  },
  { to: '/billing', icon: '◉', label: 'Billing'   },
  { to: '/health',  icon: '♡', label: 'Health'    },
];

export function Sidebar() {
  return (
    <aside className="w-56 min-h-screen bg-card border-r border-border flex flex-col">
      {/* Logo */}
      <div className="px-5 py-5 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-purple flex items-center justify-center text-white font-bold text-sm">Β</div>
          <div>
            <div className="text-white font-semibold text-sm">Byzantium</div>
            <div className="text-dim text-xs">Admin Console</div>
          </div>
        </div>
      </div>
      {/* Nav */}
      <nav className="flex-1 py-4 px-3">
        {nav.map(({ to, icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg mb-1 text-sm transition-all ${
                isActive
                  ? 'bg-purple/10 text-purple font-medium'
                  : 'text-mid hover:text-white hover:bg-border'
              }`
            }
          >
            <span className="text-base w-5">{icon}</span>
            {label}
          </NavLink>
        ))}
      </nav>
      {/* Footer */}
      <div className="px-5 py-4 border-t border-border">
        <div className="text-xs text-dim">v0.1.0 · Production</div>
      </div>
    </aside>
  );
}
