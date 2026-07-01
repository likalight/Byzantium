import { useState } from 'react';
import { TopBar } from '../components/TopBar';

interface ApiKey {
  id: string;
  name: string;
  masked: string;
  created: string;
  lastUsed: string;
  status: 'Active' | 'Revoked';
}

const initialKeys: ApiKey[] = [
  { id: '1', name: 'Production Gateway',  masked: 'byz_prod_...f82a', created: '2024-11-01', lastUsed: '2 min ago',  status: 'Active'  },
  { id: '2', name: 'Staging Environment', masked: 'byz_stg_...c19d',  created: '2024-12-10', lastUsed: '3 hrs ago',  status: 'Active'  },
  { id: '3', name: 'CI Pipeline',         masked: 'byz_ci_...7b3e',   created: '2025-01-05', lastUsed: '1 day ago',  status: 'Active'  },
];

export function ApiKeys() {
  const [keys, setKeys] = useState<ApiKey[]>(initialKeys);
  const [showModal, setShowModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [revokeConfirm, setRevokeConfirm] = useState<string | null>(null);

  const handleCreate = () => {
    if (!newKeyName.trim()) return;
    const fakeKey = `byz_${newKeyName.toLowerCase().replace(/\s+/g, '_').slice(0, 6)}_...${Math.random().toString(36).slice(2, 6)}`;
    const newKey: ApiKey = {
      id:       String(Date.now()),
      name:     newKeyName.trim(),
      masked:   fakeKey,
      created:  new Date().toISOString().slice(0, 10),
      lastUsed: 'Never',
      status:   'Active',
    };
    setKeys(prev => [newKey, ...prev]);
    setCreatedKey(fakeKey + 'xxxxxxxxxxxxxxxx'); // show full key once
    setNewKeyName('');
  };

  const handleRevoke = (id: string) => {
    setKeys(prev => prev.map(k => k.id === id ? { ...k, status: 'Revoked' as const } : k));
    setRevokeConfirm(null);
  };

  return (
    <div className="flex-1 overflow-auto">
      <TopBar title="API Keys" sub="Manage authentication keys for gateway access" />
      <div className="p-8">
        {/* Header row */}
        <div className="flex items-center justify-between mb-6">
          <div className="text-dim text-sm">{keys.filter(k => k.status === 'Active').length} active keys</div>
          <button
            onClick={() => { setShowModal(true); setCreatedKey(null); }}
            className="px-4 py-2 bg-purple hover:bg-purple/90 text-white text-sm font-medium rounded-lg transition-colors"
          >
            + Create Key
          </button>
        </div>

        <div className="bg-card border border-border rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-dim text-xs border-b border-border bg-bg/50">
                <th className="text-left px-5 py-3 font-medium">Name</th>
                <th className="text-left px-5 py-3 font-medium">Key</th>
                <th className="text-left px-5 py-3 font-medium">Created</th>
                <th className="text-left px-5 py-3 font-medium">Last Used</th>
                <th className="text-left px-5 py-3 font-medium">Status</th>
                <th className="text-left px-5 py-3 font-medium">Action</th>
              </tr>
            </thead>
            <tbody>
              {keys.map(key => (
                <tr key={key.id} className="border-b border-border last:border-0 hover:bg-border/20 transition-colors">
                  <td className="px-5 py-4 font-medium text-white">{key.name}</td>
                  <td className="px-5 py-4 font-mono text-xs text-mid bg-bg/30">{key.masked}</td>
                  <td className="px-5 py-4 text-xs text-dim">{key.created}</td>
                  <td className="px-5 py-4 text-xs text-dim">{key.lastUsed}</td>
                  <td className="px-5 py-4">
                    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${
                      key.status === 'Active'
                        ? 'bg-green/10 text-green border border-green/20'
                        : 'bg-dim/10 text-dim border border-dim/20 line-through'
                    }`}>{key.status}</span>
                  </td>
                  <td className="px-5 py-4">
                    {key.status === 'Active' && (
                      revokeConfirm === key.id ? (
                        <div className="flex items-center gap-2">
                          <span className="text-xs text-dim">Confirm?</span>
                          <button onClick={() => handleRevoke(key.id)} className="text-xs text-red hover:underline font-medium">Yes</button>
                          <button onClick={() => setRevokeConfirm(null)} className="text-xs text-dim hover:text-white">Cancel</button>
                        </div>
                      ) : (
                        <button
                          onClick={() => setRevokeConfirm(key.id)}
                          className="text-xs text-red/70 hover:text-red transition-colors font-medium"
                        >
                          Revoke
                        </button>
                      )
                    )}
                    {key.status === 'Revoked' && <span className="text-xs text-dim">—</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Key Modal */}
      {showModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-card border border-border rounded-2xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-white font-semibold">Create API Key</h2>
              <button onClick={() => { setShowModal(false); setCreatedKey(null); }} className="text-dim hover:text-white text-xl leading-none">×</button>
            </div>

            {!createdKey ? (
              <>
                <div className="mb-4">
                  <label className="block text-dim text-xs font-medium mb-2 uppercase tracking-wide">Key Name</label>
                  <input
                    type="text"
                    value={newKeyName}
                    onChange={e => setNewKeyName(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleCreate()}
                    placeholder="e.g. Production Gateway"
                    className="w-full bg-bg border border-border rounded-lg px-3 py-2.5 text-sm text-white placeholder-dim focus:outline-none focus:border-purple transition-colors"
                    autoFocus
                  />
                </div>
                <div className="flex gap-3 justify-end">
                  <button onClick={() => setShowModal(false)} className="px-4 py-2 text-sm text-dim hover:text-white transition-colors">
                    Cancel
                  </button>
                  <button
                    onClick={handleCreate}
                    disabled={!newKeyName.trim()}
                    className="px-4 py-2 bg-purple hover:bg-purple/90 disabled:opacity-40 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    Create Key
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="bg-green/5 border border-green/20 rounded-lg p-4 mb-4">
                  <div className="text-green text-xs font-medium mb-2">Key created — copy it now, it won't be shown again</div>
                  <div className="font-mono text-xs text-white break-all bg-bg rounded p-2">{createdKey}</div>
                </div>
                <button
                  onClick={() => { setShowModal(false); setCreatedKey(null); }}
                  className="w-full px-4 py-2 bg-purple hover:bg-purple/90 text-white text-sm font-medium rounded-lg transition-colors"
                >
                  Done
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
