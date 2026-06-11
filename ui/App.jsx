import React, { useState, useEffect, useCallback, useMemo } from 'react';

const API_BASE = '';
const fetchConfig = { credentials: 'same-origin' };

export default function App() {
    const [identity, setIdentity] = useState(null);
    const [error, setError] = useState('');
    const [isChecking, setIsChecking] = useState(true);

    const checkAuth = async () => {
        try {
            const res = await fetch(`${API_BASE}/v1/auth/me`, fetchConfig);
            if (res.ok) setIdentity(await res.json());
            else setIdentity(null);
        } catch (err) {
            console.error('Auth check failed:', err);
            setIdentity(null);
        } finally {
            setIsChecking(false);
        }
    };

    const login = async (username, password) => {
        try {
            const res = await fetch(`${API_BASE}/v1/auth/login`, {
                ...fetchConfig,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (!res.ok) throw new Error('Invalid credentials');
            await checkAuth();
        } catch (err) {
            console.error('Login failed:', err);
            setError('Login failed. Invalid username or password.');
        }
    };

    const logout = async () => {
        await fetch(`${API_BASE}/v1/auth/logout`, { ...fetchConfig, method: 'POST' });
        setIdentity(null);
    };

    useEffect(() => { checkAuth(); }, []);

    if (isChecking) return <div className="min-h-screen flex items-center justify-center text-gray-400 font-sans">Evaluating session constraints...</div>;
    if (!identity) return <Login onLogin={login} error={error} />;

    return (
        <div className="max-w-6xl mx-auto p-6 font-sans">
            <header className="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
                <div>
                    <h1 className="text-2xl font-bold flex items-center gap-3">Tiny Secrets Manager</h1>
                    <p className="text-sm text-gray-400">Authenticated as: <span className="text-blue-400">{identity.name}</span> {identity.is_admin ? '(Admin)' : ''}</p>
                </div>
                <div className="flex items-center gap-6">
                    <a 
                        href="https://github.com/abnabnabn/tiny-secrets-manager" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-gray-500 hover:text-gray-300 transition flex items-center gap-2"
                        title="View on GitHub"
                    >
                        <svg className="w-6 h-6 fill-current" viewBox="0 0 24 24">
                            <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 4.238 9.612 9.823 10.602.6.11.822-.26.822-.577v-2.238c-3.338.73-4.042-1.61-4.042-1.61C6.094 17.13 5.115 16.52 5.115 16.52c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 3.07 1.305 3.819 1.01.108-.775.42-1.305.762-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22v3.293c0 .319.22.69.825.57C19.765 21.61 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
                        </svg>
                    </a>
                    <button onClick={logout} className="bg-red-900/50 hover:bg-red-800 text-red-200 px-4 py-2 rounded transition">
                        Logout
                    </button>
                </div>
            </header>
            <Dashboard identity={identity} />
        </div>
    );
}

function Login({ onLogin, error }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    return (
        <div className="flex items-center justify-center min-h-screen font-sans">
            <form onSubmit={(e) => { e.preventDefault(); onLogin(username, password); }} className="bg-gray-800 p-8 rounded-lg shadow-xl w-96 border border-gray-700">
                <h2 className="text-xl font-bold mb-6 text-white text-center">Admin Login</h2>
                {error && <p className="text-red-400 text-sm mb-4">{error}</p>}
                <div className="mb-4">
                    <label className="block text-xs text-gray-400 mb-1">Username</label>
                    <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g. admin" className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-gray-100 focus:outline-none focus:border-blue-500" required />
                </div>
                <div className="mb-6">
                    <label className="block text-xs text-gray-400 mb-1">Password</label>
                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••••••" className="w-full bg-gray-900 border border-gray-700 rounded p-3 text-gray-100 focus:outline-none focus:border-blue-500" required />
                </div>
                <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold p-3 rounded transition shadow-lg">Sign In</button>
            </form>
        </div>
    );
}

function Dashboard({ identity }) {
    const [view, setView] = useState('secrets');
    const [roles, setRoles] = useState([]);
    const [filterRoleName, setFilterRoleName] = useState('');

    const fetchRoles = useCallback(async () => {
        if (!identity || !identity.is_admin) return;
        const res = await fetch(`${API_BASE}/v1/roles`, fetchConfig);
        if (res.ok) setRoles(await res.json() || []);
    }, [identity]);

    useEffect(() => { fetchRoles(); }, [fetchRoles]);

    return (
        <div className="font-sans text-gray-100">
            <nav className="flex space-x-4 mb-6">
                <button onClick={() => setView('secrets')} className={`px-4 py-2 rounded transition-all ${view === 'secrets' ? 'bg-gray-800 border-b-2 border-blue-500 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}>Secrets</button>
                {identity.is_admin && (
                    <React.Fragment>
                        <button onClick={() => setView('roles')} className={`px-4 py-2 rounded transition-all ${view === 'roles' ? 'bg-gray-800 border-b-2 border-blue-500 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}>Role Management</button>
                        <button onClick={() => setView('setup')} className={`px-4 py-2 rounded transition-all ${view === 'setup' ? 'bg-gray-800 border-b-2 border-blue-500 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}>Setup & Recovery</button>
                        <button onClick={() => setView('system')} className={`px-4 py-2 rounded transition-all ${view === 'system' ? 'bg-gray-800 border-b-2 border-blue-500 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}>System Settings</button>
                    </React.Fragment>
                )}
            </nav>
            {view === 'secrets' && <SecretsManager identity={identity} roles={roles} filterRoleName={filterRoleName} setFilterRoleName={setFilterRoleName} refreshRoles={fetchRoles} />}
            {view === 'roles' && <RoleManager roles={roles} refreshRoles={fetchRoles} />}
            {view === 'setup' && <SetupManager />}
            {view === 'system' && <SystemSettings />}
        </div>
    );
}

function SetupManager() {
    const [recoveryKeys, setRecoveryKeys] = useState([]);
    const [isRegenerating, setIsRegenerating] = useState(false);

    const handleRegenerateRecoveryKeys = async () => {
        if (!confirm("Are you sure? This will immediately invalidate all old emergency recovery keys.")) return;
        setIsRegenerating(true);
        try {
            const res = await fetch(`${API_BASE}/v1/recovery-keys/regenerate`, {
                ...fetchConfig,
                method: 'POST'
            });
            if (res.ok) {
                const data = await res.json();
                setRecoveryKeys(data.recovery_keys);
            } else {
                alert("Failed to regenerate recovery keys.");
            }
        } catch (e) {
            alert("Network error.");
        } finally {
            setIsRegenerating(false);
        }
    };

    return (
        <div className="max-w-2xl font-sans">
            <div className="bg-gray-800 p-8 rounded-lg border border-red-950 shadow-xl">
                <h3 className="text-xl font-bold text-red-400 mb-4">Emergency Recovery Management</h3>
                <p className="text-gray-300 mb-6 leading-relaxed">
                    Emergency recovery keys are used to unlock the database if the master encryption key is lost. 
                    <span className="text-red-400 font-bold block mt-2">Warning: Regenerating recovery keys immediately invalidates the previous set.</span>
                </p>
                
                <button 
                    onClick={handleRegenerateRecoveryKeys} 
                    disabled={isRegenerating}
                    className="bg-red-900 hover:bg-red-800 text-white font-bold px-6 py-3 rounded transition disabled:opacity-50 shadow-md"
                >
                    {isRegenerating ? "Regenerating..." : "Regenerate Recovery Keys"}
                </button>

                {recoveryKeys.length > 0 && (
                    <div className="mt-8 bg-red-950/40 border border-red-900 rounded-lg p-6">
                        <h4 className="text-lg font-semibold text-red-300 mb-2">New Recovery Keys:</h4>
                        <p className="text-sm text-gray-400 mb-4 italic">
                            Copy these keys immediately and store them in a secure, offline location. They will NOT be shown again.
                        </p>
                        <ul className="space-y-3">
                            {recoveryKeys.map((k, idx) => (
                                <li key={idx} className="bg-black p-3 rounded font-mono text-sm break-all select-all border border-red-900/30 shadow-inner">
                                    <span className="text-red-500 font-bold mr-3">Key {idx+1}:</span>{k}
                                </li>
                            ))}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
}

function SecretsManager({ identity, roles, filterRoleName, setFilterRoleName, refreshRoles }) {
    const [secrets, setSecrets] = useState([]);
    const [readSecret, setReadSecret] = useState(null);
    const [isAdding, setIsAdding] = useState(false);
    const [isEditing, setIsEditing] = useState(false);
    const [originalKey, setOriginalKey] = useState('');
    const [newKey, setNewKey] = useState('');
    const [newValue, setNewValue] = useState('');
    const [newEnvKey, setNewEnvKey] = useState('');
    const [isImporting, setIsImporting] = useState(false);
    const [importText, setImportText] = useState('');
    const [importAnalysis, setImportAnalysis] = useState(null);
    const [isImportProcessing, setIsImportProcessing] = useState(false);
    const [resolvedPreview, setResolvedPreview] = useState('');
    const [originalValue, setOriginalValue] = useState('');
    const [originalEnvKey, setOriginalEnvKey] = useState('');
    const [autoPopulateEnv, setAutoPopulateEnv] = useState(true);

    useEffect(() => {
        if (identity.is_admin) {
            fetch(`${API_BASE}/v1/system/settings`, fetchConfig)
                .then(res => res.ok ? res.json() : null)
                .then(data => {
                    if (data && data.auto_populate_env_name === 'false') {
                        setAutoPopulateEnv(false);
                    }
                })
                .catch(e => console.error('Failed to fetch settings', e));
        }
    }, [identity.is_admin]);

    const checkUnsavedChanges = () => {
        if (!isAdding && !isEditing) return true;
        const hasChanges = newKey !== originalKey || newValue !== originalValue || newEnvKey !== originalEnvKey;
        if (hasChanges) {
            return confirm("You have unsaved changes. Are you sure you want to discard them?");
        }
        return true;
    };

    const handleKeyChange = (e) => {
        const val = e.target.value;
        setNewKey(val);
        if (autoPopulateEnv) {
            const prevAutoEnv = newKey.replace(/\./g, '_').toUpperCase();
            if (!newEnvKey || newEnvKey === prevAutoEnv) {
                setNewEnvKey(val.replace(/\./g, '_').toUpperCase());
            }
        }
    };

    const getHeaders = useCallback(() => {
        const headers = { 'Content-Type': 'application/json' };
        if (filterRoleName) headers['X-Impersonate-Token'] = filterRoleName;
        return headers;
    }, [filterRoleName]);

    const fetchSecrets = useCallback(async () => {
        const res = await fetch(`${API_BASE}/v1/secrets`, fetchConfig);
        if (res.ok) setSecrets(await res.json() || []);
    }, []);

    useEffect(() => { fetchSecrets(); }, [fetchSecrets]);

    useEffect(() => {
        if (!newValue || !newValue.includes('${')) {
            setResolvedPreview('');
            return;
        }
        const timer = setTimeout(async () => {
            try {
                const res = await fetch(`${API_BASE}/v1/secrets/resolve`, {
                    ...fetchConfig,
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify({ value: newValue })
                });
                if (res.ok) {
                    const data = await res.json();
                    setResolvedPreview(data.value);
                }
            } catch (e) {
                console.error('Resolution failed', e);
            }
        }, 500);
        return () => clearTimeout(timer);
    }, [newValue, getHeaders]);

    const selectedRole = useMemo(() => roles.find(t => t.name === filterRoleName), [filterRoleName, roles]);

    const getPerms = useCallback((key) => {
        if (!selectedRole) return { GET: true, LIST: true, PUT: true, DELETE: true };
        const res = { GET: false, LIST: false, PUT: false, DELETE: false };
        selectedRole.policies.forEach(p => {
            let matched = false;
            if (p.prefix === '*') {
                matched = true;
            } else if (p.prefix.endsWith('*')) {
                const base = p.prefix.slice(0, -1);
                matched = key && key.startsWith(base);
            } else {
                matched = key === p.prefix || (key && key.startsWith(p.prefix + '.'));
            }

            if (matched) {
                p.methods.forEach(m => {
                    if (m === '*') { res.GET = res.LIST = res.PUT = res.DELETE = true; }
                    else if (res.hasOwnProperty(m)) { res[m] = true; }
                });
            }
        });
        return res;
    }, [selectedRole]);

    const groupedSecrets = useMemo(() => {
        if (!selectedRole) return [{ name: 'All Secrets Manager Secrets', methods: ['*'], items: secrets }];

        const groups = selectedRole.policies.map(p => ({
            name: `Prefix: ${p.prefix}`,
            methods: p.methods,
            items: []
        }));

        const unmatched = { name: 'Unmatched / Denied (Audit View)', methods: [], items: [] };

        secrets.forEach(key => {
            const matches = selectedRole.policies.filter(p => p.prefix === '*' || key.startsWith(p.prefix));
            if (matches.length > 0) {
                let bestMatch = matches[0];
                matches.forEach(m => {
                    if (m.prefix.length > bestMatch.prefix.length) bestMatch = m;
                });
                const groupIdx = selectedRole.policies.indexOf(bestMatch);
                groups[groupIdx].items.push(key);
            } else {
                unmatched.items.push(key);
            }
        });

        const validGroups = groups.filter(g => g.items.length > 0);
        validGroups.sort((a, b) => a.name.localeCompare(b.name));
        return [...validGroups, unmatched].filter(g => g.items.length > 0);
    }, [secrets, selectedRole]);

    const handleGet = async (key) => {
        if (!checkUnsavedChanges()) return;
        const res = await fetch(`${API_BASE}/v1/secrets/${key}`, { ...fetchConfig, headers: getHeaders() });
        if (res.ok) {
            setReadSecret(await res.json());
            setIsAdding(false);
            setIsEditing(false);
            setIsImporting(false);
        } else if (res.status === 403) {
            alert('Permission Denied by Backend');
        }
    };

    const handlePut = async (e) => {
        e.preventDefault();
        const res = await fetch(`${API_BASE}/v1/secrets/${newKey}`, {
            ...fetchConfig,
            method: 'PUT',
            headers: getHeaders(),
            body: JSON.stringify({ value: newValue, env_key: newEnvKey })
        });
        if (res.ok) {
            if (isEditing && originalKey && originalKey !== newKey) {
                try {
                    await fetch(`${API_BASE}/v1/secrets/${originalKey}`, {
                        ...fetchConfig,
                        method: 'DELETE',
                        headers: getHeaders()
                    });
                } catch (err) {
                    console.error('Failed to delete old key on rename', err);
                }
            }
            setIsAdding(false);
            setIsEditing(false);
            setOriginalKey('');
            setNewKey('');
            setNewValue('');
            setOriginalValue('');
            setNewEnvKey('');
            setOriginalEnvKey('');
            fetchSecrets();
        } else if (res.status === 403) {
            alert('Permission Denied by Backend');
        } else {
            alert('Failed to save secret');
        }
    };

    const handleDelete = async (key) => {
        if (!confirm(`Permanently delete ${key}?`)) return;
        const res = await fetch(`${API_BASE}/v1/secrets/${key}`, { ...fetchConfig, method: 'DELETE', headers: getHeaders() });
        if (res.ok) fetchSecrets();
        else if (res.status === 403) alert('Permission Denied by Backend');
    };

    const handleQuickAddPolicy = async (key) => {
        if (!selectedRole) return;
        const newPolicies = [...selectedRole.policies];
        if (!newPolicies.some(p => p.prefix === key)) {
            newPolicies.push({ prefix: key, methods: ['GET'] });
        }
        try {
            const res = await fetch(`${API_BASE}/v1/roles/${selectedRole.name}`, {
                ...fetchConfig,
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: newPolicies })
            });
            if (res.ok) {
                if (refreshRoles) await refreshRoles();
            } else {
                alert('Failed to update role');
            }
        } catch (e) {
            alert('Error updating role');
        }
    };

    const handleQuickRemovePolicy = async (key) => {
        if (!selectedRole) return;
        const newPolicies = selectedRole.policies.filter(p => p.prefix !== key);
        try {
            const res = await fetch(`${API_BASE}/v1/roles/${selectedRole.name}`, {
                ...fetchConfig,
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: newPolicies })
            });
            if (res.ok) {
                if (refreshRoles) await refreshRoles();
            } else {
                alert('Failed to update role');
            }
        } catch (e) {
            alert('Error updating role');
        }
    };

    const handleEdit = (key) => {
        if (!checkUnsavedChanges()) return;
        setNewKey(key);
        setOriginalKey(key);
        setNewValue('Loading...'); // UI hint
        setOriginalValue('Loading...');
        setNewEnvKey('');
        setOriginalEnvKey('');
        setIsEditing(true);
        setIsAdding(false);
        fetch(`${API_BASE}/v1/secrets/${key}`, { ...fetchConfig, headers: getHeaders() })
            .then(res => {
                if (res.ok) return res.json();
                throw new Error('Forbidden');
            })
            .then(data => {
                setNewValue(data.raw_value || data.value);
                setOriginalValue(data.raw_value || data.value);
                setNewEnvKey(data.env_key || '');
                setOriginalEnvKey(data.env_key || '');
            })
            .catch(() => {
                alert('Permission Denied by Backend');
                setIsEditing(false);
            });
    };

    const startAdd = () => {
        if (!checkUnsavedChanges()) return;
        setNewKey('');
        setOriginalKey('');
        setNewValue('');
        setOriginalValue('');
        setNewEnvKey('');
        setOriginalEnvKey('');
        setIsAdding(true);
        setIsEditing(false);
        setIsImporting(false);
        setImportAnalysis(null);
        setResolvedPreview('');
    };

    const handleParseImport = async () => {
        if (!importText.trim()) return;
        setIsImportProcessing(true);
        const lines = importText.split('\n');
        const results = { new: [], overwrite: [], unchanged: [] };

        for (let line of lines) {
            line = line.trim();
            if (!line || line.startsWith('#')) continue;
            
            if (line.startsWith('export ')) {
                line = line.substring(7).trim();
            }

            const eqIdx = line.indexOf('=');
            if (eqIdx === -1) continue;

            const envKey = line.substring(0, eqIdx).trim();
            let value = line.substring(eqIdx + 1).trim();
            
            if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
                value = value.substring(1, value.length - 1);
            }

            const vaultPath = envKey.toLowerCase().replace(/_/g, '.');

            if (!secrets.includes(vaultPath)) {
                results.new.push({ vaultPath, envKey, value });
            } else {
                try {
                    const res = await fetch(`${API_BASE}/v1/secrets/${vaultPath}`, { ...fetchConfig, headers: getHeaders() });
                    if (res.ok) {
                        const data = await res.json();
                        if (data.value === value) {
                            results.unchanged.push({ vaultPath, envKey, value });
                        } else {
                            results.overwrite.push({ vaultPath, envKey, value, oldValue: data.value });
                        }
                    } else {
                        results.overwrite.push({ vaultPath, envKey, value, oldValue: '*** Unable to read current value ***' });
                    }
                } catch (e) {
                    results.overwrite.push({ vaultPath, envKey, value, oldValue: '*** Error reading current value ***' });
                }
            }
        }
        setImportAnalysis(results);
        setIsImportProcessing(false);
    };

    const handleConfirmImport = async () => {
        setIsImportProcessing(true);
        const toProcess = [...importAnalysis.new, ...importAnalysis.overwrite];
        let errors = 0;

        for (const item of toProcess) {
            try {
                const res = await fetch(`${API_BASE}/v1/secrets/${item.vaultPath}`, {
                    ...fetchConfig,
                    method: 'PUT',
                    headers: getHeaders(),
                    body: JSON.stringify({ value: item.value, env_key: item.envKey })
                });
                if (!res.ok) errors++;
            } catch (e) {
                errors++;
            }
        }

        setIsImportProcessing(false);
        if (errors > 0) {
            alert(`Import completed with ${errors} errors.`);
        }

        if (selectedRole && toProcess.length > 0) {
            const newPolicies = [...selectedRole.policies];
            let changed = false;
            for (const item of toProcess) {
                if (!newPolicies.some(p => p.prefix === item.vaultPath)) {
                    newPolicies.push({ prefix: item.vaultPath, methods: ['GET'] });
                    changed = true;
                }
            }
            if (changed) {
                try {
                    const rRes = await fetch(`${API_BASE}/v1/roles/${selectedRole.name}`, {
                        ...fetchConfig,
                        method: 'PUT',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ policies: newPolicies })
                    });
                    if (rRes.ok && refreshRoles) await refreshRoles();
                } catch (e) {
                    console.error('Failed to update role with imported variables');
                }
            }
        }

        setIsImporting(false);
        fetchSecrets();
    };

    const canPutAnything = useMemo(() => {
        if (!selectedRole) return true;
        if (selectedRole.can_create) return true;
        return selectedRole.policies.some(p => p.methods.includes('PUT') || p.methods.includes('*'));
    }, [selectedRole]);

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 font-sans">
            <div className="bg-gray-800 rounded-lg border border-gray-700 flex flex-col overflow-hidden shadow-xl">
                <div className="p-4 border-b border-gray-700 flex justify-between items-center bg-gray-900/50">
                    <h3 className="text-lg font-semibold">Secret Paths</h3>
                    <div className="flex gap-2">
                        {identity.is_admin && !isAdding && !isEditing && !isImporting && (
                            <React.Fragment>
                                <button 
                                    onClick={() => {
                                        if (!checkUnsavedChanges()) return;
                                        setIsImporting(true);
                                        setImportText('');
                                        setImportAnalysis(null);
                                        setReadSecret(null);
                                        setIsAdding(false);
                                        setIsEditing(false);
                                    }} 
                                    disabled={selectedRole && !canPutAnything}
                                    className="bg-blue-700 hover:bg-blue-600 disabled:bg-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed text-xs px-2 py-1 rounded transition shadow-sm"
                                >
                                    Import Env Vars
                                </button>
                                <button 
                                    onClick={startAdd} 
                                    disabled={selectedRole && !canPutAnything}
                                    className="bg-green-700 hover:bg-green-600 disabled:bg-gray-700 disabled:text-gray-500 disabled:cursor-not-allowed text-xs px-2 py-1 rounded transition shadow-sm"
                                >
                                    Add Secret
                                </button>
                            </React.Fragment>
                        )}
                        {identity.is_admin && roles.filter(t => t.name !== identity.name).length > 0 && (
                            <select 
                                className="bg-gray-900 border border-gray-600 rounded p-1 text-sm text-gray-200 focus:outline-none"
                                value={filterRoleName}
                                onChange={(e) => setFilterRoleName(e.target.value)}
                            >
                                <option value="">View As: admin</option>
                                {roles.filter(t => t.name !== identity.name).map(t => <option key={t.name} value={t.name}>View As: {t.name}</option>)}
                            </select>
                        )}
                    </div>
                </div>
                
                <div className="flex-1 overflow-y-auto max-h-[600px]">
                    {groupedSecrets.length === 0 ? <p className="p-4 text-gray-400 text-sm">No secrets found.</p> : null}
                    
                    {groupedSecrets.map(group => (
                        <div key={group.name} className="border-b border-gray-700 last:border-0">
                            <div className="bg-gray-900/50 p-2 px-4 border-b border-gray-700/50 flex justify-between items-center">
                                <span className="text-[10px] font-bold text-gray-500 font-mono uppercase tracking-wider">{group.name}</span>
                                <div className="flex gap-1">
                                    {['GET', 'LIST', 'PUT', 'DELETE'].map(m => {
                                        const isLit = group.methods.includes(m) || group.methods.includes('*');
                                        return (
                                            <span key={m} className={`text-[9px] px-1.5 py-0.5 rounded border font-mono ${isLit ? 'bg-blue-900/30 text-blue-300 border-blue-800/40' : 'bg-gray-800/30 text-gray-600 border-gray-700/40'}`}>
                                                {m}
                                            </span>
                                        );
                                    })}
                                </div>
                            </div>
                            <ul className="divide-y divide-gray-700/30">
                                {group.items.map(key => {
                                    const p = getPerms(key);
                                    return (
                                        <li key={key} className="p-3 px-4 hover:bg-gray-700/30 flex justify-between items-center group transition-colors">
                                            <div className="flex items-center gap-3">
                                                <span className="font-mono text-sm text-gray-200">{key}</span>
                                                <span title="Secret is listed in policy" className={`text-[9px] font-bold px-1 rounded border ${p.LIST ? 'text-green-500 border-green-900/50 bg-green-950/20' : 'text-gray-600 border-gray-700 bg-gray-800/50'}`}>L</span>
                                            </div>
                                            <div className="flex gap-4 transition">
                                                {identity.is_admin && selectedRole && (
                                                    <React.Fragment>
                                                        {!(p.GET || p.LIST || p.PUT || p.DELETE) ? (
                                                            <button 
                                                                onClick={() => handleQuickAddPolicy(key)}
                                                                title="Add to Role"
                                                                className="text-sm font-bold text-green-500 hover:text-green-400"
                                                            >
                                                                +
                                                            </button>
                                                        ) : selectedRole.policies.some(pol => pol.prefix === key) ? (
                                                            <button 
                                                                onClick={() => handleQuickRemovePolicy(key)}
                                                                title="Remove from Role"
                                                                className="text-sm font-bold text-red-500 hover:text-red-400"
                                                            >
                                                                -
                                                            </button>
                                                        ) : null}
                                                    </React.Fragment>
                                                )}
                                                <button 
                                                    onClick={() => handleGet(key)} 
                                                    disabled={!p.GET}
                                                    title="Read secret"
                                                    className={`text-sm font-semibold transition ${p.GET ? 'text-blue-400 hover:text-blue-300' : 'text-gray-600 cursor-not-allowed'}`}
                                                >
                                                    Read
                                                </button>
                                                {identity.is_admin && (
                                                    <React.Fragment>
                                                        <button 
                                                            onClick={() => handleEdit(key)} 
                                                            disabled={!p.PUT}
                                                            title="Edit secret"
                                                            className={`text-sm font-semibold transition ${p.PUT ? 'text-yellow-400 hover:text-yellow-300' : 'text-gray-600 cursor-not-allowed'}`}
                                                        >
                                                            Edit
                                                        </button>
                                                        <button 
                                                            onClick={() => handleDelete(key)} 
                                                            disabled={!p.DELETE}
                                                            title="Delete secret"
                                                            className={`text-sm font-semibold transition ${p.DELETE ? 'text-red-400 hover:text-red-300' : 'text-gray-600 cursor-not-allowed'}`}
                                                        >
                                                            Delete
                                                        </button>
                                                    </React.Fragment>
                                                )}
                                            </div>
                                        </li>
                                    );
                                })}
                            </ul>
                        </div>
                    ))}
                </div>
            </div>

            {(readSecret || isAdding || isEditing || isImporting) && (
                <div className="bg-gray-800 p-6 rounded-lg border border-blue-900 h-fit shadow-2xl">
                    {(isAdding || isEditing) ? (
                        <form onSubmit={handlePut}>
                            <div className="flex justify-between items-start mb-4">
                                <h3 className="text-lg font-semibold">{isEditing ? 'Edit Secret' : 'Add New Secret'}</h3>
                                <button type="button" onClick={() => { setIsAdding(false); setIsEditing(false); }} className="text-gray-500 hover:text-gray-300 text-xl">&times;</button>
                            </div>
                            <div className="space-y-4">
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Key Path (dots are allowed)</label>
                                    <input type="text" required value={newKey} onChange={handleKeyChange} className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white font-mono text-sm focus:border-blue-500 outline-none" placeholder="e.g. app.database.password" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Environment Variable Key (Optional)</label>
                                    <input type="text" value={newEnvKey} onChange={e => setNewEnvKey(e.target.value)} className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white font-mono text-sm focus:border-blue-500 outline-none" placeholder="e.g. DB_PASSWORD" />
                                </div>
                                <div>
                                    <label className="block text-xs text-gray-400 mb-1">Value</label>
                                    <textarea required value={newValue} onChange={e => setNewValue(e.target.value)} className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white font-mono h-48 text-sm focus:border-blue-500 outline-none" />
                                </div>
                                {resolvedPreview && resolvedPreview !== newValue && (
                                    <div>
                                        <label className="block text-xs text-gray-400 mb-1">Resolved Value</label>
                                        <pre className="w-full bg-gray-800 border border-gray-600 rounded p-2 text-blue-300 font-mono min-h-[2.5rem] whitespace-pre-wrap text-sm">{resolvedPreview}</pre>
                                    </div>
                                )}
                                <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white font-semibold p-2 rounded transition">Save Secret</button>
                            </div>
                        </form>
                    ) : isImporting ? (
                        <div className="space-y-4">
                            <div className="flex justify-between items-start mb-4">
                                <h3 className="text-lg font-semibold text-blue-400">Import Env Vars</h3>
                                <button onClick={() => setIsImporting(false)} className="text-gray-500 hover:text-gray-300 text-xl">&times;</button>
                            </div>
                            
                            {!importAnalysis ? (
                                <React.Fragment>
                                    <p className="text-sm text-gray-300">
                                        Paste your environment variables here. The <code>export</code> prefix is optional.
                                        Keys will be lowercased and underscores will become dots.
                                    </p>
                                    <textarea 
                                        value={importText} 
                                        onChange={e => setImportText(e.target.value)} 
                                        className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white font-mono h-48 text-sm focus:border-blue-500 outline-none whitespace-pre" 
                                        placeholder="export STRIPE_API_KEY=sk_test_123&#10;DATABASE_URL=postgres://..." 
                                    />
                                    <button 
                                        onClick={handleParseImport} 
                                        disabled={isImportProcessing}
                                        className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold p-2 rounded transition"
                                    >
                                        {isImportProcessing ? 'Analyzing...' : 'Parse & Review'}
                                    </button>
                                </React.Fragment>
                            ) : (
                                <div className="space-y-6">
                                    <div className="bg-gray-900 border border-gray-700 p-4 rounded text-sm">
                                        <p className="font-semibold mb-2 text-white">Import Summary:</p>
                                        <ul className="space-y-1">
                                            <li className="text-green-400 font-medium">{importAnalysis.new.length} New Secrets</li>
                                            <li className="text-yellow-400 font-medium">{importAnalysis.overwrite.length} Secrets to Overwrite</li>
                                            <li className="text-gray-500">{importAnalysis.unchanged.length} Unchanged (Ignored)</li>
                                        </ul>
                                    </div>

                                    {importAnalysis.overwrite.length > 0 && (
                                        <div className="space-y-2">
                                            <p className="text-sm font-semibold text-yellow-400">Will be overwritten:</p>
                                            <ul className="max-h-32 overflow-y-auto bg-gray-900 border border-gray-700 rounded p-2 text-xs font-mono space-y-1">
                                                {importAnalysis.overwrite.map(item => (
                                                    <li key={item.vaultPath} className="text-gray-300 flex justify-between items-center border-b border-gray-800 last:border-0 pb-1">
                                                        <span>{item.vaultPath}</span>
                                                        <span className="text-yellow-500 font-bold ml-2">Value differs</span>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    {importAnalysis.new.length > 0 && (
                                        <div className="space-y-2">
                                            <p className="text-sm font-semibold text-green-400">Will be added:</p>
                                            <ul className="max-h-32 overflow-y-auto bg-gray-900 border border-gray-700 rounded p-2 text-xs font-mono space-y-1">
                                                {importAnalysis.new.map(item => (
                                                    <li key={item.vaultPath} className="text-gray-300">
                                                        {item.vaultPath} <span className="text-gray-600">({item.envKey})</span>
                                                    </li>
                                                ))}
                                            </ul>
                                        </div>
                                    )}

                                    <div className="flex gap-4 pt-2">
                                        <button 
                                            onClick={() => setImportAnalysis(null)} 
                                            disabled={isImportProcessing}
                                            className="flex-1 bg-gray-700 hover:bg-gray-600 text-white font-semibold p-2 rounded transition"
                                        >
                                            Back
                                        </button>
                                        <button 
                                            onClick={handleConfirmImport} 
                                            disabled={isImportProcessing || (importAnalysis.new.length === 0 && importAnalysis.overwrite.length === 0)}
                                            className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white font-semibold p-2 rounded transition"
                                        >
                                            {isImportProcessing ? 'Importing...' : 'Confirm & Import'}
                                        </button>
                                    </div>
                                </div>
                            )}
                        </div>
                    ) : (
                        <React.Fragment>
                            <div className="flex justify-between items-start mb-4">
                                <h3 className="text-lg font-semibold text-blue-400">Decrypted Payload</h3>
                                <button onClick={() => setReadSecret(null)} className="text-gray-500 hover:text-gray-300 text-xl">&times;</button>
                            </div>
                            <div className="mb-2 text-sm text-gray-400 font-mono italic">
                                {readSecret.key}
                                {readSecret.env_key && <span className="ml-2 text-purple-400">({readSecret.env_key})</span>}
                            </div>
                            <pre className="bg-black p-4 rounded border border-gray-700 whitespace-pre-wrap font-mono text-green-400 text-sm shadow-inner">{(readSecret.raw_value && readSecret.raw_value !== readSecret.value) ? readSecret.raw_value : readSecret.value}</pre>
                            {(readSecret.raw_value && readSecret.raw_value !== readSecret.value) && (
                                <div className="mt-4">
                                    <h4 className="text-sm font-semibold text-gray-400 mb-2">Resolved Value</h4>
                                    <pre className="bg-gray-900 p-4 rounded border border-gray-700 whitespace-pre-wrap font-mono text-blue-300 text-sm shadow-inner">{readSecret.value}</pre>
                                </div>
                            )}
                        </React.Fragment>
                    )}
                </div>
            )}
        </div>
    );
}

function RoleManager({ roles, refreshRoles }) {
    const [name, setName] = useState('');
    const [policies, setPolicies] = useState([{ prefix: '', methods: ['GET'] }]);
    const [generatedToken, setGeneratedToken] = useState('');
    const [editingRoleName, setEditingRoleName] = useState(null);
    const [expiresAt, setExpiresAt] = useState('');
    const [neverExpire, setNeverExpire] = useState(true);
    const [canCreate, setCanCreate] = useState(false);

    const handleCreate = async (e) => {
        e.preventDefault();
        const activePolicies = policies.filter(p => p.prefix.trim() !== '');

        let expiryVal = null;
        if (!neverExpire && expiresAt) {
            expiryVal = new Date(expiresAt).toISOString();
        }

        if (editingRoleName) {
            const res = await fetch(`${API_BASE}/v1/roles/${editingRoleName}`, {
                ...fetchConfig,
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ policies: activePolicies, can_create: canCreate, expires_at: expiryVal })
            });
            if (res.ok) {
                setEditingRoleName(null);
                setName('');
                setPolicies([{ prefix: '', methods: ['GET'] }]);
                setExpiresAt('');
                setNeverExpire(true);
                setCanCreate(false);
                refreshRoles();
            } else {
                alert('Failed to update role');
            }
            return;
        }
        
        const res = await fetch(`${API_BASE}/v1/roles`, {
            ...fetchConfig,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, policies: activePolicies, can_create: canCreate, expires_at: expiryVal })
        });
        if (res.ok) {
            const data = await res.json();
            setGeneratedToken(data.token);
            setName('');
            setPolicies([{ prefix: '', methods: ['GET'] }]);
            setExpiresAt('');
            setNeverExpire(true);
            setCanCreate(false);
            refreshRoles();
        } else {
            const errorText = await res.text();
            alert(`Failed to create role: ${errorText}`);
        }
    };

    const addPolicy = () => setPolicies([...policies, { prefix: '', methods: ['GET'] }]);
    const removePolicy = (idx) => setPolicies(policies.filter((_, i) => i !== idx));
    const updatePolicy = (idx, field, value) => {
        const next = [...policies];
        next[idx][field] = value;
        setPolicies(next);
    };

    const toggleMethod = (idx, method) => {
        const current = policies[idx].methods;
        const next = current.includes(method) 
            ? current.filter(m => m !== method) 
            : [...current, method];
        updatePolicy(idx, 'methods', next);
    };

    const handleDelete = async (roleName) => {
        if (!confirm(`Revoke role ${roleName}?`)) return;
        await fetch(`${API_BASE}/v1/roles/${roleName}`, { ...fetchConfig, method: 'DELETE' });
        refreshRoles();
    };

    const handleRegenerate = async (roleName) => {
        if (!confirm(`Regenerate token for role ${roleName}? The old token will immediately become invalid.`)) return;
        const res = await fetch(`${API_BASE}/v1/roles/${roleName}/regenerate`, { ...fetchConfig, method: 'POST' });
        if (res.ok) {
            const data = await res.json();
            setGeneratedToken(data.token);
            setEditingRoleName(null);
            setName('');
            setPolicies([{ prefix: '', methods: ['GET'] }]);
            setExpiresAt('');
            setNeverExpire(true);
            setCanCreate(false);
            refreshRoles();
        } else {
            alert('Failed to regenerate role token');
        }
    };

    const handleEdit = (t) => {
        setEditingRoleName(t.name);
        setName(t.name);
        setCanCreate(t.can_create || false);
        setPolicies(t.policies.map(p => {
            let methods = [...p.methods];
            if (methods.includes('*')) {
                methods = [...new Set([...methods, 'GET', 'LIST', 'PUT', 'DELETE'])];
                methods = methods.filter(m => m !== '*');
            }
            return { ...p, methods };
        }));
        setGeneratedToken('');
        if (t.expires_at) {
            setNeverExpire(false);
            const d = new Date(t.expires_at);
            const tzOffset = d.getTimezoneOffset() * 60000;
            const localISOTime = new Date(d - tzOffset).toISOString().slice(0, 16);
            setExpiresAt(localISOTime);
        } else {
            setNeverExpire(true);
            setExpiresAt('');
        }
    };

    const handleClone = (t) => {
        setEditingRoleName(null);
        setName(`${t.name}-copy`);
        setCanCreate(t.can_create || false);
        setPolicies(t.policies.map(p => ({ ...p })));
        setGeneratedToken('');
        if (t.expires_at) {
            setNeverExpire(false);
            const d = new Date(t.expires_at);
            const tzOffset = d.getTimezoneOffset() * 60000;
            const localISOTime = new Date(d - tzOffset).toISOString().slice(0, 16);
            setExpiresAt(localISOTime);
        } else {
            setNeverExpire(true);
            setExpiresAt('');
        }
    };

    const cancelEdit = () => {
        setEditingRoleName(null);
        setName('');
        setPolicies([{ prefix: '', methods: ['GET'] }]);
        setExpiresAt('');
        setNeverExpire(true);
        setCanCreate(false);
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-8 font-sans">
            <div className="space-y-6">
                <div className="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden shadow-xl">
                    <h3 className="text-lg font-semibold p-4 border-b border-gray-700 bg-gray-900/50">Roles</h3>
                    <ul className="divide-y divide-gray-700 max-h-[600px] overflow-y-auto">
                        {roles.map(t => (
                            <li key={t.name} className="p-4 flex flex-col gap-2 hover:bg-gray-750 transition-colors">
                                <div className="flex justify-between items-start">
                                    <div className="flex flex-col">
                                        <div className="font-semibold text-blue-400">{t.name}</div>
                                        {t.expires_at && (
                                            <div className="text-[10px] text-gray-500 flex items-center gap-1 mt-0.5">
                                                <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                                                Expires: {new Date(t.expires_at).toLocaleString()}
                                            </div>
                                        )}
                                    </div>
                                    <div className="flex gap-3">
                                        <button onClick={() => handleEdit(t)} className="text-yellow-400 hover:text-yellow-200 text-sm transition-colors">Edit</button>
                                        <button onClick={() => handleClone(t)} className="text-green-400 hover:text-green-300 text-sm transition-colors">Clone</button>
                                        <button onClick={() => handleRegenerate(t.name)} className="text-orange-400 hover:text-orange-300 text-sm transition-colors">Regenerate</button>
                                        <button onClick={() => handleDelete(t.name)} className="text-red-400 hover:text-red-200 text-sm transition-colors">Revoke</button>
                                    </div>
                                </div>
                                {t.can_create && (
                                    <div className="text-xs text-green-400 font-semibold mb-1">
                                        ✓ Can Create Secrets
                                    </div>
                                )}
                                <div className="flex flex-wrap gap-2">
                                    {t.policies.map((p, i) => (
                                        <div key={i} className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-[10px] font-mono shadow-inner">
                                            <span className="text-gray-400">{p.prefix}</span>
                                            <span className="ml-2 text-green-500">[{p.methods.join(',')}]</span>
                                        </div>
                                    ))}
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
            
            <div className="space-y-6">
                <div className="bg-gray-800 p-6 rounded-lg border border-gray-700 shadow-xl">
                    <div className="flex justify-between items-center mb-4">
                        <h3 className="text-lg font-semibold text-blue-400">{editingRoleName ? `Edit Role: ${editingRoleName}` : 'Add New Role'}</h3>
                        {editingRoleName && <button onClick={cancelEdit} className="text-gray-400 hover:text-gray-200 text-sm">Cancel Edit</button>}
                    </div>
                    <form onSubmit={handleCreate} className="space-y-4">
                        <div>
                            <label className="block text-xs text-gray-400 mb-1">Role Name</label>
                            <input type="text" required value={name} onChange={e => setName(e.target.value)} disabled={!!editingRoleName} className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white text-sm disabled:opacity-50 focus:border-blue-500 outline-none" placeholder="e.g. ci-runner" />
                        </div>

                        <div className="pt-2 pb-1 border-b border-gray-700">
                            <label className="flex items-center gap-2 cursor-pointer mb-2">
                                <input 
                                    type="checkbox" 
                                    checked={canCreate} 
                                    onChange={(e) => setCanCreate(e.target.checked)}
                                    className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
                                />
                                <span className="text-sm font-semibold text-green-400">Can Create Secrets (Global)</span>
                            </label>
                            <p className="text-xs text-gray-500 mb-2">If enabled, this role can create new secrets with any prefix.</p>
                        </div>
                        
                        <div className="space-y-3">
                            <label className="block text-xs text-gray-400">Policies (Prefixes & Methods)</label>
                            {policies.map((p, idx) => (
                                <div key={idx} className="bg-gray-900/50 p-3 rounded border border-gray-700 space-y-3 shadow-inner">
                                    <div className="flex gap-2">
                                        <input 
                                            type="text" 
                                            placeholder="Prefix (e.g. app.dev.)" 
                                            value={p.prefix} 
                                            onChange={e => updatePolicy(idx, 'prefix', e.target.value)}
                                            className="flex-1 bg-gray-900 border border-gray-700 rounded p-2 text-white text-sm font-mono focus:border-blue-500 outline-none"
                                        />
                                        {policies.length > 1 && (
                                            <button type="button" onClick={() => removePolicy(idx)} className="text-red-400 hover:text-red-300 text-lg px-2">&times;</button>
                                        )}
                                    </div>
                                    <div className="flex flex-wrap gap-4">
                                        {['GET', 'LIST', 'PUT', 'DELETE'].map(m => (
                                            <label key={m} className="flex items-center gap-2 cursor-pointer select-none">
                                                <input 
                                                    type="checkbox" 
                                                    checked={p.methods.includes(m)} 
                                                    onChange={() => toggleMethod(idx, m)}
                                                    className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
                                                />
                                                <span className="text-xs font-mono text-gray-300">{m}</span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            ))}
                            <button type="button" onClick={addPolicy} className="text-blue-400 hover:text-blue-200 text-xs font-semibold transition-colors">+ Add Another Prefix</button>
                        </div>

                        <div className="pt-2">
                            <label className="block text-xs text-gray-400 mb-2">Token Expiration</label>
                            <label className="flex items-center gap-2 mb-2 cursor-pointer text-sm">
                                <input 
                                    type="checkbox" 
                                    checked={neverExpire} 
                                    onChange={(e) => setNeverExpire(e.target.checked)}
                                    className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
                                />
                                <span className="text-gray-300">Never expire</span>
                            </label>
                            {!neverExpire && (
                                <input 
                                    type="datetime-local" 
                                    value={expiresAt}
                                    onChange={(e) => setExpiresAt(e.target.value)}
                                    required={!neverExpire}
                                    className="w-full bg-gray-900 border border-gray-700 rounded p-2 text-white text-sm focus:border-blue-500 outline-none"
                                />
                            )}
                        </div>

                        <button type="submit" className="w-full bg-blue-600 hover:bg-blue-500 text-white px-4 py-3 rounded text-sm font-bold transition mt-4 shadow-lg">
                            {editingRoleName ? 'Save Policy Changes' : 'Generate Role Token'}
                        </button>
                    </form>
                </div>
                {generatedToken && (
                    <div className="bg-green-900/30 p-6 rounded-lg border border-green-800 shadow-2xl animate-pulse">
                        <h3 className="text-sm font-semibold text-green-400 mb-2">Role Token Provisioned</h3>
                        <p className="text-xs text-gray-400 mb-2">Copy this role token now. It cannot be recovered.</p>
                        <div className="bg-black p-3 rounded font-mono text-sm break-all border border-green-900/50 flex justify-between items-center shadow-inner gap-4">
                            <span className="select-all text-green-300">{generatedToken}</span>
                            <button 
                                onClick={(e) => {
                                    const copyText = () => {
                                        if (navigator.clipboard && window.isSecureContext) {
                                            return navigator.clipboard.writeText(generatedToken);
                                        } else {
                                            let textArea = document.createElement("textarea");
                                            textArea.value = generatedToken;
                                            textArea.style.position = "fixed";
                                            textArea.style.left = "-999999px";
                                            textArea.style.top = "-999999px";
                                            document.body.appendChild(textArea);
                                            textArea.focus();
                                            textArea.select();
                                            return new Promise((res, rej) => {
                                                document.execCommand('copy') ? res() : rej();
                                                textArea.remove();
                                            });
                                        }
                                    };
                                    copyText().then(() => {
                                        const btn = e.target;
                                        const originalText = btn.innerText;
                                        btn.innerText = 'Copied!';
                                        setTimeout(() => btn.innerText = originalText, 2000);
                                    }).catch(() => alert('Failed to copy. Please select and copy manually.'));
                                }} 
                                className="bg-green-800 hover:bg-green-700 text-white px-3 py-1 rounded text-xs transition whitespace-nowrap"
                            >
                                Copy
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

function SystemSettings() {
    const [settings, setSettings] = useState({
        backup_target: '',
        backup_interval_mins: '5',
        backup_retention_all_days: '1',
        backup_retention_daily_days: '30',
        auto_populate_env_name: 'true'
    });
    const [isSaving, setIsSaving] = useState(false);
    const [isBackingUp, setIsBackingUp] = useState(false);

    useEffect(() => {
        fetch(`${API_BASE}/v1/system/settings`, fetchConfig)
            .then(res => res.json())
            .then(data => {
                if (data) {
                    setSettings(prev => ({ ...prev, ...data }));
                }
            })
            .catch(err => console.error("Failed to load settings", err));
    }, []);

    const handleSave = async (e) => {
        e.preventDefault();
        setIsSaving(true);
        try {
            const res = await fetch(`${API_BASE}/v1/system/settings`, {
                ...fetchConfig,
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(settings)
            });
            if (!res.ok) throw new Error("Failed to save settings");
            alert("Settings saved successfully.");
        } catch (err) {
            alert(err.message);
        } finally {
            setIsSaving(false);
        }
    };

    const triggerBackup = async () => {
        setIsBackingUp(true);
        try {
            const res = await fetch(`${API_BASE}/v1/system/backup`, { ...fetchConfig, method: 'POST' });
            if (!res.ok) throw new Error(await res.text());
            alert("Backup completed successfully.");
        } catch (err) {
            alert("Backup failed: " + err.message);
        } finally {
            setIsBackingUp(false);
        }
    };

    return (
        <div className="max-w-3xl font-sans">
            <div className="bg-gray-800 p-8 rounded-lg shadow-xl border border-gray-700 mb-8">
                <div className="flex justify-between items-center mb-6 border-b border-gray-700 pb-4">
                    <div>
                        <h2 className="text-xl font-bold text-white">System Settings</h2>
                        <p className="text-sm text-gray-400 mt-1">Configure global server parameters</p>
                    </div>
                </div>

                <form onSubmit={handleSave} className="space-y-6">
                    <div className="bg-gray-900/50 p-6 rounded-lg border border-gray-700">
                        <h3 className="text-lg font-semibold text-gray-200 mb-4 border-b border-gray-700 pb-2">Backup Configuration</h3>
                        
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <div className="md:col-span-2">
                                <label className="block text-sm font-medium text-gray-400 mb-2">Backup Target (Path or SCP)</label>
                                <input 
                                    type="text" 
                                    value={settings.backup_target || ''} 
                                    onChange={e => setSettings({...settings, backup_target: e.target.value})}
                                    placeholder="/var/lib/backups/ or user@host:/backups/"
                                    className="w-full bg-gray-900 border border-gray-600 rounded p-3 text-white placeholder-gray-500 focus:border-blue-500 focus:outline-none" 
                                />
                                <p className="text-xs text-gray-500 mt-1">Leave empty to disable backups.</p>
                            </div>

                            <div>
                                <label className="block text-sm font-medium text-gray-400 mb-2">Check Interval (Minutes)</label>
                                <input 
                                    type="number" min="1"
                                    value={settings.backup_interval_mins || '5'} 
                                    onChange={e => setSettings({...settings, backup_interval_mins: e.target.value})}
                                    className="w-full bg-gray-900 border border-gray-600 rounded p-3 text-white focus:border-blue-500 focus:outline-none" 
                                />
                                <p className="text-xs text-gray-500 mt-1">How often the background daemon checks for changes.</p>
                            </div>

                            <div className="md:col-span-2 mt-2">
                                <h4 className="text-sm font-medium text-gray-300 mb-3">Retention Policy</h4>
                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                    <div className="bg-gray-800 p-4 rounded border border-gray-700 flex flex-col justify-center">
                                        <label className="text-xs text-gray-400 mb-1">Keep ALL backups for (Days):</label>
                                        <input 
                                            type="number" min="0"
                                            value={settings.backup_retention_all_days || '1'} 
                                            onChange={e => setSettings({...settings, backup_retention_all_days: e.target.value})}
                                            className="w-full bg-gray-900 border border-gray-600 rounded p-2 text-white focus:border-blue-500 focus:outline-none" 
                                        />
                                    </div>
                                    <div className="bg-gray-800 p-4 rounded border border-gray-700 flex flex-col justify-center">
                                        <label className="text-xs text-gray-400 mb-1">Keep 1 backup per day for next (Days):</label>
                                        <input 
                                            type="number" min="0"
                                            value={settings.backup_retention_daily_days || '30'} 
                                            onChange={e => setSettings({...settings, backup_retention_daily_days: e.target.value})}
                                            className="w-full bg-gray-900 border border-gray-600 rounded p-2 text-white focus:border-blue-500 focus:outline-none" 
                                        />
                                    </div>
                                </div>
                                <p className="text-xs text-gray-500 mt-2 italic">Backups older than the sum of these two values will be automatically deleted from local directories.</p>
                            </div>

                            <div className="md:col-span-2 mt-4">
                                <h4 className="text-sm font-medium text-gray-300 mb-3">GUI Preferences</h4>
                                <label className="flex items-center gap-2 cursor-pointer">
                                    <input 
                                        type="checkbox" 
                                        checked={settings.auto_populate_env_name === 'true'} 
                                        onChange={e => setSettings({...settings, auto_populate_env_name: e.target.checked ? 'true' : 'false'})}
                                        className="w-4 h-4 rounded border-gray-700 bg-gray-900 text-blue-600 focus:ring-blue-500"
                                    />
                                    <span className="text-sm text-gray-300">Auto-populate Environment Variable names when creating/editing secrets</span>
                                </label>
                            </div>
                        </div>
                    </div>

                    <div className="flex gap-4">
                        <button 
                            type="submit" 
                            disabled={isSaving}
                            className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-3 rounded font-medium shadow transition disabled:opacity-50"
                        >
                            {isSaving ? "Saving..." : "Save Settings"}
                        </button>

                        <button 
                            type="button"
                            onClick={triggerBackup}
                            disabled={isBackingUp || !settings.backup_target}
                            className="bg-gray-700 hover:bg-gray-600 text-white px-6 py-3 rounded font-medium shadow transition disabled:opacity-50"
                        >
                            {isBackingUp ? "Backing up..." : "Run Backup Now"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

