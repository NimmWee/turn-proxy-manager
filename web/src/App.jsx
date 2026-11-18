import React, { useCallback, useEffect, useRef, useState } from 'react';
import { api, setCsrf } from './api';
import ExportForm from './ExportForm';
import RoutingPanel from './RoutingPanel';
import { Monitoring, Settings, Subscriptions, Transport } from './AdminSections';
import { Badge, Brand, Chart, DeviceBadge, Empty, Icon, Modal, ThemeButton, bytes, platformName, uptime } from './components';

const sections = {
  overview: { label: 'Обзор', icon: 'grid', description: 'Подключения и состояние сервера.' },
  users: { label: 'Пользователи', icon: 'users', description: 'Доступ к серверу для семьи и близких.' },
  devices: { label: 'Устройства', icon: 'devices', description: 'Отдельное подключение для каждого телефона и компьютера.' },
  subscriptions: { label: 'Подписки', icon: 'key', description: 'Выдача, замена и отзыв ссылок регистрации.' },
  transport: { label: 'VPN и транспорт', icon: 'server', description: 'Состояние интерфейса и служб на сервере.' },
  routing: { label: 'Маршрутизация', icon: 'shield', description: 'Доставка правил DNS и маршрутизации управляемым клиентам.' },
  monitoring: { label: 'Мониторинг', icon: 'activity', description: 'Нагрузка, доступное место и активность подключений.' },
  events: { label: 'Журнал', icon: 'clock', description: 'Изменения доступа и подключения устройств.' },
  settings: { label: 'Настройки', icon: 'settings', description: 'Доступ к панели и оформление.' },
};

const eventNames = { 'bootstrap.issue': 'Выдан стартовый профиль', 'bootstrap.claim': 'Стартовый профиль активирован', 'user.create': 'Добавлен пользователь', 'user.enable': 'Пользователь включён', 'user.disable': 'Пользователь отключён', 'device.create': 'Добавлено устройство', 'device.enroll': 'Устройство зарегистрировано', 'device.revoke': 'Запрошен отзыв доступа', 'device.applied': 'Доступ устройству открыт', 'device.revoked': 'Доступ устройству отозван', 'credential.issue': 'Выпущен ключ доступа', 'credential.revoke': 'Ключ доступа отозван', 'subscription.issue': 'Создана подписка', 'subscription.rotate': 'Ссылка подписки заменена', 'subscription.revoke': 'Ссылка подписки отозвана', 'legacy.import': 'Исходные подключения добавлены', 'legacy.adopt': 'Подключения приняты под управление' };

function Events({ data, search }) {
  const events = data.events.filter(event => `${eventNames[event.action] || 'Изменение доступа'} ${event.subject_name}`.toLowerCase().includes(search.toLowerCase()));
  if (!events.length) return <section className="surface"><Empty icon="clock" title={search ? 'События не найдены' : 'Здесь появятся изменения'}>{search ? 'Попробуйте другое имя или событие.' : 'Добавление пользователей и изменение доступа будут отображаться здесь.'}</Empty></section>;
  return <section className="surface"><ol className="event-list">{events.map(event => <li className="event-row" key={event.id}><span className="event-icon"><Icon name="clock" size={18}/></span><div className="event-copy"><strong>{eventNames[event.action] || 'Изменение доступа'}</strong><span>{event.subject_name}</span></div><time dateTime={event.ts}>{Number.isNaN(Date.parse(event.ts)) ? 'Время не указано' : new Date(event.ts).toLocaleString('ru-RU', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' })}</time></li>)}</ol></section>;
}

function LoginPage({ onLogin, dark, toggleTheme }) {
  const [username, setUsername] = useState('admin'), [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { const value = await api('/auth/login', { method: 'POST', body: { username, password } }); setCsrf(value.csrf); onLogin(value); }
    catch (error) { setError(error.message); }
    finally { setBusy(false); }
  }
  return <div className="login-page"><div className="login-top"><Brand/><ThemeButton dark={dark} onClick={toggleTheme}/></div><main className="login-card">
    <div className="login-shield"><Icon name="lock" size={30}/></div><div className="eyebrow">ВАШЕ ЛИЧНОЕ ПРОСТРАНСТВО</div><h1>Рады видеть вас</h1><p className="login-intro">Войдите, чтобы управлять подключениями<br/>семьи и состоянием сервера.</p>
    <form onSubmit={submit}><label className="field">Имя администратора<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required maxLength={128} autoFocus/></label>
      <label className="field">Пароль<div className="password-field"><input type={visible ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required maxLength={1024}/><button type="button" className="icon-button" aria-label={visible ? 'Скрыть пароль' : 'Показать пароль'} onClick={() => setVisible(!visible)}><Icon name="eye" size={18}/></button></div></label>
      {error && <div className="form-error" role="alert">{error}</div>}<button className="button primary login-submit" disabled={busy}>{busy ? <><Icon name="refresh" className="spinning"/> Входим…</> : <>Войти в панель <Icon name="arrow" size={17}/></>}</button>
    </form><div className="login-note"><Icon name="shield" size={15}/> Доступ только для администратора</div>
  </main><footer className="login-footer">FreeTurn Manager <span>Ваш сервер. Ваши подключения.</span></footer></div>;
}

function UserForm({ onDone, onClose }) {
  const [name, setName] = useState(''), [limit, setLimit] = useState('3'), [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { await api('/users', { method: 'POST', body: { name: name.trim(), device_limit: limit ? Number(limit) : null } }); await onDone('Пользователь добавлен'); }
    catch (error) { setError(error.message); setBusy(false); }
  }
  return <Modal title="Новый пользователь" description="Отдельный доступ для близкого человека." onClose={onClose} busy={busy}><form onSubmit={submit} className="modal-form">
    <label className="field">Имя<input value={name} onChange={event => setName(event.target.value)} placeholder="Например, Анна" autoFocus required maxLength={128}/></label>
    <label className="field">Количество устройств<input type="number" min="1" max="245" value={limit} onChange={event => setLimit(event.target.value)} placeholder="Без ограничения"/><small>Оставьте пустым, чтобы не ограничивать число устройств.</small></label>
    {error && <div className="form-error" role="alert">{error}</div>}<div className="modal-actions"><button type="button" className="button secondary" disabled={busy} onClick={onClose}>Отмена</button><button className="button primary" disabled={busy || !name.trim()}>{busy ? 'Добавляем…' : 'Добавить пользователя'}</button></div>
  </form></Modal>;
}

function DeviceForm({ users, onDone, onClose }) {
  const active = users.filter(user => user.enabled);
  const [user, setUser] = useState(active[0]?.id || ''), [name, setName] = useState(''), [platform, setPlatform] = useState('android');
  const [publicKey, setPublicKey] = useState(''), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const requestId = useRef(crypto.randomUUID());
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { const value = await api('/devices', { method: 'POST', body: { user_id: user, name: name.trim(), platform, public_key: publicKey.trim(), request_id: requestId.current } }); await onDone(value.apply?.errors ? 'Устройство добавлено, применение требует внимания' : 'Устройство добавлено'); }
    catch (error) { setError(error.message); setBusy(false); }
  }
  return <Modal title="Новое устройство" description="У каждого устройства будут свои ключи и адрес." onClose={onClose} busy={busy}><form onSubmit={submit} className="modal-form">
    {!active.length ? <div className="info-note">Сначала добавьте или включите пользователя.</div> : <>
    <label className="field">Пользователь<select value={user} onChange={event => setUser(event.target.value)} required>{active.map(user => <option value={user.id} key={user.id}>{user.name}</option>)}</select></label>
    <div className="form-grid"><label className="field">Название<input value={name} onChange={event => setName(event.target.value)} placeholder="Телефон Анны" maxLength={128} required/></label><label className="field">Платформа<select value={platform} onChange={event => setPlatform(event.target.value)}>{Object.entries(platformName).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></label></div>
    <label className="field">Публичный WireGuard-ключ<textarea value={publicKey} onChange={event => setPublicKey(event.target.value)} placeholder="Ключ устройства в формате Base64" maxLength={100} required spellCheck={false} rows={2}/><small>Создайте ключ на устройстве и вставьте публичную часть. Приватный ключ остаётся у вас.</small></label></>}
    {error && <div className="form-error" role="alert">{error}</div>}<div className="modal-actions"><button type="button" className="button secondary" onClick={onClose} disabled={busy}>Отмена</button><button className="button primary" disabled={busy || !user || !name.trim() || publicKey.trim().length !== 44}>{busy ? 'Добавляем…' : 'Добавить устройство'}</button></div>
  </form></Modal>;
}

function Confirm({ action, onClose, onDone }) {
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  async function confirm() {
    setBusy(true); setError('');
    try { const result = await api(`/${action.kind}/${action.item.id}/enabled`, { method: 'POST', body: { enabled: action.enabled } }); await onDone(result.apply?.errors ? 'Запрос принят, применение требует внимания' : 'Изменения сохранены'); }
    catch (error) { setError(error.message); setBusy(false); }
  }
  const label = action.kind === 'users' ? 'пользователя' : 'устройство';
  return <Modal title={`${action.enabled ? 'Включить' : 'Отключить'} ${label}?`} description={action.item.name} busy={busy} onClose={onClose}><div className="modal-form">
    <p className="confirm-copy">{action.enabled ? (action.kind === 'users' ? 'Пользователь снова сможет подключать устройства. Ранее отключённые устройства включаются отдельно.' : 'Доступ для этого устройства будет открыт.') : (action.kind === 'users' ? 'Все устройства пользователя потеряют доступ. Их можно будет включить снова.' : 'Устройство потеряет доступ. Подключение можно будет включить снова.')}</p>
    {error && <div className="form-error" role="alert">{error}</div>}<div className="modal-actions"><button className="button secondary" disabled={busy} onClick={onClose}>Отмена</button><button className={`button ${action.enabled ? 'primary' : 'danger'}`} disabled={busy} onClick={confirm}>{busy ? 'Сохраняем…' : action.enabled ? 'Включить доступ' : 'Отключить доступ'}</button></div>
  </div></Modal>;
}

function Overview({ data, samples, setSection, newUser }) {
  const [chart, setChart] = useState('cpu');
  const metrics = data.metrics, activeUsers = data.users.filter(user => user.enabled), activeDevices = data.devices.filter(device => device.enabled);
  const memoryPct = metrics.memory_total_bytes ? Math.round(metrics.memory_used_bytes / metrics.memory_total_bytes * 100) : null;
  return <>
    <div className="summary-grid">
      <article className="summary-card"><div className="summary-label"><span>Процессор</span><span className="metric-icon blue"><Icon name="activity" size={18}/></span></div><div className="summary-value">{Number.isFinite(metrics.cpu_pct) ? metrics.cpu_pct.toLocaleString('ru-RU') : '—'}<small>%</small></div><p>{metrics.cpu_sample_ready ? 'Текущая загрузка сервера' : 'Ожидаем следующее измерение'}</p><progress value={metrics.cpu_pct ?? 0} max="100" aria-label="Загрузка процессора"/></article>
      <article className="summary-card"><div className="summary-label"><span>Память</span><span className="metric-icon violet"><Icon name="memory" size={18}/></span></div><div className="summary-value">{memoryPct ?? '—'}<small>%</small></div><p>{bytes(metrics.memory_used_bytes)} из {bytes(metrics.memory_total_bytes)}</p><progress className="violet-progress" value={memoryPct ?? 0} max="100" aria-label="Использование памяти"/></article>
      <article className="summary-card"><div className="summary-label"><span>Пользователи</span><span className="metric-icon green"><Icon name="users" size={18}/></span></div><div className="summary-value">{activeUsers.length}</div><p>С открытым доступом</p><button className="text-link" onClick={() => setSection('users')}>Все пользователи <Icon name="arrow" size={14}/></button></article>
      <article className="summary-card"><div className="summary-label"><span>Устройства</span><span className="metric-icon amber"><Icon name="devices" size={18}/></span></div><div className="summary-value">{activeDevices.length}</div><p>Разрешено подключение</p><button className="text-link" onClick={() => setSection('devices')}>Недавно активны: {metrics.recent_handshakes_estimate ?? '—'} <Icon name="arrow" size={14}/></button></article>
    </div>
    <div className="overview-grid"><section className="surface chart-surface"><div className="surface-heading"><div><h2>Нагрузка сервера</h2><p>Настоящие показатели в реальном времени</p></div><div className="segmented"><button className={chart === 'cpu' ? 'active' : ''} onClick={() => setChart('cpu')}>CPU</button><button className={chart === 'memory' ? 'active' : ''} onClick={() => setChart('memory')}>RAM</button></div></div><Chart samples={samples} kind={chart}/></section>
      <section className="surface traffic-surface"><div className="surface-heading"><div><h2>Трафик VPN</h2><p>С момента запуска интерфейса</p></div><Icon name="activity"/></div><div className="traffic-line"><span className="traffic-icon down"><Icon name="download"/></span><div><span>Получено сервером</span><strong>{bytes(metrics.rx_bytes)}</strong></div></div><div className="traffic-line"><span className="traffic-icon up"><Icon name="upload"/></span><div><span>Отправлено сервером</span><strong>{bytes(metrics.tx_bytes)}</strong></div></div><div className="traffic-note"><Icon name="clock" size={15}/> Сервер работает {uptime(metrics.uptime_seconds)}</div></section></div>
    <div className="overview-grid lower-grid"><section className="surface"><div className="surface-heading"><div><h2>Ваши пользователи</h2><p>Доступ для семьи и близких</p></div><button className="text-link" onClick={() => setSection('users')}>Все пользователи <Icon name="arrow" size={14}/></button></div>{activeUsers.length ? <div className="family-list">{activeUsers.slice(0, 4).map(user => <div className="family-row" key={user.id}><span className="avatar">{user.name.trim().slice(0, 1).toUpperCase()}</span><div className="family-name"><strong>{user.name}</strong><span>{data.devices.filter(device => device.user_id === user.id && device.enabled).length} устройств с доступом</span></div><Badge tone="success">Включён</Badge></div>)}</div> : <Empty icon="users" title="Добавьте первого пользователя" action={<button className="button primary" onClick={newUser}><Icon name="plus" size={16}/>Добавить</button>}>У каждого близкого человека будет собственный доступ.</Empty>}</section>
      <section className="surface connection-surface"><div className="surface-heading"><div><h2>Подключение</h2><p>Состояние вашего сервера</p></div><span className="metric-icon blue"><Icon name="shield" size={18}/></span></div><dl className="connection-list"><div><dt>VPN</dt><dd><Badge tone={data.status.consistent ? 'success' : 'warning'}>{data.status.consistent ? 'Работает' : 'Нужна проверка'}</Badge></dd></div><div><dt>Адрес</dt><dd className="mono">{data.status.endpoint}</dd></div><div><dt>Устройств с доступом</dt><dd>{data.status.expected_peers}</dd></div><div><dt>Настроено подключений</dt><dd>{data.status.peers}</dd></div></dl><div className="connection-note"><Icon name="info" size={16}/><span>Активность оценивается по подключениям за последние 3 минуты.</span></div></section></div>
  </>;
}

function Users({ data, search, showDisabled, action, newUser }) {
  const users = data.users.filter(user => (showDisabled || user.enabled) && user.name.toLowerCase().includes(search.toLowerCase()));
  if (!users.length) return <section className="surface"><Empty icon="users" title={search ? 'Никого не нашли' : 'Пока нет пользователей'} action={!search && <button className="button primary" onClick={newUser}><Icon name="plus" size={16}/>Добавить пользователя</button>}>{search ? 'Попробуйте изменить запрос или показать отключённых.' : 'Добавьте близкого человека, чтобы открыть ему доступ.'}</Empty></section>;
  return <section className="surface table-surface"><div className="table-scroll"><table className="users-table"><thead><tr><th>Пользователь</th><th>Устройства</th><th>Лимит</th><th>Доступ</th><th className="align-right">Действие</th></tr></thead><tbody>{users.map(user => <tr key={user.id}><td><div className="person-cell"><span className="avatar">{user.name.trim().slice(0, 1).toUpperCase()}</span><strong>{user.name}</strong></div></td><td>{data.devices.filter(device => device.user_id === user.id && device.enabled).length}<span className="cell-secondary"> с доступом</span></td><td>{user.device_limit ?? 'Без ограничения'}</td><td><Badge tone={user.enabled ? 'success' : 'muted'}>{user.enabled ? 'Включён' : 'Отключён'}</Badge></td><td className="align-right"><div className="user-actions">{user.enabled && <><button className="button small secondary" onClick={() => action({ kind: 'subscription-export', item: user })}>Подписка</button><button className="button small secondary" onClick={() => action({ kind: 'bootstrap-export', item: user })}>Стартовый профиль</button></>}<button className={`button small ${user.enabled ? 'secondary' : 'primary-soft'}`} onClick={() => action({ kind: 'users', item: user, enabled: !user.enabled })}>{user.enabled ? 'Отключить' : 'Включить'}</button></div></td></tr>)}</tbody></table></div></section>;
}

function Devices({ data, search, showDisabled, action, newDevice }) {
  const users = Object.fromEntries(data.users.map(user => [user.id, user]));
  const devices = data.devices.filter(device => (showDisabled || device.enabled) && `${device.name} ${users[device.user_id]?.name || ''} ${device.ip}`.toLowerCase().includes(search.toLowerCase()));
  if (!devices.length) return <section className="surface"><Empty title={search ? 'Устройства не найдены' : 'Пока нет устройств'} action={!search && <button className="button primary" onClick={newDevice}><Icon name="plus" size={16}/>Добавить устройство</button>}>{search ? 'Попробуйте другое имя или адрес.' : 'Добавьте устройство для одного из пользователей.'}</Empty></section>;
  return <section className="surface table-surface"><div className="table-scroll"><table className="devices-table">
    <thead><tr><th>Устройство</th><th>Пользователь</th><th>Адрес</th><th>Состояние</th><th>Трафик VPN</th><th className="align-right">Действие</th></tr></thead>
    <tbody>{devices.map(device => {
      const name = device.origin === 'legacy' && ['iphone', 'android'].includes(device.name)
        ? (device.name === 'iphone' ? 'iPhone' : 'Android') : device.name;
      const handshake = device.last_handshake_at && Number.isFinite(Date.parse(device.last_handshake_at))
        ? new Date(device.last_handshake_at).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' }) : 'нет данных';
      const userEnabled = users[device.user_id]?.enabled;
      const retry = device.state === 'error' && device.enabled;
      return <tr key={device.id}>
        <td><div className="person-cell"><span className="device-tile"><Icon name="devices"/></span><div><strong>{name}</strong><span className="cell-subtitle">{platformName[device.platform]} · {device.vpn_type === 'awg' ? 'AmneziaWG' : 'WireGuard'}</span></div></div></td>
        <td>{users[device.user_id]?.name || '—'}</td>
        <td className="mono">{device.ip}</td>
        <td><DeviceBadge device={device}/><span className="cell-subtitle">Последний handshake · {handshake}</span><span className="cell-subtitle">Ревизия на сервере · {device.revision ?? '—'}</span></td>
        <td className="device-traffic"><span>Получено {bytes(device.rx_bytes)}</span><span>Отправлено {bytes(device.tx_bytes)}</span></td>
        <td className="align-right"><button className={`button small ${device.enabled ? 'secondary' : 'primary-soft'}`} disabled={!device.enabled && !userEnabled} title={!device.enabled && !userEnabled ? 'Сначала включите пользователя' : undefined} onClick={() => action({ kind: 'devices', item: device, enabled: retry || !device.enabled })}>{retry ? 'Повторить' : device.enabled ? 'Отключить' : 'Включить'}</button></td>
      </tr>;
    })}</tbody>
  </table></div></section>;
}

export default function App() {
  const [dark, setDark] = useState(() => localStorage.getItem('ftm-theme') ? localStorage.getItem('ftm-theme') === 'dark' : window.matchMedia('(prefers-color-scheme: dark)').matches);
  const [auth, setAuth] = useState(null), [starting, setStarting] = useState(true), [section, setSection] = useState('overview');
  const [data, setData] = useState(null), [samples, setSamples] = useState([]), [refreshing, setRefreshing] = useState(false), [dataError, setDataError] = useState('');
  const [sectionRevision, setSectionRevision] = useState(0);
  const [search, setSearch] = useState(''), [showDisabled, setShowDisabled] = useState(false), [modal, setModal] = useState(null), [toast, setToast] = useState(''), [menu, setMenu] = useState(false);
  const fetching = useRef(false), epoch = useRef(0);
  useEffect(() => { document.documentElement.classList.toggle('dark', dark); localStorage.setItem('ftm-theme', dark ? 'dark' : 'light'); }, [dark]);
  useEffect(() => { let alive = true; api('/auth/me').then(value => { if (alive) { setCsrf(value.csrf); setAuth(value); } }).catch(() => {}).finally(() => { if (alive) setStarting(false); }); return () => { alive = false; }; }, []);
  useEffect(() => { const end = () => { epoch.current += 1; setAuth(null); setData(null); setSamples([]); setModal(null); setCsrf(null); }; window.addEventListener('ftm-session-ended', end); return () => window.removeEventListener('ftm-session-ended', end); }, []);
  const load = useCallback(async () => {
    if (!auth || fetching.current) return; fetching.current = true; setRefreshing(true); const current = epoch.current;
    try { const [status, metrics, users, devices, events] = await Promise.all(['/status', '/metrics', '/users', '/devices', '/events'].map(path => api(path))); if (current !== epoch.current) return; setData({ status, metrics, users, devices, events, updated: new Date() }); setDataError(''); setSamples(previous => previous.at(-1)?.sampled_at === metrics.sampled_at ? previous : [...previous, metrics].slice(-40)); }
    catch (error) { if (current === epoch.current) setDataError(error.message); }
    finally { fetching.current = false; setRefreshing(false); }
  }, [auth]);
  useEffect(() => { if (!auth) return; load(); const timer = setInterval(load, 15000); return () => clearInterval(timer); }, [auth, load]);
  useEffect(() => { if (!toast) return; const timer = setTimeout(() => setToast(''), 5000); return () => clearTimeout(timer); }, [toast]);
  function navigate(value) { setSection(value); setSearch(''); setShowDisabled(false); setMenu(false); }
  function refresh() { setSectionRevision(current => current + 1); return load(); }
  async function done(message) { setModal(null); setToast(message); await refresh(); }
  async function logout() { try { await api('/auth/logout', { method: 'POST' }); epoch.current += 1; setAuth(null); setData(null); setSamples([]); setCsrf(null); } catch (error) { setToast(error.message); } }
  if (starting) return <div className="startup"><Brand/><Icon name="refresh" className="spinning"/></div>;
  if (!auth) return <LoginPage onLogin={value => { epoch.current += 1; setAuth(value); }} dark={dark} toggleTheme={() => setDark(!dark)}/>;
  const title = section === 'overview' ? 'Обзор сервера' : section === 'events' ? 'Журнал событий' : sections[section].label;
  const needsLiveData = ['overview', 'users', 'devices', 'events', 'transport'].includes(section);
  return <div className="app-layout">{menu && <button className="mobile-backdrop" aria-label="Закрыть меню" onClick={() => setMenu(false)}/>}
    <aside className={`sidebar ${menu ? 'mobile-open' : ''}`}><Brand/><div className="sidebar-label">ВАШЕ ПРОСТРАНСТВО</div><nav aria-label="Главная навигация">{Object.entries(sections).map(([key, value]) => <button key={key} className={`nav-item ${section === key ? 'active' : ''}`} onClick={() => navigate(key)} aria-current={section === key ? 'page' : undefined}><Icon name={value.icon}/><span>{value.label}</span>{key === 'devices' && data && <small>{data.devices.filter(device => device.enabled).length}</small>}</button>)}</nav><div className="sidebar-bottom"><div className="private-note"><Icon name="shield" size={19}/><div><strong>Личный сервер</strong><span>Доступ под вашим контролем</span></div></div><div className="account-row"><span className="avatar admin-avatar">А</span><div><strong>{auth.username}</strong><span>Администратор</span></div><button className="icon-button" aria-label="Выйти из панели" title="Выйти" onClick={logout}><Icon name="logout" size={18}/></button></div></div></aside>
    <div className="workspace"><header className="topbar"><div className="topbar-left"><button className="icon-button mobile-menu" aria-label="Открыть меню" onClick={() => setMenu(true)}><Icon name="menu"/></button><span className="breadcrumb">Управление <Icon name="arrow" size={13}/><strong>{sections[section].label}</strong></span></div><div className="topbar-actions">{data && <Badge tone={data.status.consistent ? 'success' : 'warning'}>{data.status.consistent ? 'VPN работает' : 'Нужна проверка'}</Badge>}<ThemeButton dark={dark} onClick={() => setDark(!dark)}/></div></header>
      <main className="main-content"><div className="page-heading"><div><h1>{title}</h1><p>{sections[section].description}</p></div><div className="page-actions">{['users', 'devices'].includes(section) ? <button className="button primary" onClick={() => setModal({ kind: section === 'users' ? 'new-user' : 'new-device' })} disabled={!data}><Icon name="plus" size={17}/>{section === 'users' ? 'Добавить пользователя' : 'Добавить устройство'}</button> : section !== 'routing' && <button className="button secondary" onClick={refresh} disabled={refreshing}><Icon name="refresh" size={17} className={refreshing ? 'spinning' : ''}/><span>Обновить</span></button>}</div></div>
        {dataError && <div className="error-banner" role="alert"><Icon name="info"/><div><strong>Не удалось обновить данные</strong><span>{dataError}{data ? '. Показаны последние полученные значения.' : ''}</span></div><button className="button small secondary" onClick={load}>Повторить</button></div>}
        {!data && needsLiveData ? <div className="surface loading-state"><Icon name="refresh" className="spinning" size={27}/><strong>{dataError ? 'Ожидаем подключения к серверу' : 'Загружаем данные сервера'}</strong><span>Это займёт несколько секунд</span></div> : <>
          {['users', 'devices', 'events'].includes(section) && <div className="table-toolbar"><label className="search-field"><Icon name="search" size={18}/><input type="search" value={search} onChange={event => setSearch(event.target.value)} placeholder={section === 'users' ? 'Найти пользователя' : section === 'events' ? 'Найти событие или имя' : 'Найти устройство или адрес'} aria-label="Поиск"/></label>{section !== 'events' && <label className="checkbox-label"><input type="checkbox" checked={showDisabled} onChange={event => setShowDisabled(event.target.checked)}/>Показать отключённых</label>}<span className="result-count">{section === 'events' ? `Последние ${data.events.length} событий` : `${section === 'users' ? data.users.filter(user => user.enabled).length : data.devices.filter(device => device.enabled).length} с доступом`}</span></div>}
          {section === 'overview' && <Overview data={data} samples={samples} setSection={navigate} newUser={() => setModal({ kind: 'new-user' })}/>}
          {section === 'users' && <Users data={data} search={search} showDisabled={showDisabled} action={setModal} newUser={() => setModal({ kind: 'new-user' })}/>}
          {section === 'devices' && <Devices data={data} search={search} showDisabled={showDisabled} action={setModal} newDevice={() => setModal({ kind: 'new-device' })}/>}
          {section === 'events' && <Events data={data} search={search}/>}
          {section === 'routing' && <RoutingPanel/>}
          {section === 'subscriptions' && <Subscriptions revision={sectionRevision} action={setModal}/>}
          {section === 'monitoring' && <Monitoring revision={sectionRevision} metrics={data?.metrics ?? {}}/>}
          {section === 'transport' && <Transport status={data.status}/>}
          {section === 'settings' && <Settings revision={sectionRevision} openRouting={() => navigate('routing')} toggleTheme={() => setDark(!dark)} dark={dark}/>}
          {data && <div className="content-footer"><span><span className="live-dot"/> Данные с вашего сервера</span><span>Обновлено в {data.updated.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}</span></div>}
        </>}
      </main><footer className="workspace-footer"><span>FreeTurn Manager</span><span>Простое управление личной сетью</span></footer></div>
    {toast && <div className="toast" role="status"><span className="toast-icon"><Icon name="check" size={17}/></span>{toast}<button className="icon-button" aria-label="Закрыть уведомление" onClick={() => setToast('')}><Icon name="close" size={15}/></button></div>}
    {modal && ['subscription-export', 'subscription-revoke', 'bootstrap-export'].includes(modal.kind) && <ExportForm kind={modal.kind} user={modal.item} onClose={() => setModal(null)} onDone={done}/>}
    {modal?.kind === 'new-user' && <UserForm onClose={() => setModal(null)} onDone={done}/>}
    {modal?.kind === 'new-device' && data && <DeviceForm users={data.users} onClose={() => setModal(null)} onDone={done}/>}
    {modal && ['users', 'devices'].includes(modal.kind) && <Confirm action={modal} onClose={() => setModal(null)} onDone={done}/>}
  </div>;
}
