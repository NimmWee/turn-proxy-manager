import React, { useEffect, useId, useRef } from 'react';

const paths = {
  grid: <><rect x="3" y="3" width="7" height="7" rx="1.6"/><rect x="14" y="3" width="7" height="7" rx="1.6"/><rect x="3" y="14" width="7" height="7" rx="1.6"/><rect x="14" y="14" width="7" height="7" rx="1.6"/></>,
  users: <><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M22 21v-2a4 4 0 0 0-3-3.87M16 3.13a4 4 0 0 1 0 7.75"/><circle cx="9" cy="7" r="4"/></>,
  devices: <><rect x="6" y="2" width="12" height="20" rx="3"/><path d="M10 18h4M10 5h4"/></>,
  server: <><rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M15 6.5h3M15 17.5h3"/></>,
  shield: <><path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m8 12 3 3 5-6"/></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 7a7 7 0 0 1 11.6-2L20 8M4 16l2.3 3A7 7 0 0 0 18 17"/></>,
  plus: <path d="M12 5v14M5 12h14"/>, search: <><circle cx="10.5" cy="10.5" r="7"/><path d="m16 16 5 5"/></>,
  sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2m-3-7 1.5-1.5M4.5 19.5 6 18m12 0 1.5 1.5M4.5 4.5 6 6"/></>,
  moon: <path d="M21 13A9 9 0 0 1 11 3a9 9 0 1 0 10 10Z"/>,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4m7 14 5-5-5-5M21 12H9"/></>,
  arrow: <path d="m9 5 7 7-7 7"/>, check: <path d="m5 12 4 4L19 6"/>, close: <path d="m6 6 12 12M6 18 18 6"/>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  activity: <path d="M2 12h4l3-8 6 16 3-8h4"/>,
  memory: <><rect x="5" y="5" width="14" height="14" rx="3"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v3m6-3v3M9 19v3m6-3v3M2 9h3m-3 6h3m14-6h3m-3 6h3"/></>,
  download: <><path d="M12 3v12m-5-5 5 5 5-5M5 17v4h14v-4"/></>,
  upload: <><path d="M12 15V3m-5 5 5-5 5 5M5 17v4h14v-4"/></>,
  lock: <><rect x="4" y="10" width="16" height="12" rx="3"/><path d="M8 10V6a4 4 0 0 1 8 0v4M12 15v2"/></>,
  menu: <path d="M4 6h16M4 12h16M4 18h16"/>, info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7h.01"/></>,
  eye: <><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></>,
};

export function Icon({ name, size = 20, className = '' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}>{paths[name] || paths.grid}</svg>;
}

export function Badge({ tone = 'muted', children }) { return <span className={`badge badge-${tone}`}><span className="badge-dot"/>{children}</span>; }
export function Brand() { return <div className="brand"><div className="brand-mark"><Icon name="shield" size={25}/></div><div><strong>FreeTurn</strong><span>MANAGER</span></div></div>; }

export function ThemeButton({ dark, onClick }) {
  return <button className="icon-button" onClick={onClick} aria-label={dark ? 'Включить светлую тему' : 'Включить тёмную тему'} title={dark ? 'Светлая тема' : 'Тёмная тема'}><Icon name={dark ? 'sun' : 'moon'}/></button>;
}

export function Modal({ title, description, children, onClose, busy }) {
  const ref = useRef(null);
  const titleId = useId();
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="modal" aria-labelledby={titleId} onCancel={event => { event.preventDefault(); if (!busy) onClose(); }} onClick={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <section><header className="modal-header"><div><h2 id={titleId}>{title}</h2>{description && <p>{description}</p>}</div><button className="icon-button" aria-label="Закрыть" disabled={busy} onClick={onClose}><Icon name="close"/></button></header>{children}</section>
  </dialog>;
}

export function Empty({ icon = 'devices', title, children, action }) {
  return <div className="empty-state"><span className="empty-icon"><Icon name={icon} size={27}/></span><h3>{title}</h3><p>{children}</p>{action}</div>;
}

export function bytes(value) {
  if (!Number.isFinite(value)) return '—';
  const units = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ']; let index = 0, number = value;
  while (number >= 1024 && index < units.length - 1) { number /= 1024; index += 1; }
  return `${number.toLocaleString('ru-RU', { maximumFractionDigits: index > 1 ? 1 : 0 })} ${units[index]}`;
}
export function uptime(value) {
  if (!Number.isFinite(value)) return '—';
  const days = Math.floor(value / 86400), hours = Math.floor(value / 3600) % 24, minutes = Math.floor(value / 60) % 60;
  return days ? `${days} д ${hours} ч` : `${hours} ч ${minutes} мин`;
}
export const platformName = { ios: 'iPhone / iPad', android: 'Android', windows: 'Windows', other: 'Другое' };

export function DeviceBadge({ device }) {
  if (device.state === 'error') return <Badge tone="warning">Требует внимания</Badge>;
  if (['pending', 'revoking'].includes(device.state)) return <Badge tone="warning">Применяется</Badge>;
  return <Badge tone={device.enabled ? 'success' : 'muted'}>{device.enabled ? 'Доступ открыт' : 'Отключено'}</Badge>;
}

export function Chart({ samples, kind }) {
  const values = samples.map(sample => kind === 'cpu' ? sample.cpu_pct : sample.memory_used_bytes / sample.memory_total_bytes * 100).filter(Number.isFinite);
  if (values.length < 2) return <div className="chart-wait"><Icon name="activity" size={28}/><span>Собираем показатели</span><small>График появится после следующего обновления</small></div>;
  const points = values.map((value, index) => `${index / (values.length - 1) * 760 + 20},${160 - value * 1.35}`);
  return <div className="chart"><svg viewBox="0 0 800 185" role="img" aria-label={kind === 'cpu' ? 'График загрузки процессора' : 'График использования памяти'}>
    <defs><linearGradient id="chart-area" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="currentColor" stopOpacity="0.17"/><stop offset="100%" stopColor="currentColor" stopOpacity="0"/></linearGradient></defs>
    {[25, 92.5, 160].map(y => <line key={y} x1="20" y1={y} x2="780" y2={y} className="chart-grid"/>)}
    <path d={`M20,160 L${points.join(' L')} L780,160 Z`} fill="url(#chart-area)"/>
    <polyline points={points.join(' ')} fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round"/>
  </svg><div className="chart-labels"><span>Последние {values.length} измерений</span><span>Обновление каждые 15 секунд · шкала 0–100%</span></div></div>;
}
