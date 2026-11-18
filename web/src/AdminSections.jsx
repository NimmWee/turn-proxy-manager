import React, { useEffect, useState } from 'react';
import { api } from './api';
import { Badge, Empty, Icon, bytes, uptime } from './components';

function useSectionData(path, revision, { pollMs = 0, delay = 0 } = {}) {
  const [state, setState] = useState(null);
  useEffect(() => {
    let timer;
    const controller = new AbortController();
    async function fetchData() {
      try {
        const value = await api(path, { signal: controller.signal });
        if (!controller.signal.aborted) setState({ path, revision, value, error: '' });
      } catch (error) {
        if (!controller.signal.aborted) setState(previous => ({ path, revision, error: error.message,
          value: previous?.path === path ? previous.value : null }));
      } finally {
        if (pollMs && !controller.signal.aborted) timer = setTimeout(fetchData, pollMs);
      }
    }
    timer = setTimeout(fetchData, delay);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [path, revision, pollMs, delay]);
  const current = state?.path === path ? state : null;
  return { value: current?.value, error: current?.error, loading: current?.revision !== revision };
}

function SectionStatus({ resource }) {
  if (resource.error) return <div className="error-banner" role="alert"><Icon name="info"/><span>{resource.error}</span></div>;
  if (resource.loading) return <div className="section-loading" role="status">Загружаем данные…</div>;
  return null;
}

const ranges = [[1, 'Час'], [6, '6 часов'], [24, 'Сутки'], [168, 'Неделя']];
const timeLabel = stamp => new Date(stamp * 1000).toLocaleString('ru-RU', {
  day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
});

function HistoryChart({ label, samples, field, step, percent = false }) {
  const values = samples.filter(sample => Number.isFinite(sample[field]));
  if (!values.length) return <div className="history-chart"><h3>{label}</h3><p>За этот период пока нет измерений.</p></div>;
  const start = samples[0].timestamp;
  const end = samples.at(-1).timestamp;
  const width = Math.max(end - start, step * 60);
  const maximum = percent ? 100 : Math.max(1, ...values.map(sample => sample[field]));
  let previous = null;
  const path = values.map(sample => {
    const x = 20 + 760 * (sample.timestamp - start) / width;
    const y = 135 - 110 * sample[field] / maximum;
    // Leave a gap when a sampling bucket is absent or has no value for this metric.
    const bucket = Math.floor(sample.timestamp / (step * 60));
    const line = previous !== null && bucket === previous + 1;
    previous = bucket;
    return `${line ? 'L' : 'M'}${x},${y}${line ? '' : ' h0.01'}`;
  }).join(' ');
  const suffix = percent ? '%' : '';
  return <div className="history-chart">
    <h3>{label}<span>{values.at(-1)[field].toLocaleString('ru-RU')}{suffix}</span></h3>
    <svg className="history-plot" viewBox="0 0 800 150" role="img" aria-label={label}>
      {[25, 80, 135].map(y => <line key={y} x1="20" x2="780" y1={y} y2={y} className="chart-grid"/>)}
      <path d={path} fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" vectorEffect="non-scaling-stroke"/>
    </svg>
    <div className="chart-labels"><span>{timeLabel(start)}</span><span>Шкала 0–{maximum}{suffix}</span>{end !== start && <span>{timeLabel(end)}</span>}</div>
  </div>;
}

export function Monitoring({ metrics, revision }) {
  const [hours, setHours] = useState(24);
  const resource = useSectionData(`/metrics/history?hours=${hours}`, revision, { pollMs: 60000 });
  const history = resource.value;
  return <div className="admin-stack">
    <section className="surface">
      <div className="surface-heading"><div><h2>Текущие показатели</h2><p>Счётчики трафика за время работы интерфейса WireGuard</p></div><Icon name="activity"/></div>
      <dl className="connection-list section-details monitoring-details">
        <div><dt>Свободно на диске</dt><dd>{bytes(metrics.disk_free_bytes)} из {bytes(metrics.disk_total_bytes)}</dd></div>
        <div><dt>Получено через VPN</dt><dd>{bytes(metrics.rx_bytes)}</dd></div>
        <div><dt>Отправлено через VPN</dt><dd>{bytes(metrics.tx_bytes)}</dd></div>
        <div><dt>Недавние подключения</dt><dd>{metrics.recent_handshakes_estimate ?? 'Нет данных'}</dd></div>
        <div><dt>Время работы VPS</dt><dd>{uptime(metrics.uptime_seconds)}</dd></div>
      </dl>
    </section>
    <section className="surface">
      <div className="surface-heading history-heading"><div><h2>История нагрузки</h2><p>Сервер сохраняет измерения каждую минуту</p></div>
        <div className="segmented" aria-label="Период мониторинга">{ranges.map(([value, label]) => <button key={value} type="button" className={hours === value ? 'active' : ''} aria-pressed={hours === value} onClick={() => setHours(value)}>{label}</button>)}</div>
      </div>
      <SectionStatus resource={resource}/>
      {history?.sampling_failed && <p className="connection-note" role="status">Последнее измерение не сохранилось. Доступные записи показаны ниже.</p>}
      {history?.samples.length > 0 ? <>
        <HistoryChart label="Загрузка процессора" samples={history.samples} field="cpu_pct" step={history.step_minutes} percent/>
        <HistoryChart label="Использование памяти" samples={history.samples} field="memory_pct" step={history.step_minutes} percent/>
        <HistoryChart label="Недавние подключения" samples={history.samples} field="recent_handshakes_estimate" step={history.step_minutes}/>
      </> : history && <Empty icon="activity" title="История пока пуста">Данные появятся после первого измерения.</Empty>}
    </section>
  </div>;
}

export function Subscriptions({ revision, action }) {
  const [filter, setFilter] = useState({ search: '', page: 1 });
  const resource = useSectionData(`/subscriptions?${new URLSearchParams(filter)}`, revision, { delay: 220 });
  const settings = useSectionData('/settings', revision);
  const canManage = settings.value?.credential_export_enabled === true;
  return <>
    <div className="table-toolbar"><label className="search-field"><Icon name="search" size={18}/><input type="search" maxLength={128} value={filter.search} onChange={event => setFilter({ search: event.target.value, page: 1 })} placeholder="Найти пользователя" aria-label="Найти пользователя"/></label></div>
    <SectionStatus resource={resource}/>
    <SectionStatus resource={settings}/>
    {settings.value && !canManage && <p className="info-note section-note">Выдача и отзыв подписок доступны через защищённую HTTPS-панель.</p>}
    {resource.value?.items.length ? <section className="surface table-surface"><div className="table-scroll"><table className="subscriptions-table"><thead><tr><th>Пользователь</th><th>Версия</th><th>Состояние</th><th className="align-right">Действие</th></tr></thead>
      <tbody>{resource.value.items.map(item => {
        const user = { id: item.user_id, name: item.name, version: item.version };
        const active = item.version !== null && !item.revoked_at;
        const state = !item.version ? 'Не выдана' : item.revoked_at ? 'Отозвана' : item.enabled ? 'Активна' : 'Пользователь отключён';
        return <tr key={item.user_id}><td><strong>{item.name}</strong></td><td>{item.version ?? '—'}</td>
          <td><Badge tone={active && item.enabled ? 'success' : 'muted'}>{state}</Badge></td><td className="align-right"><div className="user-actions">
            {canManage && item.enabled && <button className="button small secondary" onClick={() => action({ kind: 'subscription-export', item: user })}>{active ? 'Заменить ссылку' : 'Выдать'}</button>}
            {canManage && active && <button className="button small secondary" onClick={() => action({ kind: 'subscription-revoke', item: user })}>Отозвать ссылку</button>}
          </div></td></tr>;
      })}</tbody></table></div></section> : resource.value && <section className="surface"><Empty icon="lock" title={filter.search ? 'Пользователи не найдены' : 'Пока нет подписок'}>Ссылки выдаются пользователям с открытым доступом.</Empty></section>}
    {(filter.page > 1 || resource.value?.has_next) && <div className="section-pagination"><button className="button secondary small" disabled={filter.page === 1 || resource.loading} onClick={() => setFilter({ ...filter, page: filter.page - 1 })}>Назад</button><span>Страница {filter.page}</span><button className="button secondary small" disabled={!resource.value?.has_next || resource.loading} onClick={() => setFilter({ ...filter, page: filter.page + 1 })}>Дальше</button></div>}
  </>;
}

export function Transport({ status }) {
  const serviceStates = { active: 'Работает', activating: 'Запускается', deactivating: 'Останавливается', failed: 'Ошибка', inactive: 'Остановлена', inactive_or_unavailable: 'Не отвечает' };
  return <div className="admin-stack">
    <section className="surface"><div className="surface-heading"><h2>VPN и WireGuard</h2><Badge tone={status.consistent ? 'success' : 'warning'}>{status.consistent ? 'Состояние согласовано' : 'Нужна проверка'}</Badge></div>
      <dl className="connection-list section-details">
        <div><dt>Адрес FreeTurn</dt><dd className="mono">{status.endpoint}</dd></div>
        <div><dt>Интерфейс</dt><dd>{status.interface ?? '—'}</dd></div>
        <div><dt>Версия сервера</dt><dd>{status.version ?? '—'}</dd></div>
        <div><dt>Подключений в интерфейсе</dt><dd>{status.peers ?? '—'} из {status.expected_peers ?? '—'}</dd></div>
        <div><dt>Ожидают применения</dt><dd>{status.pending_root_operations ?? '—'}</dd></div>
        <div><dt>Отсутствуют / лишние / отключённые в интерфейсе</dt><dd>{status.missing_peers ?? '—'} / {status.unknown_peers ?? '—'} / {status.disabled_peers_present ?? '—'}</dd></div>
      </dl>
    </section>
    <section className="surface"><div className="surface-heading"><h2>Службы</h2><Icon name="server"/></div>
      {status.services && Object.keys(status.services).length ? <dl className="connection-list section-details">{Object.entries(status.services).map(([name, value]) => <div key={name}><dt>{name}</dt><dd><Badge tone={value === 'active' ? 'success' : 'warning'}>{serviceStates[value] ?? 'Нет данных'}</Badge></dd></div>)}</dl> : <Empty icon="server" title="Нет данных о службах"/>}
    </section>
  </div>;
}

export function Settings({ revision, openRouting, toggleTheme, dark }) {
  const resource = useSectionData('/settings', revision);
  const settings = resource.value;
  return <div className="admin-stack">
    <section className="surface"><div className="surface-heading"><h2>Доступ к панели</h2><Icon name="lock"/></div>
      <SectionStatus resource={resource}/>
      {settings && <dl className="connection-list section-details">
        <div><dt>Адрес HTTPS</dt><dd>{settings.public_origin || 'Доступ через SSH'}</dd></div>
        <div><dt>Защищённая cookie сессии</dt><dd>{settings.secure_cookie ? 'Включена' : 'Локальный режим'}</dd></div>
        <div><dt>Управление ссылками подписки</dt><dd>{settings.credential_export_enabled ? 'Доступно' : 'Требуется HTTPS'}</dd></div>
        <div><dt>Хранение истории мониторинга</dt><dd>{settings.history_days} дней</dd></div>
      </dl>}
    </section>
    <section className="surface"><div className="surface-heading"><div><h2>Оформление</h2><p>Тема сохраняется в этом браузере</p></div><button className="button secondary small" onClick={toggleTheme}>{dark ? 'Светлая тема' : 'Тёмная тема'}</button></div></section>
    <section className="surface"><div className="surface-heading"><div><h2>Маршрутизация</h2><p>Правила для управляемых клиентов</p></div><button className="button secondary small" onClick={openRouting}>Открыть правила</button></div></section>
  </div>;
}
