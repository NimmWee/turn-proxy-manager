import React, { useRef, useState } from 'react';
import { api } from './api';
import { Modal } from './components';

export default function ExportForm({ kind, user, onClose, onDone }) {
  const bootstrap = kind === 'bootstrap-export';
  const [password, setPassword] = useState(''), [name, setName] = useState(''), [platform, setPlatform] = useState('android');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const requestId = useRef(crypto.randomUUID());
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const body = { password, request_id: requestId.current, ...(bootstrap ? { name: name.trim(), platform } : {}) };
      const value = await api(`/users/${user.id}/${kind}`, { method: 'POST', body });
      const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url; link.download = `freeturn-${bootstrap ? 'bootstrap' : 'subscription'}-${requestId.current}.json`;
      document.body.appendChild(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      await onDone('Файл скачан. Передайте его лично пользователю.');
    } catch (error) { setError(error.message); }
    finally { setPassword(''); setBusy(false); }
  }
  function changed(setter, value) { setter(value); requestId.current = crypto.randomUUID(); }
  return <Modal title={bootstrap ? 'Стартовый профиль' : 'Подписка пользователя'} description={`Личный доступ для ${user.name}.`} onClose={onClose} busy={busy}>
    <form onSubmit={submit} className="modal-form">
      <div className="info-note">Эти файлы предназначены для управляемого клиента. Опубликованные версии Android и Windows пока не поддерживают их импорт.</div>
      {bootstrap ? <><div className="info-note">Сначала выпустите подписку для пользователя. Профиль создаст отдельное устройство; дождитесь его включения в списке устройств. Код активации действует 1 час.</div>
        <label className="field">Название устройства<input value={name} onChange={event => changed(setName, event.target.value)} required maxLength={128} placeholder="Например, телефон Анны"/></label>
        <label className="field">Устройство<select value={platform} onChange={event => changed(setPlatform, event.target.value)}><option value="android">Android</option><option value="windows">Windows</option><option value="other">Другое</option></select></label></>
        : <div className="info-note">Новая выдача заменяет предыдущий ключ регистрации. Уже подключённые устройства продолжат работать.</div>}
      <label className="field">Подтвердите пароль администратора<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required maxLength={1024}/></label>
      <small>Файл содержит секреты подключения. Не публикуйте его и сохраните вне папки проекта. При сетевой ошибке повторите запрос в этой форме в течение 10 минут.</small>
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="modal-actions"><button type="button" className="button secondary" disabled={busy} onClick={onClose}>Отмена</button><button className="button primary" disabled={busy || !password || (bootstrap && !name.trim())}>{busy ? 'Готовим файл…' : 'Скачать файл'}</button></div>
    </form>
  </Modal>;
}
