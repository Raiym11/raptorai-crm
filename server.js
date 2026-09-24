const express = require('express');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'https://crm.raptorai.ru');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Webhook-Secret');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const PEPPER = process.env.PASSWORD_PEPPER;
const ADMIN_CODE = process.env.ADMIN_CODE;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const TELEGRAM_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

const pool = new Pool({
  host: 'postgres',
  port: 5432,
  user: 'raptorai',
  password: process.env.PGPASSWORD,
  database: 'raptorai_crm'
});

function hashPassword(password) {
  return crypto.createHash('sha256').update(password + PEPPER).digest('hex');
}

// Проверка секрета на каждом запросе
app.use((req, res, next) => {
  if (req.headers['x-webhook-secret'] !== WEBHOOK_SECRET) {
    return res.status(403).json({ ok: false, error: 'Доступ запрещён.' });
  }
  next();
});

// 1. Создать сотрудника
app.post('/crm-create-employee', async (req, res) => {
  const { adminCode, username, password, name } = req.body;
  if (adminCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код администратора.' });
  if (!username || !password || !name) return res.status(400).json({ ok: false, error: 'Не хватает данных.' });
  try {
    await pool.query(
      'INSERT INTO employees (username, password_hash, name) VALUES ($1, $2, $3)',
      [username.trim().toLowerCase(), hashPassword(password), name.trim()]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.code === '23505' ? 'Такой логин уже занят.' : 'Ошибка создания сотрудника.' });
  }
});

// 2. Вход сотрудника
app.post('/crm-login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query(
    'SELECT name, password_hash, active FROM employees WHERE username = $1',
    [(username || '').trim().toLowerCase()]
  );
  const row = result.rows[0];
  if (!row || row.password_hash !== hashPassword(password || '') || !row.active) {
    return res.status(401).json({ ok: false, error: 'Неверный логин или пароль.' });
  }
  res.json({ ok: true, name: row.name });
});

// 3. Список сотрудников
app.post('/crm-employees-list', async (req, res) => {
  if (req.body.adminCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код администратора.' });
  const result = await pool.query('SELECT id, username, name, active FROM employees ORDER BY id');
  res.json({ ok: true, employees: result.rows });
});

app.post('/crm-delete-employee', async (req, res) => {
  const { adminCode, id } = req.body;
  if (adminCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код администратора.' });
  if (!id) return res.status(400).json({ ok: false, error: 'Не хватает данных.' });
  await pool.query('DELETE FROM employees WHERE id = $1', [id]);
  res.json({ ok: true });
});

app.post('/crm-reset-password', async (req, res) => {
  const { adminCode, id, newPassword } = req.body;
  if (adminCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код администратора.' });
  if (!id || !newPassword) return res.status(400).json({ ok: false, error: 'Не хватает данных.' });
  await pool.query('UPDATE employees SET password_hash = $1 WHERE id = $2', [hashPassword(newPassword), id]);
  res.json({ ok: true });
});

// 4. Приём отчётности
app.post('/crm-report', async (req, res) => {
  const { username, password, date, client, amount, status, channel } = req.body;
  const empResult = await pool.query(
    'SELECT name, password_hash, active FROM employees WHERE username = $1',
    [(username || '').trim().toLowerCase()]
  );
  const emp = empResult.rows[0];
  if (!emp || emp.password_hash !== hashPassword(password || '') || !emp.active) {
    return res.status(401).json({ ok: false, error: 'Неверный логин или пароль.' });
  }
  const amountNum = parseFloat(amount) || 0;
  const isClosed = status === 'Сдан и закрыт';
  const commission = isClosed ? Math.round(amountNum * 0.2) : 0;

  await pool.query(
    'INSERT INTO deals (date, employee, client, amount, status, channel, commission) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [date, emp.name, client, amountNum, status, channel, commission]
  );

  if (TELEGRAM_TOKEN && TELEGRAM_CHAT_ID) {
    var text = '📋 <b>Новый отчёт от ' + emp.name + '</b>\n' +
      'Клиент: ' + client + '\n' +
      'Сумма: ' + amountNum + ' ₽\n' +
      'Статус: ' + status + '\n' +
      'Канал: ' + channel +
      (commission > 0 ? '\n💰 Комиссия: ' + commission + ' ₽' : '');
    fetch('https://api.telegram.org/bot' + TELEGRAM_TOKEN + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text, parse_mode: 'HTML' })
    }).catch(() => {});
  }

  res.json({ ok: true });
});

// 5. Список сделок
app.post('/crm-list', async (req, res) => {
  if (req.body.accessCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код доступа.' });
  const result = await pool.query('SELECT id, date, employee, client, amount, status, channel, commission FROM deals ORDER BY id DESC');
  res.json({ ok: true, deals: result.rows });
});

// 6. Обновить этап
app.post('/crm-update-stage', async (req, res) => {
  const { accessCode, row_number, newStatus, amount } = req.body;
  if (accessCode !== ADMIN_CODE) return res.status(403).json({ ok: false, error: 'Неверный код доступа.' });
  if (!row_number || !newStatus) return res.status(400).json({ ok: false, error: 'Не хватает данных.' });
  const amountNum = parseFloat(amount) || 0;
  const isClosed = newStatus === 'Сдан и закрыт';
  const commission = isClosed ? Math.round(amountNum * 0.2) : 0;
  await pool.query('UPDATE deals SET status = $1, commission = $2 WHERE id = $3', [newStatus, commission, row_number]);
  res.json({ ok: true });
});

app.listen(3000, () => console.log('CRM API running on port 3000'));
