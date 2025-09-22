
const express = require('express');
const db = require('./db');
const path = require('path');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { generateToken } = require('./middlewares/authMiddleware');
const User = require('./models/User');
const Task = require('./models/Task');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

db.sync();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware para autenticação nas páginas web
function webAuth(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect('/login');
  jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
    if (err) return res.redirect('/login');
    req.user = decoded;
    next();
  });
}

// Página inicial
app.get('/', (req, res) => {
  res.render('index');
});

// Registro
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const exists = await User.findOne({ where: { username } });
    if (exists) return res.render('register', { error: 'Usuário já existe' });
    const hash = bcrypt.hashSync(password, 10);
    await User.create({ username, password: hash, name: username });
    res.redirect('/login');
  } catch {
    res.render('register', { error: 'Erro ao registrar' });
  }
});

// Login
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ where: { username } });
    if (!user) return res.render('login', { error: 'Usuário não encontrado' });
    if (!bcrypt.compareSync(password, user.password))
      return res.render('login', { error: 'Senha inválida' });
    const token = generateToken(user);
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/tasks');
  } catch {
    res.render('login', { error: 'Erro ao logar' });
  }
});

// Logout
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/login');
});

// Dashboard de tarefas
app.get('/tasks', webAuth, async (req, res) => {
  const tasks = await Task.findAll({ where: { user_id: req.user.id }, order: [['id', 'DESC']] });
  res.render('tasks', { tasks });
});

// Nova tarefa
app.get('/tasks/new', webAuth, (req, res) => {
  res.render('new-task');
});
app.post('/tasks/new', webAuth, async (req, res) => {
  const { title, description } = req.body;
  await Task.create({ title, description, user_id: req.user.id });
  res.redirect('/tasks');
});

// Editar tarefa
app.get('/tasks/edit/:id', webAuth, async (req, res) => {
  const task = await Task.findOne({ where: { id: req.params.id, user_id: req.user.id } });
  if (!task) return res.redirect('/tasks');
  res.render('edit-task', { task });
});
app.post('/tasks/edit/:id', webAuth, async (req, res) => {
  const { title, description } = req.body;
  await Task.update({ title, description }, { where: { id: req.params.id, user_id: req.user.id } });
  res.redirect('/tasks');
});

// Completar tarefa
app.post('/tasks/complete/:id', webAuth, async (req, res) => {
  await Task.update({ completed: true }, { where: { id: req.params.id, user_id: req.user.id } });
  res.redirect('/tasks');
});

// Excluir tarefa
app.post('/tasks/delete/:id', webAuth, async (req, res) => {
  await Task.destroy({ where: { id: req.params.id, user_id: req.user.id } });
  res.redirect('/tasks');
});

// Rotas API originais
app.use('/api/user', require('./routes/userRoutes'));
app.use('/api/task', require('./routes/taskRoutes'));

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
