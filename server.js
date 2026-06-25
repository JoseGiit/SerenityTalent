const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'serenity_secret_2024';

// ── Base de datos ──────────────────────────────────────────────
const pool = mysql.createPool({
  host: 'reseau.proxy.rlwy.net',
  port: 22884,
  database: 'railway',
  user: 'root',
  password: 'QbfQUyBUvPvDuURDeOyxkEPTrAOzznWn',
  ssl: false,
  waitForConnections: true,
  connectionLimit: 10,
});

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS Candidato (
      IdCandidato INT UNSIGNED NOT NULL AUTO_INCREMENT,
      Nombre VARCHAR(100) NOT NULL,
      Apellido VARCHAR(100) NOT NULL,
      Correo VARCHAR(150) NOT NULL,
      Telefono VARCHAR(20) DEFAULT NULL,
      Curriculum VARCHAR(255) DEFAULT NULL,
      FechaRegistro DATE NOT NULL,
      PRIMARY KEY (IdCandidato)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
}

// ── Middleware ─────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.originalUrl}`);
  next();
});

// ── POST /api/register ─────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { Nombre, Correo, IJsuario, Contrasena } = req.body;

  if (!Nombre || !Correo || !IJsuario || !Contrasena) {
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  try {
    // Verificar si el usuario o correo ya existen
    const [existe] = await pool.query(
      'SELECT IdUsuario FROM Usuario WHERE Correo = ? OR Usuario = ?',
      [Correo, IJsuario]
    );

    if (existe.length > 0) {
      return res.status(409).json({ error: 'El usuario o correo ya está registrado' });
    }

    // Hashear contraseña antes de guardar
    const hash = await bcrypt.hash(Contrasena, 10);

    // Insertar nuevo usuario con rol 2 por defecto
    const [result] = await pool.query(
      'INSERT INTO Usuario (Nombre, Correo, Usuario, Contrasena, IdRol) VALUES (?, ?, ?, ?, 2)',
      [Nombre, Correo, IJsuario, hash]
    );

    // Recuperar el usuario recién creado
    const [rows] = await pool.query(
      'SELECT IdUsuario, Nombre, Correo, Usuario, IdRol FROM Usuario WHERE IdUsuario = ?',
      [result.insertId]
    );

    const usuario = rows[0];
    const token = jwt.sign(
      { id: usuario.IdUsuario, usuario: usuario.Usuario, rol: usuario.IdRol },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.status(201).json({ token, usuario });
  } catch (err) {
    console.error('Error en /register:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── POST /api/login ────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { identifier, Contrasena } = req.body;

  if (!identifier || !Contrasena) {
    return res.status(400).json({ error: 'Usuario/correo y contraseña son requeridos' });
  }

  try {
    // Buscar por correo o nombre de usuario
    const [rows] = await pool.query(
      'SELECT * FROM Usuario WHERE Correo = ? OR Usuario = ? LIMIT 1',
      [identifier, identifier]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const usuario = rows[0];

    // Comparar contraseña con el hash guardado
    const coincide = await bcrypt.compare(Contrasena, usuario.Contrasena);

    if (!coincide) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: usuario.IdUsuario, usuario: usuario.Usuario, rol: usuario.IdRol },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      usuario: {
        id: usuario.IdUsuario,
        nombre: usuario.Nombre,
        correo: usuario.Correo,
        usuario: usuario.Usuario,
        rol: usuario.IdRol
      }
    });
  } catch (err) {
    console.error('Error en /login:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/candidatos ─────────────────────────────────────────
app.get('/api/candidatos', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT IdCandidato, Nombre, Apellido, Correo, Telefono, Curriculum, FechaRegistro FROM Candidato ORDER BY FechaRegistro DESC'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en /api/candidatos:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── POST /api/candidatos ────────────────────────────────────────
app.post('/api/candidatos', async (req, res) => {
  const {
    Nombre,
    Apellido,
    Correo,
    Telefono,
    Curriculum,
  } = req.body;

  if (!Nombre || !Apellido || !Correo || !Telefono) {
    return res.status(400).json({ error: 'Nombre, apellido, correo y teléfono son requeridos' });
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO Candidato (Nombre, Apellido, Correo, Telefono, Curriculum, FechaRegistro) VALUES (?, ?, ?, ?, ?, CURDATE())',
      [
        Nombre,
        Apellido,
        Correo,
        Telefono,
        Curriculum || '',
      ]
    );

    const [rows] = await pool.query(
      'SELECT * FROM Candidato WHERE IdCandidato = ?',
      [result.insertId]
    );

    res.status(201).json({ candidato: rows[0] });
  } catch (err) {
    console.error('Error en /api/candidatos POST:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Arrancar ───────────────────────────────────────────────────
initializeDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
      console.log(`📄 Abre http://localhost:${PORT}/index.html`);
    });
  })
  .catch((err) => {
    console.error('Error inicializando la base de datos:', err.message);
    process.exit(1);
  });