const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'serenity_secret_2024';
const DB_NAME = 'railway';

// ── Base de datos ──────────────────────────────────────────────
const pool = mysql.createPool({
  host: 'reseau.proxy.rlwy.net',
  port: 22884,
  database: DB_NAME,
  user: 'root',
  password: 'QbfQUyBUvPvDuURDeOyxkEPTrAOzznWn',
  ssl: false,
  waitForConnections: true,
  connectionLimit: 10,
});

async function ensureColumnExists(table, columnName, columnDefinition) {
  const [rows] = await pool.query(
    `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?`,
    [DB_NAME, table, columnName]
  );

  if (rows.length === 0) {
    const query = 'ALTER TABLE `' + table + '` ADD COLUMN ' + columnDefinition;
    await pool.query(query);
  }
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS Candidato (
      IdCandidato INT UNSIGNED NOT NULL AUTO_INCREMENT,
      Nombre VARCHAR(100) NOT NULL,
      Apellido VARCHAR(100) NOT NULL,
      Correo VARCHAR(150) NOT NULL,
      Telefono VARCHAR(20) DEFAULT NULL,
      Curriculum VARCHAR(255) DEFAULT NULL,
      Estado VARCHAR(50) DEFAULT 'Activo',
      FechaRegistro DATE NOT NULL,
      PRIMARY KEY (IdCandidato)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await ensureColumnExists('Candidato', 'Estado', "Estado VARCHAR(50) DEFAULT 'Activo'");

  await pool.query(`
    CREATE TABLE IF NOT EXISTS Vacante (
      IdVacante INT UNSIGNED NOT NULL AUTO_INCREMENT,
      Titulo VARCHAR(255) NOT NULL,
      Descripcion TEXT NOT NULL,
      Departamento VARCHAR(150) DEFAULT NULL,
      Estado VARCHAR(50) DEFAULT 'Activa',
      FechaCreacion DATE NOT NULL,
      FechaCierre DATE DEFAULT NULL,
      PRIMARY KEY (IdVacante)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS Postulacion (
      IdPostulacion INT UNSIGNED NOT NULL AUTO_INCREMENT,
      IdCandidato INT UNSIGNED NOT NULL,
      IdVacante INT UNSIGNED NOT NULL,
      Estado VARCHAR(50) DEFAULT 'Registrado',
      FechaPostulacion DATE NOT NULL,
      UltimaActualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (IdPostulacion)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS Entrevista (
      IdEntrevista INT UNSIGNED NOT NULL AUTO_INCREMENT,
      IdPostulacion INT UNSIGNED NOT NULL,
      Fecha DATE DEFAULT NULL,
      Hora VARCHAR(20) DEFAULT NULL,
      Modalidad VARCHAR(50) DEFAULT NULL,
      Observaciones VARCHAR(255) DEFAULT NULL,
      PRIMARY KEY (IdEntrevista)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS Evaluacion (
      IdEvaluacion INT UNSIGNED NOT NULL AUTO_INCREMENT,
      IdEntrevista INT UNSIGNED NOT NULL,
      IdUsuario INT UNSIGNED NOT NULL DEFAULT 1,
      Calificacion INT NOT NULL,
      Comentarios VARCHAR(255) DEFAULT NULL,
      Fecha DATE NOT NULL,
      PRIMARY KEY (IdEvaluacion)
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



app.get('/api/candidatos', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT 
        IdCandidato,
        Nombre,
        Apellido,
        Correo,
        Telefono,
        Curriculum,
        Estado,
        FechaRegistro
      FROM Candidato
      ORDER BY FechaRegistro DESC, IdCandidato DESC
    `);

    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/candidatos:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/candidatos/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT IdCandidato, Nombre, Apellido, Correo, Telefono, Curriculum, Estado, FechaRegistro FROM Candidato WHERE IdCandidato = ?`,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Candidato no encontrado' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error en GET /api/candidatos/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.put('/api/candidatos/:id', async (req, res) => {
  const { id } = req.params;
  const { Nombre, Apellido, Correo, Telefono, Estado, Curriculum } = req.body;

  if (!Nombre || !Apellido || !Correo) {
    return res.status(400).json({ error: 'Nombre, apellido y correo son requeridos' });
  }

  try {
    const [result] = await pool.query(
      `UPDATE Candidato SET Nombre = ?, Apellido = ?, Correo = ?, Telefono = ?, Estado = ?, Curriculum = ? WHERE IdCandidato = ?`,
      [Nombre.trim(), Apellido.trim(), Correo.trim(), Telefono || null, Estado || 'Activo', Curriculum || '', id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Candidato no encontrado' });
    }

    const [rows] = await pool.query('SELECT * FROM Candidato WHERE IdCandidato = ?', [id]);
    res.json({ candidato: rows[0] });
  } catch (err) {
    console.error('Error en PUT /api/candidatos/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.delete('/api/candidatos/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query('DELETE FROM Candidato WHERE IdCandidato = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Candidato no encontrado' });
    }

    res.json({ message: 'Candidato eliminado correctamente' });
  } catch (err) {
    console.error('Error en DELETE /api/candidatos/:id:', err.message);
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

// ── POST /api/vacantes ───────────────────────────────────────
app.post('/api/vacantes', async (req, res) => {
  const { Titulo, Descripcion, Departamento, Estado, FechaCreacion, FechaCierre } = req.body;

  console.log('POST /api/vacantes body:', req.body);

  if (!Titulo || !Descripcion) {
    return res.status(400).json({ error: 'Titulo y Descripcion son requeridos' });
  }

  try {
    const fechaCreacion = FechaCreacion || new Date().toISOString().slice(0,10);

    const estadoClean = (Estado || 'Activa').toString().trim().slice(0,50);
    const [result] = await pool.query(
      'INSERT INTO Vacante (Titulo, Descripcion, Departamento, Estado, FechaCreacion, FechaCierre) VALUES (?, ?, ?, ?, ?, ?)',
      [Titulo, Descripcion, Departamento || '', estadoClean, fechaCreacion, FechaCierre || null]
    );

    const [rows] = await pool.query('SELECT * FROM Vacante WHERE IdVacante = ?', [result.insertId]);

    res.status(201).json({ vacante: rows[0] });
  } catch (err) {
    console.error('Error en POST /api/vacantes:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/vacantes (para pruebas) ─────────────────────────────────────
app.get('/api/vacantes', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM Vacante ORDER BY IdVacante DESC');
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/vacantes:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/postulaciones ─────────────────────────────────────
app.get('/api/postulaciones', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        p.IdPostulacion,
        p.IdCandidato,
        p.IdVacante,
        p.Estado,
        p.FechaPostulacion,
        p.UltimaActualizacion,
        c.Nombre,
        c.Apellido,
        c.Correo,
        c.Telefono,
        c.Curriculum,
        c.FechaRegistro
      FROM Postulacion p
      INNER JOIN Candidato c ON p.IdCandidato = c.IdCandidato
      ORDER BY p.UltimaActualizacion DESC, p.FechaPostulacion DESC
    `);

    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/postulaciones:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/postulaciones/:id ─────────────────────────────────
app.get('/api/postulaciones/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const [rows] = await pool.query(
      `
      SELECT
        p.IdPostulacion,
        p.IdCandidato,
        p.IdVacante,
        p.Estado,
        p.FechaPostulacion,
        p.UltimaActualizacion,
        c.Nombre,
        c.Apellido,
        c.Correo,
        c.Telefono,
        c.Curriculum,
        c.FechaRegistro
      FROM Postulacion p
      INNER JOIN Candidato c ON p.IdCandidato = c.IdCandidato
      WHERE p.IdPostulacion = ?
      `,
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Postulación no encontrada' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error en GET /api/postulaciones/:id:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── PUT /api/postulaciones/:id/estado ──────────────────────────
app.put('/api/postulaciones/:id/estado', async (req, res) => {
  const { id } = req.params;
  const { Estado } = req.body;

  const estadosPermitidos = [
    'Registrado',
    'En revisión',
    'Entrevista',
    'Evaluación',
    'Oferta',
    'Contratado',
    'Rechazado'
  ];

  if (!Estado) {
    return res.status(400).json({ error: 'Debe seleccionar un estado' });
  }

  if (!estadosPermitidos.includes(Estado)) {
    return res.status(400).json({ error: 'Estado no permitido' });
  }

  try {
    const [existe] = await pool.query(
      'SELECT IdPostulacion, Estado FROM Postulacion WHERE IdPostulacion = ?',
      [id]
    );

    if (existe.length === 0) {
      return res.status(404).json({ error: 'Postulación no encontrada' });
    }

    const estadoAnterior = existe[0].Estado;

    await pool.query(
      `
      UPDATE Postulacion
      SET Estado = ?, UltimaActualizacion = NOW()
      WHERE IdPostulacion = ?
      `,
      [Estado, id]
    );

    const [actualizada] = await pool.query(
      `
      SELECT
        p.IdPostulacion,
        p.IdCandidato,
        p.IdVacante,
        p.Estado,
        p.FechaPostulacion,
        p.UltimaActualizacion,
        c.Nombre,
        c.Apellido,
        c.Correo,
        c.Telefono,
        c.Curriculum,
        c.FechaRegistro
      FROM Postulacion p
      INNER JOIN Candidato c ON p.IdCandidato = c.IdCandidato
      WHERE p.IdPostulacion = ?
      `,
      [id]
    );

    res.json({
      message: 'Estado actualizado correctamente. El candidato puede visualizar el nuevo estado.',
      estadoAnterior,
      estadoNuevo: Estado,
      postulacion: actualizada[0]
    });

  } catch (err) {
    console.error('Error actualizando estado:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── POST /api/postulaciones/crear-o-buscar ─────────────────────
app.post('/api/postulaciones/crear-o-buscar', async (req, res) => {
  const { IdCandidato } = req.body;

  if (!IdCandidato) {
    return res.status(400).json({ error: 'IdCandidato es requerido' });
  }

  try {
    // Verificar que el candidato exista
    const [candidato] = await pool.query(
      'SELECT IdCandidato FROM Candidato WHERE IdCandidato = ?',
      [IdCandidato]
    );

    if (candidato.length === 0) {
      return res.status(404).json({ error: 'Candidato no encontrado' });
    }

    // Buscar si ya tiene una postulación
    const [existente] = await pool.query(
      `
      SELECT 
        IdPostulacion, 
        IdCandidato, 
        IdVacante, 
        Estado, 
        FechaPostulacion,
        UltimaActualizacion
      FROM Postulacion
      WHERE IdCandidato = ?
      ORDER BY IdPostulacion DESC
      LIMIT 1
      `,
      [IdCandidato]
    );

    if (existente.length > 0) {
      return res.json({
        message: 'Postulación encontrada',
        postulacion: existente[0]
      });
    }

    // Buscar una vacante activa o la primera disponible
    const [vacantes] = await pool.query(
      `
      SELECT IdVacante 
      FROM Vacante 
      ORDER BY IdVacante ASC 
      LIMIT 1
      `
    );

    if (vacantes.length === 0) {
      return res.status(400).json({
        error: 'No existe ninguna vacante registrada. Debe existir al menos una vacante para crear la postulación.'
      });
    }

    const IdVacante = vacantes[0].IdVacante;

    // Crear postulación nueva
    const [result] = await pool.query(
      `
      INSERT INTO Postulacion
      (IdCandidato, IdVacante, Estado, FechaPostulacion, UltimaActualizacion)
      VALUES (?, ?, 'Registrado', CURDATE(), NOW())
      `,
      [IdCandidato, IdVacante]
    );

    const [nueva] = await pool.query(
      `
      SELECT 
        IdPostulacion, 
        IdCandidato, 
        IdVacante, 
        Estado, 
        FechaPostulacion,
        UltimaActualizacion
      FROM Postulacion
      WHERE IdPostulacion = ?
      `,
      [result.insertId]
    );

    return res.status(201).json({
      message: 'Postulación creada',
      postulacion: nueva[0]
    });

  } catch (err) {
    console.error('Error creando o buscando postulación:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

app.get('/api/entrevistas', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        e.IdEntrevista,
        e.IdPostulacion,
        e.Fecha,
        e.Hora,
        e.Modalidad,
        e.Observaciones,
        p.IdCandidato,
        p.IdVacante,
        p.Estado AS EstadoEntrevista,
        p.FechaPostulacion,
        c.Nombre,
        c.Apellido,
        c.Correo,
        c.Telefono,
        v.Titulo AS Vacante,
        (SELECT COUNT(*) FROM Evaluacion ev WHERE ev.IdEntrevista = e.IdEntrevista) AS EvaluacionesCount
      FROM Entrevista e
      LEFT JOIN Postulacion p ON e.IdPostulacion = p.IdPostulacion
      LEFT JOIN Candidato c ON p.IdCandidato = c.IdCandidato
      LEFT JOIN Vacante v ON p.IdVacante = v.IdVacante
      ORDER BY e.Fecha DESC, e.IdEntrevista DESC
    `);

    const entrevistas = rows.map((item) => ({
      ...item,
      Evaluada: Number(item.EvaluacionesCount) > 0,
      EvaluacionesCount: Number(item.EvaluacionesCount),
      FechaPostulacion: item.FechaPostulacion || item.Fecha || null,
    }));

    res.json(entrevistas);
  } catch (err) {
    console.error('Error en GET /api/entrevistas:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/evaluaciones', async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT IdEvaluacion, IdEntrevista, IdUsuario, Calificacion, Comentarios, Fecha
      FROM Evaluacion
      ORDER BY Fecha DESC, IdEvaluacion DESC
    `);

    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/evaluaciones:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/evaluaciones', async (req, res) => {
  const { IdEntrevista, IdUsuario = 1, Calificacion, Comentarios = '' } = req.body;

  if (!IdEntrevista || Calificacion === undefined || Calificacion === null) {
    return res.status(400).json({ error: 'IdEntrevista y Calificacion son requeridos' });
  }

  const calificacionNum = Number(Calificacion);

  if (Number.isNaN(calificacionNum) || calificacionNum < 1 || calificacionNum > 5) {
    return res.status(400).json({ error: 'La calificación debe estar entre 1 y 5' });
  }

  try {
    const comentarioTexto = String(Comentarios || '').slice(0, 255);
    const [existente] = await pool.query(
      'SELECT IdEvaluacion FROM Evaluacion WHERE IdEntrevista = ? LIMIT 1',
      [IdEntrevista]
    );

    let result;

    if (existente.length > 0) {
      [result] = await pool.query(
        'UPDATE Evaluacion SET IdUsuario = ?, Calificacion = ?, Comentarios = ?, Fecha = CURDATE() WHERE IdEntrevista = ?',
        [IdUsuario, calificacionNum, comentarioTexto, IdEntrevista]
      );
    } else {
      [result] = await pool.query(
        'INSERT INTO Evaluacion (IdEntrevista, IdUsuario, Calificacion, Comentarios, Fecha) VALUES (?, ?, ?, ?, CURDATE())',
        [IdEntrevista, IdUsuario, calificacionNum, comentarioTexto]
      );
    }

    const [rows] = await pool.query(
      'SELECT * FROM Evaluacion WHERE IdEntrevista = ? ORDER BY IdEvaluacion DESC LIMIT 1',
      [IdEntrevista]
    );

    res.status(201).json({ evaluacion: rows[0], actualizado: existente.length > 0 });
  } catch (err) {
    console.error('Error en POST /api/evaluaciones:', err.message);
    res.status(500).json({ error: err.message });
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