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

// Roles del sistema (coinciden con los IdRol en la BD)
const ROLES = {
  ADMIN: 1,
  RECLUTADOR: 2,
  CANDIDATO: 3,
};

// ── Base de datos ──────────────────────────────────────────────
const pool = mysql.createPool({
  host: 'sakura.proxy.rlwy.net',
  port: 21301,
  database: DB_NAME,
  user: 'root',
  password: 'GCpYKCLXRMpHMfVwtxEWiVzUsBbxNzop',
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
  // Vínculo real entre la cuenta de login (Usuario) y su perfil de candidato.
  // Nullable: un Admin/Reclutador puede seguir dando de alta candidatos que
  // no tienen cuenta propia en el sistema, y un Candidato puede postular a
  // un tercero cuyo perfil tampoco queda vinculado a ninguna cuenta.
  await ensureColumnExists('Candidato', 'IdUsuario', 'IdUsuario INT UNSIGNED DEFAULT NULL');

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

  // Tabla de usuarios para login/roles
  await pool.query(`
    CREATE TABLE IF NOT EXISTS Usuario (
      IdUsuario INT UNSIGNED NOT NULL AUTO_INCREMENT,
      Nombre VARCHAR(150) NOT NULL,
      Correo VARCHAR(150) NOT NULL,
      Usuario VARCHAR(100) NOT NULL,
      Contrasena VARCHAR(255) NOT NULL,
      IdRol TINYINT UNSIGNED NOT NULL DEFAULT 3,
      FechaRegistro DATETIME DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (IdUsuario),
      UNIQUE KEY uq_usuario_correo (Correo, Usuario)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  // Si la tabla Usuario ya existía (por ejemplo, creada manualmente en
  // Railway sin esta columna), la agregamos para que las consultas que
  // seleccionan FechaRegistro no fallen con "Unknown column".
  await ensureColumnExists('Usuario', 'FechaRegistro', 'FechaRegistro DATETIME DEFAULT CURRENT_TIMESTAMP');

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

// ── Middleware de autenticación y autorización ──────────────────

// Verifica que venga un JWT válido en el header Authorization: Bearer <token>
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acceso no autorizado: token no proporcionado' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }
    // payload: { id, usuario, rol, correo }
    req.user = payload;
    next();
  });
}

// Genera un middleware que solo deja pasar a los roles indicados
function authorizeRoles(...rolesPermitidos) {
  return (req, res, next) => {
    if (!req.user || !rolesPermitidos.includes(req.user.rol)) {
      return res.status(403).json({ error: 'No tiene permisos para realizar esta acción' });
    }
    next();
  };
}

// Permite el acceso a Admin/Reclutador sobre cualquier candidato,
// pero a un usuario con rol Candidato solo sobre su propio registro
// (se identifica comparando el correo del token con el correo del Candidato).
async function permitirPropioCandidatoOStaff(req, res, next) {
  if (req.user.rol === ROLES.ADMIN || req.user.rol === ROLES.RECLUTADOR) {
    return next();
  }

  if (req.user.rol === ROLES.CANDIDATO) {
    try {
      const [rows] = await pool.query(
        'SELECT Correo, IdUsuario FROM Candidato WHERE IdCandidato = ?',
        [req.params.id]
      );

      if (rows.length === 0) {
        return res.status(404).json({ error: 'Candidato no encontrado' });
      }

      // Preferimos comparar por IdUsuario (vínculo real de cuenta). Si el
      // registro es antiguo y todavía no tiene IdUsuario asignado, caemos
      // de vuelta a comparar por correo como antes.
      if (rows[0].IdUsuario !== null && rows[0].IdUsuario !== undefined) {
        if (Number(rows[0].IdUsuario) !== Number(req.user.id)) {
          return res.status(403).json({ error: 'Solo puede acceder a su propio perfil' });
        }
        return next();
      }

      const correoToken = (req.user.correo || '').toLowerCase();
      const correoCandidato = (rows[0].Correo || '').toLowerCase();

      if (correoToken !== correoCandidato) {
        return res.status(403).json({ error: 'Solo puede acceder a su propio perfil' });
      }

      return next();
    } catch (err) {
      console.error('Error verificando propiedad de candidato:', err.message);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }

  return res.status(403).json({ error: 'No tiene permisos para realizar esta acción' });
}

// ── POST /api/register ─────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { Nombre, Correo, IJsuario, Contrasena } = req.body;

  if (!Nombre || !Correo || !IJsuario || !Contrasena) {
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  // El registro público siempre crea cuentas con rol de candidato.
  const rolFinal = ROLES.CANDIDATO;

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

    // Insertar nuevo usuario con el rol elegido (Reclutador o Candidato)
    const [result] = await pool.query(
      'INSERT INTO Usuario (Nombre, Correo, Usuario, Contrasena, IdRol) VALUES (?, ?, ?, ?, ?)',
      [Nombre, Correo, IJsuario, hash, rolFinal]
    );

    // Recuperar el usuario recién creado
    const [rows] = await pool.query(
      'SELECT IdUsuario, Nombre, Correo, Usuario, IdRol FROM Usuario WHERE IdUsuario = ?',
      [result.insertId]
    );

    const usuario = rows[0];
    const token = jwt.sign(
      { id: usuario.IdUsuario, usuario: usuario.Usuario, rol: usuario.IdRol, correo: usuario.Correo },
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

    const usuarioDb = rows[0];

    // Comparar contraseña con el hash guardado
    const coincide = await bcrypt.compare(Contrasena, usuarioDb.Contrasena);

    if (!coincide) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: usuarioDb.IdUsuario, usuario: usuarioDb.Usuario, rol: usuarioDb.IdRol, correo: usuarioDb.Correo },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    // Misma forma que /api/register: siempre IdUsuario, Nombre, Correo, Usuario, IdRol
    res.json({
      token,
      usuario: {
        IdUsuario: usuarioDb.IdUsuario,
        Nombre: usuarioDb.Nombre,
        Correo: usuarioDb.Correo,
        Usuario: usuarioDb.Usuario,
        IdRol: usuarioDb.IdRol,
      },
    });
  } catch (err) {
    console.error('Error en /login:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/candidatos (listado completo) ─────────────────────
// Admin y Reclutador. Candidato NO: expone PII de otros candidatos.
app.get('/api/candidatos', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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

// ── GET /api/candidatos/mi-perfil ────────────────────────────────
// Solo Candidato. Devuelve el perfil de candidato vinculado a esta cuenta
// (por IdUsuario), si ya existe. Debe ir declarada ANTES de
// '/api/candidatos/:id' o Express interpretaría "mi-perfil" como un id.
app.get('/api/candidatos/mi-perfil', authenticateToken, authorizeRoles(ROLES.CANDIDATO), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT IdCandidato, Nombre, Apellido, Correo, Telefono, Curriculum, Estado, FechaRegistro FROM Candidato WHERE IdUsuario = ? LIMIT 1',
      [req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Todavía no tiene un perfil de candidato registrado' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error en GET /api/candidatos/mi-perfil:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── POST /api/candidatos/mi-perfil ───────────────────────────────
// Solo Candidato. Crea o actualiza (upsert) el perfil de candidato vinculado
// a esta cuenta, identificado por IdUsuario. Así, sin importar cuántas veces
// se postule, siempre es el mismo registro de Candidato el que se actualiza
// y el que aparece vinculado a sus postulaciones.
app.post('/api/candidatos/mi-perfil', authenticateToken, authorizeRoles(ROLES.CANDIDATO), async (req, res) => {
  const { Nombre, Apellido, Correo, Telefono, Curriculum } = req.body;

  if (!Nombre || !Apellido || !Correo || !Telefono) {
    return res.status(400).json({ error: 'Nombre, apellido, correo y teléfono son requeridos' });
  }

  try {
    const [existente] = await pool.query(
      'SELECT IdCandidato FROM Candidato WHERE IdUsuario = ? LIMIT 1',
      [req.user.id]
    );

    let idCandidato;

    if (existente.length > 0) {
      idCandidato = existente[0].IdCandidato;

      await pool.query(
        'UPDATE Candidato SET Nombre = ?, Apellido = ?, Correo = ?, Telefono = ?, Curriculum = ? WHERE IdCandidato = ?',
        [Nombre.trim(), Apellido.trim(), Correo.trim(), Telefono.trim(), Curriculum || '', idCandidato]
      );
    } else {
      const [result] = await pool.query(
        'INSERT INTO Candidato (Nombre, Apellido, Correo, Telefono, Curriculum, FechaRegistro, IdUsuario) VALUES (?, ?, ?, ?, ?, CURDATE(), ?)',
        [Nombre.trim(), Apellido.trim(), Correo.trim(), Telefono.trim(), Curriculum || '', req.user.id]
      );
      idCandidato = result.insertId;
    }

    const [rows] = await pool.query('SELECT * FROM Candidato WHERE IdCandidato = ?', [idCandidato]);

    res.status(200).json({ candidato: rows[0] });
  } catch (err) {
    console.error('Error en POST /api/candidatos/mi-perfil:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/candidatos/mi-seguimiento ───────────────────────────
// Solo Candidato. Devuelve, para el candidato vinculado a la cuenta
// autenticada (por IdUsuario), todas sus postulaciones junto con las
// entrevistas agendadas y la evaluación de cada entrevista (si ya
// existe). Es de solo lectura: el candidato nunca puede modificar
// nada de esto, solo consultarlo. Debe ir declarada ANTES de
// '/api/candidatos/:id' o Express interpretaría "mi-seguimiento" como un id.
app.get('/api/candidatos/mi-seguimiento', authenticateToken, authorizeRoles(ROLES.CANDIDATO), async (req, res) => {
  try {
    // 1. Ubicar el perfil de Candidato vinculado a esta cuenta.
    const [candidatoRows] = await pool.query(
      'SELECT IdCandidato, Nombre, Apellido, Correo FROM Candidato WHERE IdUsuario = ? LIMIT 1',
      [req.user.id]
    );

    if (candidatoRows.length === 0) {
      return res.status(404).json({ error: 'Todavía no tiene un perfil de candidato registrado' });
    }

    const candidato = candidatoRows[0];

    // 2. Traer postulaciones + vacante + entrevista + evaluación en una
    //    sola consulta (con LEFT JOIN, porque una postulación puede no
    //    tener entrevista todavía, y una entrevista puede no tener
    //    evaluación todavía).
    const [rows] = await pool.query(
      `
      SELECT
        p.IdPostulacion,
        p.IdVacante,
        p.Estado AS EstadoPostulacion,
        p.FechaPostulacion,
        p.UltimaActualizacion,
        v.Titulo AS VacanteTitulo,
        v.Departamento,
        e.IdEntrevista,
        e.Fecha AS FechaEntrevista,
        e.Hora,
        e.Modalidad,
        e.Observaciones,
        ev.IdEvaluacion,
        ev.Calificacion,
        ev.Comentarios,
        ev.Fecha AS FechaEvaluacion
      FROM Postulacion p
      LEFT JOIN Vacante v ON p.IdVacante = v.IdVacante
      LEFT JOIN Entrevista e ON e.IdPostulacion = p.IdPostulacion
      LEFT JOIN Evaluacion ev ON ev.IdEntrevista = e.IdEntrevista
      WHERE p.IdCandidato = ?
      ORDER BY p.UltimaActualizacion DESC, e.Fecha DESC
      `,
      [candidato.IdCandidato]
    );

    // 3. Agrupar filas planas en: postulaciones -> entrevistas -> evaluación.
    const postulacionesMap = new Map();

    for (const row of rows) {
      if (!postulacionesMap.has(row.IdPostulacion)) {
        postulacionesMap.set(row.IdPostulacion, {
          IdPostulacion: row.IdPostulacion,
          IdVacante: row.IdVacante,
          VacanteTitulo: row.VacanteTitulo || 'Vacante no disponible',
          Departamento: row.Departamento,
          Estado: row.EstadoPostulacion,
          FechaPostulacion: row.FechaPostulacion,
          UltimaActualizacion: row.UltimaActualizacion,
          entrevistas: [],
        });
      }

      const postulacion = postulacionesMap.get(row.IdPostulacion);

      if (row.IdEntrevista) {
        let entrevista = postulacion.entrevistas.find((e) => e.IdEntrevista === row.IdEntrevista);

        if (!entrevista) {
          entrevista = {
            IdEntrevista: row.IdEntrevista,
            Fecha: row.FechaEntrevista,
            Hora: row.Hora,
            Modalidad: row.Modalidad,
            Observaciones: row.Observaciones,
            evaluacion: null,
          };
          postulacion.entrevistas.push(entrevista);
        }

        if (row.IdEvaluacion && !entrevista.evaluacion) {
          entrevista.evaluacion = {
            Calificacion: row.Calificacion,
            Comentarios: row.Comentarios,
            Fecha: row.FechaEvaluacion,
          };
        }
      }
    }

    const postulaciones = Array.from(postulacionesMap.values());

    res.json({ candidato, postulaciones });
  } catch (err) {
    console.error('Error en GET /api/candidatos/mi-seguimiento:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── POST /api/candidatos/postular-tercero ─────────────────────────
// Solo Candidato. Crea o actualiza el perfil de OTRA persona (no la propia
// cuenta del usuario autenticado) para postularla en su nombre.
//
// Reglas de seguridad:
// - Nunca se le puede pasar el propio correo del usuario autenticado
//   (para eso existe /mi-perfil).
// - Nunca se toca un perfil que ya tenga IdUsuario asignado: esos
//   pertenecen a la cuenta de otra persona y no son editables desde acá.
//   Si el correo coincide con uno de esos, se crea un perfil nuevo en vez
//   de sobrescribir datos ajenos.
app.post('/api/candidatos/postular-tercero', authenticateToken, authorizeRoles(ROLES.CANDIDATO), async (req, res) => {
  const { Nombre, Apellido, Correo, Telefono, Curriculum } = req.body;

  if (!Nombre || !Apellido || !Correo || !Telefono) {
    return res.status(400).json({ error: 'Nombre, apellido, correo y teléfono son requeridos' });
  }

  const correoNormalizado = Correo.trim().toLowerCase();

  if (correoNormalizado === (req.user.correo || '').toLowerCase()) {
    return res.status(400).json({ error: 'Ese es tu propio correo. Para postularte a ti mismo usa la opción "Me postulo yo".' });
  }

  try {
    const [existente] = await pool.query(
      'SELECT IdCandidato FROM Candidato WHERE LOWER(Correo) = ? AND IdUsuario IS NULL LIMIT 1',
      [correoNormalizado]
    );

    let idCandidato;

    if (existente.length > 0) {
      idCandidato = existente[0].IdCandidato;

      await pool.query(
        'UPDATE Candidato SET Nombre = ?, Apellido = ?, Correo = ?, Telefono = ?, Curriculum = ? WHERE IdCandidato = ?',
        [Nombre.trim(), Apellido.trim(), Correo.trim(), Telefono.trim(), Curriculum || '', idCandidato]
      );
    } else {
      const [result] = await pool.query(
        'INSERT INTO Candidato (Nombre, Apellido, Correo, Telefono, Curriculum, FechaRegistro, IdUsuario) VALUES (?, ?, ?, ?, ?, CURDATE(), NULL)',
        [Nombre.trim(), Apellido.trim(), Correo.trim(), Telefono.trim(), Curriculum || '']
      );
      idCandidato = result.insertId;
    }

    const [rows] = await pool.query('SELECT * FROM Candidato WHERE IdCandidato = ?', [idCandidato]);

    res.status(200).json({ candidato: rows[0] });
  } catch (err) {
    console.error('Error en POST /api/candidatos/postular-tercero:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/candidatos/:id ──────────────────────────────────────
// Admin/Reclutador: cualquier candidato. Candidato: solo su propio perfil.
app.get('/api/candidatos/:id', authenticateToken, permitirPropioCandidatoOStaff, async (req, res) => {
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

// ── PUT /api/candidatos/:id ──────────────────────────────────────
// Admin/Reclutador: cualquier candidato. Candidato: solo su propio perfil.
app.put('/api/candidatos/:id', authenticateToken, permitirPropioCandidatoOStaff, async (req, res) => {
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

// ── DELETE /api/candidatos/:id ───────────────────────────────────
// Eliminación permanente: solo Administrador.
app.delete('/api/candidatos/:id', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
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

// ── POST /api/candidatos (alta manual) ───────────────────────────
// Admin y Reclutador. Permite vincular opcionalmente el nuevo Candidato a
// una cuenta de Usuario existente (rol Candidato) mediante IdUsuario. Se
// valida que la cuenta exista, que tenga rol Candidato, y que no esté ya
// vinculada a otro Candidato (relación 1 a 1 entre Usuario y Candidato).
app.post('/api/candidatos', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const {
    Nombre,
    Apellido,
    Correo,
    Telefono,
    Curriculum,
    IdUsuario,
  } = req.body;

  if (!Nombre || !Apellido || !Correo || !Telefono) {
    return res.status(400).json({ error: 'Nombre, apellido, correo y teléfono son requeridos' });
  }

  // IdUsuario es opcional: permite vincular esta ficha de candidato a una
  // cuenta de login existente. Si viene vacío/null, el candidato queda
  // sin cuenta vinculada (como hasta ahora).
  let idUsuarioFinal = null;

  if (IdUsuario !== undefined && IdUsuario !== null && IdUsuario !== '') {
    const idUsuarioNum = Number(IdUsuario);

    if (!Number.isInteger(idUsuarioNum) || idUsuarioNum <= 0) {
      return res.status(400).json({ error: 'IdUsuario inválido' });
    }

    try {
      // 1. La cuenta debe existir y tener rol Candidato.
      const [usuarioRows] = await pool.query(
        'SELECT IdUsuario, IdRol FROM Usuario WHERE IdUsuario = ?',
        [idUsuarioNum]
      );

      if (usuarioRows.length === 0) {
        return res.status(404).json({ error: 'El usuario seleccionado no existe' });
      }

      if (Number(usuarioRows[0].IdRol) !== ROLES.CANDIDATO) {
        return res.status(400).json({ error: 'Solo se pueden vincular cuentas con rol Candidato' });
      }

      // 2. Esa cuenta no debe estar ya vinculada a otro candidato
      //    (relación 1 a 1 entre Usuario y Candidato).
      const [vinculoExistente] = await pool.query(
        'SELECT IdCandidato FROM Candidato WHERE IdUsuario = ?',
        [idUsuarioNum]
      );

      if (vinculoExistente.length > 0) {
        return res.status(409).json({ error: 'Ese usuario ya está vinculado a otro candidato' });
      }

      idUsuarioFinal = idUsuarioNum;
    } catch (err) {
      console.error('Error validando IdUsuario en POST /api/candidatos:', err.message);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
  }

  try {
    const [result] = await pool.query(
      'INSERT INTO Candidato (Nombre, Apellido, Correo, Telefono, Curriculum, FechaRegistro, IdUsuario) VALUES (?, ?, ?, ?, ?, CURDATE(), ?)',
      [
        Nombre,
        Apellido,
        Correo,
        Telefono,
        Curriculum || '',
        idUsuarioFinal,
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
// Admin y Reclutador.
app.post('/api/vacantes', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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

// ── DELETE /api/vacantes/:id ─────────────────────────────────
// Eliminación permanente: Administrador y Reclutador. El Candidato nunca
// puede eliminar vacantes (authorizeRoles lo bloquea con 403 aunque
// intente llamar al endpoint directamente).
app.delete('/api/vacantes/:id', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query('DELETE FROM Vacante WHERE IdVacante = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Vacante no encontrada' });
    }

    res.json({ message: 'Vacante eliminada correctamente' });
  } catch (err) {
    console.error('Error en DELETE /api/vacantes/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/vacantes ─────────────────────────────────────
// Admin/Reclutador: todas las vacantes. Candidato: solo vacantes activas.
app.get('/api/vacantes', authenticateToken, async (req, res) => {
  try {
    let query = 'SELECT * FROM Vacante';
    const params = [];

    if (req.user.rol === ROLES.CANDIDATO) {
      query += ' WHERE Estado = ?';
      params.push('Activa');
    }

    query += ' ORDER BY IdVacante DESC';

    const [rows] = await pool.query(query, params);
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/vacantes:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/postulaciones ─────────────────────────────────────
// Admin y Reclutador (seguimiento_candidato.html). Candidato consulta su
// estado por otra vía (modal público por correo), no por este listado.
app.get('/api/postulaciones', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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
        c.FechaRegistro,
        v.Titulo AS VacanteTitulo
      FROM Postulacion p
      INNER JOIN Candidato c ON p.IdCandidato = c.IdCandidato
      LEFT JOIN Vacante v ON p.IdVacante = v.IdVacante
      ORDER BY p.UltimaActualizacion DESC, p.FechaPostulacion DESC
    `);

    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/postulaciones:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ── GET /api/postulaciones/consulta ─────────────────────────────
// Público (index.html, HU-04). Permite a cualquier persona consultar el
// estado de SU postulación por correo, sin exponer el listado completo de
// candidatos ni de postulaciones de terceros. Debe ir declarada ANTES de
// '/api/postulaciones/:id' o Express interpretaría "consulta" como un id.
app.get('/api/postulaciones/consulta', async (req, res) => {
  const correo = String(req.query.correo || '').trim().toLowerCase();

  if (!correo) {
    return res.status(400).json({ error: 'Correo es requerido' });
  }

  try {
    const [candidatoRows] = await pool.query(
      'SELECT IdCandidato, Nombre, Apellido, Correo, FechaRegistro FROM Candidato WHERE LOWER(Correo) = ?',
      [correo]
    );

    if (candidatoRows.length === 0) {
      return res.status(404).json({ error: 'No se encontró ningún candidato registrado con ese correo' });
    }

    const candidato = candidatoRows[0];

    const [postulaciones] = await pool.query(
      `
      SELECT IdPostulacion, IdCandidato, IdVacante, Estado, FechaPostulacion, UltimaActualizacion
      FROM Postulacion
      WHERE IdCandidato = ?
      ORDER BY UltimaActualizacion DESC, FechaPostulacion DESC
      `,
      [candidato.IdCandidato]
    );

    res.json({ candidato, postulaciones });
  } catch (err) {
    console.error('Error en GET /api/postulaciones/consulta:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/postulaciones/:id ─────────────────────────────────
// Admin y Reclutador.
app.get('/api/postulaciones/:id', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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
// Admin y Reclutador (actualizar_estado.html).
app.put('/api/postulaciones/:id/estado', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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
// Solo Candidato. Se permite crear una postulación sobre:
//   1. El propio perfil de candidato del usuario autenticado
//      (por IdUsuario, con fallback a correo para registros viejos), o
//   2. Un perfil de candidato SIN dueño (IdUsuario NULL), es decir, uno
//      registrado en nombre de un tercero vía "Postular a otra persona".
// Nunca se permite crear una postulación sobre el perfil de OTRA cuenta.
app.post('/api/postulaciones/crear-o-buscar', authenticateToken, authorizeRoles(ROLES.CANDIDATO), async (req, res) => {
  const { IdCandidato, IdVacante } = req.body;

  if (!IdCandidato) {
    return res.status(400).json({ error: 'IdCandidato es requerido' });
  }

  if (!IdVacante) {
    return res.status(400).json({ error: 'IdVacante es requerido' });
  }

  try {
    // Verificar que el candidato exista y que sea el propio dueño de la cuenta
    // o un perfil de tercero sin cuenta vinculada.
    const [candidatoRows] = await pool.query(
      'SELECT IdCandidato, Correo, IdUsuario FROM Candidato WHERE IdCandidato = ?',
      [IdCandidato]
    );

    if (candidatoRows.length === 0) {
      return res.status(404).json({ error: 'Candidato no encontrado' });
    }

    const candidato = candidatoRows[0];
    const esDuenoPorUsuario = candidato.IdUsuario !== null && candidato.IdUsuario !== undefined
      && Number(candidato.IdUsuario) === Number(req.user.id);
    const esDuenoPorCorreo = (req.user.correo || '').toLowerCase() === (candidato.Correo || '').toLowerCase();
    // Perfil sin cuenta vinculada = fue registrado por otra persona en su
    // nombre (vía "Postular a otra persona"). Cualquier candidato puede
    // crear una postulación para este tipo de perfil.
    const esPerfilSinDueno = candidato.IdUsuario === null || candidato.IdUsuario === undefined;

    if (!esDuenoPorUsuario && !esDuenoPorCorreo && !esPerfilSinDueno) {
      return res.status(403).json({ error: 'Solo puede postularse con su propio perfil de candidato' });
    }

    // Verificar que la vacante exista
    const [vacanteRows] = await pool.query(
      'SELECT IdVacante FROM Vacante WHERE IdVacante = ?',
      [IdVacante]
    );

    if (vacanteRows.length === 0) {
      return res.status(404).json({ error: 'La vacante seleccionada no existe' });
    }

    // Buscar si ya existe una postulación de ESTE candidato para ESTA
    // vacante puntual (un candidato puede postularse a varias vacantes
    // distintas; lo que no debe duplicarse es la misma vacante dos veces).
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
      WHERE IdCandidato = ? AND IdVacante = ?
      ORDER BY IdPostulacion DESC
      LIMIT 1
      `,
      [IdCandidato, IdVacante]
    );

    if (existente.length > 0) {
      return res.json({
        message: 'Postulación encontrada',
        postulacion: existente[0]
      });
    }

    // Crear postulación nueva para la vacante seleccionada
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

// ── GET /api/entrevistas ─────────────────────────────────────────
// Admin y Reclutador.
app.get('/api/entrevistas', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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

// Helper: trae una entrevista por id ya con los joins de candidato/vacante,
// para devolver siempre la misma "forma" de objeto en create/update.
async function obtenerEntrevistaConDetalle(idEntrevista) {
  const [rows] = await pool.query(
    `
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
      v.Titulo AS Vacante
    FROM Entrevista e
    LEFT JOIN Postulacion p ON e.IdPostulacion = p.IdPostulacion
    LEFT JOIN Candidato c ON p.IdCandidato = c.IdCandidato
    LEFT JOIN Vacante v ON p.IdVacante = v.IdVacante
    WHERE e.IdEntrevista = ?
    `,
    [idEntrevista]
  );
  return rows[0] || null;
}

// ── POST /api/entrevistas ─────────────────────────────────────────
// Admin y Reclutador. Crea una entrevista ligada a una Postulacion existente.
app.post('/api/entrevistas', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const { IdPostulacion, Fecha, Hora, Modalidad, Observaciones } = req.body;

  if (!IdPostulacion || !Fecha || !Hora) {
    return res.status(400).json({ error: 'IdPostulacion, Fecha y Hora son requeridos' });
  }

  try {
    const [postulacionRows] = await pool.query(
      'SELECT IdPostulacion FROM Postulacion WHERE IdPostulacion = ?',
      [IdPostulacion]
    );

    if (postulacionRows.length === 0) {
      return res.status(404).json({ error: 'La postulación indicada no existe' });
    }

    const [result] = await pool.query(
      'INSERT INTO Entrevista (IdPostulacion, Fecha, Hora, Modalidad, Observaciones) VALUES (?, ?, ?, ?, ?)',
      [IdPostulacion, Fecha, Hora, Modalidad || null, String(Observaciones || '').slice(0, 255)]
    );

    const entrevista = await obtenerEntrevistaConDetalle(result.insertId);
    res.status(201).json({ entrevista });
  } catch (err) {
    console.error('Error en POST /api/entrevistas:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── PUT /api/entrevistas/:id ────────────────────────────────────
// Admin y Reclutador.
app.put('/api/entrevistas/:id', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const { id } = req.params;
  const { IdPostulacion, Fecha, Hora, Modalidad, Observaciones } = req.body;

  if (!IdPostulacion || !Fecha || !Hora) {
    return res.status(400).json({ error: 'IdPostulacion, Fecha y Hora son requeridos' });
  }

  try {
    const [postulacionRows] = await pool.query(
      'SELECT IdPostulacion FROM Postulacion WHERE IdPostulacion = ?',
      [IdPostulacion]
    );

    if (postulacionRows.length === 0) {
      return res.status(404).json({ error: 'La postulación indicada no existe' });
    }

    const [result] = await pool.query(
      'UPDATE Entrevista SET IdPostulacion = ?, Fecha = ?, Hora = ?, Modalidad = ?, Observaciones = ? WHERE IdEntrevista = ?',
      [IdPostulacion, Fecha, Hora, Modalidad || null, String(Observaciones || '').slice(0, 255), id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Entrevista no encontrada' });
    }

    const entrevista = await obtenerEntrevistaConDetalle(id);
    res.json({ entrevista });
  } catch (err) {
    console.error('Error en PUT /api/entrevistas/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── DELETE /api/entrevistas/:id ─────────────────────────────────
// Admin y Reclutador.
app.delete('/api/entrevistas/:id', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query('DELETE FROM Entrevista WHERE IdEntrevista = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Entrevista no encontrada' });
    }

    res.json({ message: 'Entrevista eliminada correctamente' });
  } catch (err) {
    console.error('Error en DELETE /api/entrevistas/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/evaluaciones ────────────────────────────────────────
// Admin y Reclutador.
app.get('/api/evaluaciones', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
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

// ── POST /api/evaluaciones ───────────────────────────────────────
// Admin y Reclutador.
app.post('/api/evaluaciones', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  const { IdEntrevista, IdUsuario, Calificacion, Comentarios = '' } = req.body;

  if (!IdEntrevista || Calificacion === undefined || Calificacion === null) {
    return res.status(400).json({ error: 'IdEntrevista y Calificacion son requeridos' });
  }

  const calificacionNum = Number(Calificacion);

  if (Number.isNaN(calificacionNum) || calificacionNum < 1 || calificacionNum > 5) {
    return res.status(400).json({ error: 'La calificación debe estar entre 1 y 5' });
  }

  // Si no se envía IdUsuario explícito, se usa el usuario autenticado.
  const idUsuarioEvaluador = IdUsuario || req.user.id || 1;

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
        [idUsuarioEvaluador, calificacionNum, comentarioTexto, IdEntrevista]
      );
    } else {
      [result] = await pool.query(
        'INSERT INTO Evaluacion (IdEntrevista, IdUsuario, Calificacion, Comentarios, Fecha) VALUES (?, ?, ?, ?, CURDATE())',
        [IdEntrevista, idUsuarioEvaluador, calificacionNum, comentarioTexto]
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

// ── POST /api/usuarios (crear usuario por Admin) ─────────────────
app.post('/api/usuarios', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
  const { Nombre, Correo, Usuario: UsuarioName, Contrasena, IdRol } = req.body;

  if (!Nombre || !Correo || !UsuarioName || !Contrasena || !IdRol) {
    return res.status(400).json({ error: 'Todos los campos son requeridos' });
  }

  try {
    const hash = await bcrypt.hash(Contrasena, 10);
    const [result] = await pool.query(
      'INSERT INTO Usuario (Nombre, Correo, Usuario, Contrasena, IdRol, FechaRegistro) VALUES (?, ?, ?, ?, ?, NOW())',
      [Nombre, Correo, UsuarioName, hash, Number(IdRol)]
    );

    const [rows] = await pool.query('SELECT IdUsuario, Nombre, Correo, Usuario, IdRol, FechaRegistro FROM Usuario WHERE IdUsuario = ?', [result.insertId]);

    res.status(201).json({ usuario: rows[0] });
  } catch (err) {
    console.error('Error en POST /api/usuarios:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── GET /api/usuarios/candidatos-disponibles ─────────────────────
// Admin y Reclutador. Lista las cuentas con rol Candidato para poder
// vincularlas a un registro de Candidato desde el alta manual
// (registrar_candidato.html). Incluye un flag "Vinculado" para que el
// frontend pueda marcar/deshabilitar las cuentas que ya tienen un
// Candidato asociado (relación 1 a 1 vía IdUsuario). Debe ir declarada
// ANTES de '/api/usuarios/:id' o Express interpretaría
// "candidatos-disponibles" como un id.
app.get('/api/usuarios/candidatos-disponibles', authenticateToken, authorizeRoles(ROLES.ADMIN, ROLES.RECLUTADOR), async (req, res) => {
  try {
    const [rows] = await pool.query(`
      SELECT
        u.IdUsuario,
        u.Nombre,
        u.Correo,
        u.Usuario,
        (SELECT COUNT(*) FROM Candidato c WHERE c.IdUsuario = u.IdUsuario) AS VinculadoCount
      FROM Usuario u
      WHERE u.IdRol = ?
      ORDER BY u.Nombre ASC
    `, [ROLES.CANDIDATO]);

    const usuarios = rows.map((u) => ({
      IdUsuario: u.IdUsuario,
      Nombre: u.Nombre,
      Correo: u.Correo,
      Usuario: u.Usuario,
      Vinculado: Number(u.VinculadoCount) > 0,
    }));

    res.json(usuarios);
  } catch (err) {
    console.error('Error en GET /api/usuarios/candidatos-disponibles:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── Endpoints de administración de Usuarios (solo Admin) ─────────────────
// Panel de administración de usuarios/roles
app.get('/api/usuarios', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT IdUsuario, Nombre, Correo, Usuario, IdRol, FechaRegistro FROM Usuario ORDER BY IdUsuario DESC'
    );
    res.json(rows);
  } catch (err) {
    console.error('Error en GET /api/usuarios:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.get('/api/usuarios/:id', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      'SELECT IdUsuario, Nombre, Correo, Usuario, IdRol, FechaRegistro FROM Usuario WHERE IdUsuario = ? LIMIT 1',
      [id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('Error en GET /api/usuarios/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.put('/api/usuarios/:id', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
  const { id } = req.params;
  const { Nombre, Correo, Usuario: UsuarioName, IdRol, Contrasena } = req.body;

  if (!Nombre || !Correo || !UsuarioName || !IdRol) {
    return res.status(400).json({ error: 'Nombre, Correo, Usuario e IdRol son requeridos' });
  }

  try {
    // Si se envía contraseña, hashearla
    let params = [Nombre.trim(), Correo.trim(), UsuarioName.trim(), Number(IdRol), id];
    let query;

    if (Contrasena) {
      const hash = await bcrypt.hash(Contrasena, 10);
      query = 'UPDATE Usuario SET Nombre = ?, Correo = ?, Usuario = ?, IdRol = ?, Contrasena = ? WHERE IdUsuario = ?';
      params = [Nombre.trim(), Correo.trim(), UsuarioName.trim(), Number(IdRol), hash, id];
    } else {
      query = 'UPDATE Usuario SET Nombre = ?, Correo = ?, Usuario = ?, IdRol = ? WHERE IdUsuario = ?';
    }

    const [result] = await pool.query(query, params);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const [rows] = await pool.query('SELECT IdUsuario, Nombre, Correo, Usuario, IdRol, FechaRegistro FROM Usuario WHERE IdUsuario = ?', [id]);
    res.json({ usuario: rows[0] });
  } catch (err) {
    console.error('Error en PUT /api/usuarios/:id:', err.message);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

app.delete('/api/usuarios/:id', authenticateToken, authorizeRoles(ROLES.ADMIN), async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await pool.query('DELETE FROM Usuario WHERE IdUsuario = ?', [id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json({ message: 'Usuario eliminado correctamente' });
  } catch (err) {
    console.error('Error en DELETE /api/usuarios/:id:', err.message);
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