const fs = require('fs');
const path = require('path');
const assert = require('assert');

const root = path.join(__dirname, '..');

function read(file) {
  return fs.readFileSync(path.join(root, file), 'utf8');
}

const server = read('server.js');
assert.match(server, /ADMIN:\s*1/);
assert.match(server, /RECLUTADOR:\s*2/);
assert.match(server, /CANDIDATO:\s*3/);

const index = read('public/index.html');
assert.match(index, /if \(rol === 1 \|\| rol === 2\) return 'candidatos\.html';/);
assert.match(index, /if \(rol === 3\) return 'vacantes\.html';/);

const candidatos = read('public/candidatos.html');
assert.match(candidatos, /if \(rol !== 1 && rol !== 2\)/);
assert.match(candidatos, /data-role-show="1,2"/);
assert.match(candidatos, /data-role-show="1"[^>]*href="admin_usuarios\.html"|href="admin_usuarios\.html"[^>]*data-role-show="1"/);

const auth = read('public/js/auth.js');
assert.match(auth, /history\.back\(|document\.referrer/);

const entrevistas = read('public/entrevistas.html');
assert.match(entrevistas, /window\.__accessDenied\s*=\s*true/);
assert.match(entrevistas, /__accessDenied/);

console.log('Role mapping checks passed.');
