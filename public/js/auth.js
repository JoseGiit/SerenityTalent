// Helper for client-side auth UI and requests
(function(window){
  function getToken(){
    return localStorage.getItem('token') || localStorage.getItem('st_token') || null;
  }

  function parseJwt(token){
    try{
      const payload = token.split('.')[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decodeURIComponent(escape(decoded)));
    }catch(e){return null;}
  }

  function getUser(){
    const raw = localStorage.getItem('st_usuario') || null;
    if (raw) {
      try { return JSON.parse(raw); } catch(e) { }
    }

    const t = getToken();
    if(!t) return null;
    return parseJwt(t);
  }

  function fetchAuth(url, options){
    options = options || {};
    options.headers = options.headers || {};
    const t = getToken();
    if(t) options.headers['Authorization'] = 'Bearer ' + t;
    return fetch(url, options);
  }

  function applyRoleVisibility(){
    const user = getUser();
    // Support different shapes: { rol } from JWT payload or { IdRol } from API user object
    let role = null;
    if (user) {
      if (user.rol !== undefined) role = Number(user.rol);
      else if (user.IdRol !== undefined) role = Number(user.IdRol);
      else if (user.idRol !== undefined) role = Number(user.idRol);
    }
    document.querySelectorAll('[data-role-show]').forEach(el => {
      const allowed = String(el.getAttribute('data-role-show')).split(',').map(s=>Number(s.trim()));
      if(role !== null && allowed.includes(role)) el.style.display = '';
      else el.style.display = 'none';
    });
    document.querySelectorAll('[data-role-hide]').forEach(el => {
      const hide = String(el.getAttribute('data-role-hide')).split(',').map(s=>Number(s.trim()));
      if(role !== null && hide.includes(role)) el.style.display = 'none';
      else el.style.display = '';
    });
  }

  function logout(){
    localStorage.removeItem('token');
    window.location.href = '/index.html';
  }

  window.Auth = {
    getToken, getUser, fetchAuth, applyRoleVisibility, logout
  };

  document.addEventListener('DOMContentLoaded', applyRoleVisibility);
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof window.renderHeaderUser === 'function') {
      try { window.renderHeaderUser(); } catch (e) { /* ignore */ }
    }
  });
})(window);
