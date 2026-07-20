
(function(window){
  function getToken(){
    return localStorage.getItem('st_token') || localStorage.getItem('token') || null;
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

  function getRole(){
    const user = getUser();
    if (!user) return null;
    if (user.rol !== undefined) return Number(user.rol);
    if (user.IdRol !== undefined) return Number(user.IdRol);
    if (user.idRol !== undefined) return Number(user.idRol);
    return null;
  }

  function fetchAuth(url, options){
    options = options || {};
    options.headers = options.headers || {};
    const t = getToken();
    if(t) options.headers['Authorization'] = 'Bearer ' + t;
    return fetch(url, options);
  }

  function applyRoleVisibility(){
    const role = getRole();
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

  
  
  
  function clearSession(){
    localStorage.removeItem('token');
    localStorage.removeItem('st_token');
    localStorage.removeItem('st_usuario');
  }

  function logout(){
    clearSession();
    window.location.href = '/index.html';
  }

  
  
  
  
  
  function handleApiError(response, options){
    if (response.status === 401) {
      clearSession();
      window.location.href = 'index.html';
      return true;
    }
    if (response.status === 403) {
      showAccessDeniedAlert(
        (options && options.message) || 'Tu sesión sigue activa, pero tu rol no tiene acceso a esta sección.',
        (options && options.redirectUrl) || 'vacantes.html'
      );
      return true;
    }
    return false;
  }

  
  
  
  
  
  
  
  
  
  
  
  
  async function requireRole(rolesPermitidos, opts){
    const user = getUser();
    if (!user) {
      
      window.location.href = (opts && opts.loginUrl) || 'index.html';
      return false;
    }
    const role = getRole();
    if (role === null || !rolesPermitidos.includes(role)) {
      showAccessDeniedAlert(
        (opts && opts.message) || 'No tenés permiso para ver esta página con tu rol actual.',
        (opts && opts.redirectUrl) || 'vacantes.html',
        opts
      );
      return false;
    }
    return true;
  }

  function showAccessDeniedAlert(message, redirectUrl, options){
    const settings = Object.assign({ title: 'Acceso restringido', redirectDelay: 0, fallbackUrl: redirectUrl || 'vacantes.html' }, options || {});
    if (!document.body) {
      window.location.href = settings.fallbackUrl;
      return;
    }

    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-[9999] bg-black/50 backdrop-blur-sm flex items-center justify-center px-4';
    overlay.innerHTML = `
      <div class="w-full max-w-md rounded-2xl border border-outline-variant bg-surface-container-lowest p-6 shadow-2xl">
        <div class="flex items-center gap-3 mb-4">
          <div class="flex h-12 w-12 items-center justify-center rounded-full bg-primary/10 text-primary">
            <span class="material-symbols-outlined text-2xl">lock</span>
          </div>
          <div>
            <h3 class="text-lg font-bold text-on-surface">${settings.title}</h3>
            <p class="text-sm text-on-surface-variant">Solo para el rol adecuado</p>
          </div>
        </div>
        <p class="text-sm leading-6 text-on-surface-variant">${message}</p>
        <div class="mt-5 flex items-center justify-end gap-3">
          <button type="button" class="rounded-lg border border-outline-variant px-4 py-2 text-sm font-semibold text-on-surface-variant hover:bg-surface-container transition-all" data-action="back">Volver</button>
          <span class="rounded-full bg-primary/10 px-3 py-1 text-sm font-semibold text-primary">Volviendo…</span>
        </div>
      </div>`;

    document.body.appendChild(overlay);

    const redirectToSafePage = () => {
      const previousPage = document.referrer && document.referrer.includes(window.location.origin)
        ? new URL(document.referrer).pathname.replace(/^\//, '')
        : '';
      const destination = previousPage || settings.fallbackUrl || 'vacantes.html';
      if (destination && destination !== window.location.pathname.replace(/^\//, '')) {
        window.location.href = destination;
      } else {
        window.history.back();
      }
    };

    overlay.querySelector('[data-action="back"]').addEventListener('click', redirectToSafePage);

    if (settings.redirectDelay > 0) {
      setTimeout(() => {
        overlay.remove();
        redirectToSafePage();
      }, settings.redirectDelay);
    }
  }

  window.Auth = {
    getToken, getUser, getRole, fetchAuth, applyRoleVisibility, logout,
    handleApiError, requireRole
  };
  window.showAccessDeniedAlert = showAccessDeniedAlert;

  document.addEventListener('DOMContentLoaded', applyRoleVisibility);
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof window.renderHeaderUser === 'function') {
      try { window.renderHeaderUser(); } catch (e) {  }
    }
  });
})(window);