window.Portalink = (() => {
  let csrf = "";

  async function obtenerSesion(rolEsperado) {
    const respuesta = await fetch("api_portalink.php", {
      headers: { Accept: "application/json" },
      cache: "no-store"
    });
    const resultado = await respuesta.json();

    if (!respuesta.ok || !resultado.success) {
      location.replace("iniciarsesion.html");
      throw new Error(resultado.message || "Tu sesión expiró.");
    }

    if (rolEsperado && resultado.rol !== rolEsperado) {
      const destinos = {
        admin: "ADMINISTRADOR.html",
        orientador: "inicioAdm.html",
        estudiante: "inicioEstu.html"
      };
      location.replace(destinos[resultado.rol] || "iniciarsesion.html");
      throw new Error("Esta página no corresponde a tu tipo de cuenta.");
    }

    csrf = resultado.csrf;
    return resultado;
  }

  async function api(accion, datos = {}) {
    const respuesta = await fetch("api_portalink.php", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify({ accion, ...datos })
    });
    const resultado = await respuesta.json();

    if (respuesta.status === 401) {
      location.replace("iniciarsesion.html");
    }

    if (!respuesta.ok || !resultado.success) {
      throw new Error(resultado.message || "No se pudo completar la solicitud.");
    }

    return resultado;
  }

  async function cerrarSesion() {
    await api("cerrar_sesion");
    location.replace("iniciarsesion.html");
  }

  function escapar(valor) {
    return String(valor ?? "").replace(/[&<>"']/g, (caracter) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    })[caracter]);
  }

  function fechaLocal(valor) {
    return new Date(String(valor).replace(" ", "T"));
  }

  function fechaLegible(valor, opciones = {}) {
    const fecha = fechaLocal(valor);
    if (Number.isNaN(fecha.getTime())) return "Fecha pendiente";
    return new Intl.DateTimeFormat("es", opciones).format(fecha);
  }

  function mostrarMensaje(elemento, texto, tipo = "error") {
    elemento.textContent = texto;
    elemento.className = `mensaje ${tipo}`;
    elemento.hidden = false;
  }

  return {
    api,
    cerrarSesion,
    escapar,
    fechaLegible,
    fechaLocal,
    mostrarMensaje,
    obtenerSesion
  };
})();
