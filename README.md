# audit_browsers_redacted

Auditoría **segura** de perfiles de navegador (Chrome / Edge / Firefox).  
Este script inspecciona las bases de datos locales de los navegadores en **modo solo lectura** y genera un reporte con métricas sin exponer datos sensibles.

---

## ✨ Funcionalidad

- Abre perfiles **solo lectura** (no modifica nada).
- Detecta y lista bases de datos comunes de navegadores:
  - Cookies
  - Login Data
  - Web Data
  - Places.sqlite (historial Firefox)
  - logins.json (Firefox)
- Muestra solo:
  - Nombre de tablas
  - Número de filas
  - Para datos sensibles (cookies / logins):
    - Longitud
    - Hash HMAC-SHA256 truncado (correlación local, no reversible).
- Exporta un reporte en **JSON** (`audit_report.json`).

⚠️ **Nunca descifra ni expone contraseñas o cookies en claro.**

---

## 🚀 Uso

```bash
python audit_browsers_redacted.py
