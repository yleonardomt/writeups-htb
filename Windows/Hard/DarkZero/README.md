# DarkZero (HTB) — Writeup **Redactado** (Metodología + Lecciones)

> **Spoiler policy / Nota:** Esta máquina es **Active Directory** y (si está activa en HTB) no corresponde publicar un walkthrough completo con *flags, credenciales, hashes, tickets, payloads* ni comandos “copy-paste” que dejen el dominio comprometido.  
> Este documento está **redactado** a propósito: explica **qué hice, por qué funcionó y qué aprender**, + recomendaciones defensivas.

---

## 🧾 Resumen Ejecutivo

**DarkZero** fue un escenario avanzado de **Active Directory** donde el camino de compromiso combinó:

- **Acceso inicial** mediante **MSSQL** (autenticado) en un DC/servidor con SQL expuesto.
- **Pivot** usando **Linked Servers** (confianza cruzada) hacia un segundo host/segmento.
- **Ejecución remota** desde SQL (funcionalidad peligrosa mal controlada).
- **Escalada local a SYSTEM** por una debilidad/vulnerabilidad del host (privesc).
- **Robo de credenciales** (secretos locales/LSA) y abuso de **Kerberos**.
- Abuso de permisos/condiciones para **replicación** (**DCSync**) y compromiso de dominio.

**Cadena (alto nivel):**  
Recon → MSSQL → Linked Server → RCE en host remoto → SYSTEM → Creds → Kerberos/Tickets → DCSync → **Domain Compromise**

---

## 📌 Información de la máquina

- **Plataforma:** Hack The Box  
- **Nombre:** DarkZero  
- **Dificultad:** Hard  
- **SO:** Windows (Active Directory)  
- **Tags:** AD, MSSQL, Kerberos, Lateral Movement, PrivEsc, DCSync

---

## 🗂️ Tabla de Contenido

1. Reconocimiento
2. Acceso inicial (MSSQL)
3. Hallazgo clave: Linked Servers
4. Movimiento lateral (pivot por SQL)
5. Escalada de privilegios local (SYSTEM)
6. Post-explotación: credenciales y contexto de dominio
7. Kerberos: tickets y abuso de confianza
8. DCSync: extracción de secretos del dominio (concepto)
9. Mitigaciones y recomendaciones defensivas
10. Lecciones aprendidas

---

## 1) 🔎 Reconocimiento

### 1.1 Enumeración de red (qué busqué)
En un AD “clásico” me interesa ver:

- **DNS / Kerberos / LDAP / SMB** (señales de DC)
- **MSSQL (1433)** (vector común cuando hay cuentas válidas)
- **WinRM (5985)** (para sesión remota si logro credenciales buenas)

**Hallazgos (resumido):**
- Servicios típicos de AD visibles.
- **MSSQL** accesible → se convirtió en el vector principal.

> **Por qué importa:** si SQL está expuesto y tengo una cuenta válida, puedo enumerar permisos, configuraciones peligrosas y relaciones de confianza (como linked servers).

---

## 2) 🔐 Acceso inicial (MSSQL)

Entré al SQL con autenticación de Windows (cuenta de dominio de bajo privilegio).

### 2.1 Objetivo dentro de SQL
Una vez dentro, mis prioridades fueron:

- Ver **contexto** (quién soy / qué rol tengo).
- Enumerar **configuración** (features peligrosas).
- Buscar **linked servers** (esto fue lo decisivo).

> **Idea clave:** en entornos AD, SQL muchas veces termina siendo un *puente* hacia otros sistemas por mala segmentación o malas confianzas.

---

## 3) ⭐ Hallazgo clave: Linked Servers (la pieza que lo rompió todo)

### 3.1 ¿Qué es un Linked Server?
Es una funcionalidad de SQL que permite que un servidor SQL consulte/ejecute cosas en **otro** servidor SQL “remoto”.  
El problema es que, si está mal configurado, puede crear:

- **Saltos de confianza** invisibles para el equipo (pivot).
- Ejecución bajo otra identidad (por ejemplo, una **service account**).
- Acceso a otro segmento/red donde yo no debería estar.

### 3.2 Lo que encontré
Había un linked server apuntando a otro host/segmento, y el mapeo implicaba que mi login terminaba operando como una cuenta de servicio remota.

> **Resultado:** “mi usuario humilde” se volvió un **trampolín** hacia un segundo sistema con un contexto más fuerte.

---

## 4) 🧭 Movimiento lateral (pivot por SQL)

### 4.1 Estrategia
Usé el linked server para:

1. Ejecutar consultas en el servidor remoto.
2. Habilitar una vía de ejecución remota (feature peligrosa) **si el contexto lo permitía**.
3. Probar ejecución con comandos inofensivos (ver identidad y permisos).
4. Preparar una sesión interactiva (reverse shell / sesión remota) **sin dejar un desastre**.

> **Redacción importante:** omito comandos exactos y payloads listos, pero el concepto es: *si SQL puede ejecutar comandos del sistema, SQL se vuelve RCE*.

### 4.2 Validación
Confirmé que la ejecución en el host remoto corría como una **cuenta de servicio** (no como mi usuario original).

**Esto explica el salto de privilegio “indirecto”:**
- No escalé mi usuario.
- Aproveché una **mala confianza** que me ejecutó como alguien mejor.

---

## 5) ⬆️ Escalada local a SYSTEM (privesc)

Ya con ejecución en el host remoto, lo siguiente fue:

- Enumerar **versión de Windows**, parches, privilegios, y vectores conocidos.
- Encontrar una ruta de privesc viable (en este caso: **un exploit local** aplicable al build).

**Resultado:** pasé a **NT AUTHORITY\\SYSTEM**.

> **Por qué es crítico:** SYSTEM me abre puertas a *cred dumping*, secretos del sistema, tickets y material sensible que antes no podía tocar.

---

## 6) 🧠 Post-explotación: credenciales y contexto de dominio

Con SYSTEM enfoqué en:

- **Credenciales en memoria / LSA Secrets**
- Tokens, sesiones, cuentas de servicio
- Identificar **máquinas y relaciones de confianza** (dominios/forests)

Esto me dio material para el siguiente paso: **Kerberos**.

---

## 7) 🎟️ Kerberos: tickets y abuso de confianza

### 7.1 Qué intenté
En Kerberos, un ticket puede representar identidad y acceso. Yo quería:

- Obtener/capturar tickets que me den acceso más alto.
- Validar si existían **condiciones de delegación** o confianza que pudiera abusar.

### 7.2 Hallazgo en confianza (alto nivel)
Al enumerar trusts, apareció un atributo de confianza que habilitaba escenarios peligrosos (delegación / TGT).

> **Interpretación:** había una ruta para lograr que un sistema “privilegiado” terminara autenticándose y yo pudiera reutilizar ese material.

### 7.3 Coerción de autenticación (concepto)
En vez de “esperar” a que ocurra, forcé un evento para provocar autenticación desde un equipo objetivo hacia donde yo podía observar.

- **Idea:** “haz que X se autentique contra Y”
- **Luego:** capturar/usar el material resultante (según el caso)

> De nuevo: omito el copy-paste exacto. Lo importante es entender **la lógica**.

---

## 8) 🧬 DCSync (concepto) → Compromiso de dominio

### 8.1 ¿Qué es DCSync?
DCSync es un abuso donde, si una identidad tiene permisos de replicación, puede pedirle al DC los secretos (hashes/keys) como si fuera otro DC.

### 8.2 Qué permitió que funcione
Con el material Kerberos adecuado (y/o credenciales obtenidas en post-explotación), logré ejecutar una operación equivalente a “replicar secretos”.

**Resultado:** obtuve hashes/keys de cuentas críticas → con eso, el dominio quedó comprometido.

---

## 9) 🛡️ Mitigaciones y recomendaciones defensivas

### 9.1 SQL Server (alto impacto)
- **Revisar y minimizar Linked Servers** (si no es imprescindible, eliminarlo).
- Restringir severamente identidades usadas en linked servers (**no** cuentas poderosas).
- Deshabilitar features de ejecución de comandos del SO si existen (o controlarlas con políticas/monitoring).
- Auditoría y alertas: consultas remotas inusuales, cambios de configuración, ejecución sospechosa.

### 9.2 Active Directory / Kerberos
- Revisar trusts y configuraciones de **delegación** (evitar opciones peligrosas sin necesidad).
- Monitorear eventos de Kerberos (tickets anómalos, patrones raros, time skew).
- Proteger cuentas de alto valor (tiering, Protected Users cuando aplique).
- Reducir permisos de replicación: **nadie** debería poder replicar secretos “porque sí”.

### 9.3 Endpoint / Detección
- EDR: detección de *credential dumping*, acceso a LSASS, ejecución anómala.
- Reglas SIEM para actividades de replicación, autenticaciones cruzadas, cambios de configuración.

---

## 10) ✅ Lecciones aprendidas

- **Linked Servers** mal configurados son básicamente **puentes** para romper segmentación.
- SQL “solo es base de datos” es un mito: puede ser un **orquestador de movimiento lateral**.
- Si llegas a **SYSTEM**, el juego cambia: credenciales, tickets y secretos se vuelven alcanzables.
- Kerberos + trusts mal gestionados = **escenario perfecto** para escaladas a nivel dominio.
- La defensa real es **capas**: hardening + segmentación + monitoreo + privilegio mínimo.

---

## 🧰 Herramientas (mencionadas sin abuso)
- Escaneo/Recon: Nmap (u equivalente)
- AD enum: herramientas tipo PowerView / LDAP enum
- SQL: clientes MSSQL (e.g., Impacket)
- Post-ex: herramientas de análisis de credenciales/tickets (concepto)


