# sshvault

Gestor local de claves SSH, certificados, hosts y ficheros de `~/.ssh`, con todo el estado dentro de un único fichero cifrado y portable.

```text
$ sshvault
Ok! Serving http://localhost:7000
```

Abre esa URL en el navegador. La app se sirve solo en loopback y muestra el desbloqueo o la creación del vault en su propia interfaz.

## Qué hace

- **Keys**: claves públicas, privadas y certificados, con alias, tags, huella y estado local. Permite copiar, editar, generar pares ed25519/RSA/ECDSA, desplegar en `~/.ssh` y retirarlos.
- **Hosts**: entradas de `~/.ssh/config` con `Host`, `HostName`, `User`, `Port`, varios `IdentityFile` y opciones avanzadas ordenadas. Previsualiza el bloque y copia el comando `ssh`.
- **Files**: otros ficheros de `~/.ssh`, como `known_hosts` o `authorized_keys`, con edición de texto o binario, descarga, despliegue y avisos para ficheros sensibles.
- **Importación**: escanea `~/.ssh`, detecta claves, certificados, hosts y ficheros, y los añade al vault sin modificar nada hasta que lo confirmas. Empareja privada y pública por el nombre base antes de `.pub`, aunque la pública tenga sufijos como `.old` o `.crdownload`: `foo` + `foo.pub.old` forma una clave `foo`; un `foo.pub.old` huérfano se importa como clave pública `foo`; y `foo.old` + `foo.pub.old` produce una clave privada `foo.old` y una pública `foo`.
- **Resolver duplicados**: detecta entradas `Host` definidas a la vez dentro y fuera del bloque gestionado. Permite comentar el bloque antiguo, eliminarlo con backup o conservar solo los patrones no duplicados, siempre uno a uno.
- **Interfaz**: tablas HTML nativas y componentes [Sumi.css](https://github.com/vladocar/Sumi.css) vendorizados, con tema **Sistema / Claro / Oscuro** desde Ajustes.
- **Ficheros internos**: los nombres que contienen `.vault` (el propio vault, su `.lock`, backups, etc.) se excluyen del escaneo y de Files. Si ya estaban importados, se ocultan y se pueden quitar del vault sin tocar el fichero real.
- **Bloqueo por inactividad**: por defecto 15 minutos. Al bloquear, la clave derivada se descarta de memoria y la web pide la contraseña de nuevo.
- **Cambio de contraseña**: re-cifra el vault con un salt nuevo.
- **Abrir otro vault**: desde la pantalla de bloqueo o Settings puedes cargar un `ssh.vault` existente de cualquier carpeta. En `--ui` se usa el diálogo nativo; en navegador se escribe la ruta.
- **Desbloqueo web**: al arrancar, el servidor queda bloqueado y la UI pide la contraseña. Si el vault no existe, ofrece crearlo. `--change-password` sigue siendo una operación de terminal.

## Instalación

Requiere Go 1.27.1 o superior. Glaze es CGo-free, así que no hace falta compilador de C.

```bash
go build -o sshvault ./cmd/sshvault
# o
make build
```

También puedes usar `go install ./cmd/sshvault`.

### Homebrew (macOS)

```bash
brew tap lucasmenendez/sshvault
# Homebrew 7 o superior: autorizar el tap de terceros
brew trust lucasmenendez/sshvault
brew install sshvault
sshvault --ui
```

El tap contiene la fórmula publicada automáticamente desde los releases del proyecto.

Solo macOS y Linux. El binario usa `flock`, permisos POSIX y symlinks. La UI nativa de `--ui` usa el WebView del sistema: WKWebView en macOS y WebKitGTK en Linux. En Linux hay que tener instalado WebKitGTK (`libwebkit2gtk-4.1-0` en Debian/Ubuntu, por ejemplo).

## Uso

```bash
# Vault por defecto: ~/.ssh/ssh.vault
./sshvault

# Ruta explícita
./sshvault -f ./trabajo.vault
./sshvault ./trabajo.vault

# Directorio SSH alternativo (útil para pruebas)
# El vault por defecto pasa a /tmp/ssh-test/ssh.vault
./sshvault --ssh-dir /tmp/ssh-test

# Si existe ./ssh.vault pero no ~/.ssh/ssh.vault, no se abre solo:
./sshvault -f ./ssh.vault

# Otro puerto, y abrir el navegador
./sshvault --addr 127.0.0.1:8080 --open

# UI nativa (Glaze), sin navegador externo
./sshvault --ui

# Cambiar la contraseña y salir
./sshvault --change-password
```

Sin `-f` ni argumento posicional, el CLI usa `~/.ssh/ssh.vault`; con `--ssh-dir /ruta`, usa `/ruta/ssh.vault`. No hay fallback automático a `./ssh.vault`: si existe, se muestra un aviso y puedes abrirlo desde la propia web con **Open existing vault…** o con `-f ./ssh.vault`.

El CLI ya no pide la contraseña por terminal en el arranque normal. Arranca el servidor bloqueado y la web app pide la contraseña; si el fichero no existe, ofrece crearlo. `--change-password` sigue siendo una operación explícita de terminal.

### Flags

| Flag | Descripción |
| --- | --- |
| `-f`, `--file` | Ruta del vault. Por defecto `~/.ssh/ssh.vault`, o `<ssh-dir>/ssh.vault` si se usa `--ssh-dir`. |
| `--ssh-dir` | Directorio SSH a gestionar. Por defecto `~/.ssh`. |
| `--addr` | Dirección de escucha. Solo loopback: `127.0.0.1`, `::1` o `localhost`. |
| `--lock-after` | Duración de inactividad antes de bloquear. `0` lo desactiva. |
| `--open` | Abre la URL en el navegador por defecto. Incompatible con `--ui`. |
| `--ui` | Abre la UI en una ventana nativa con Glaze. Incompatible con `--open` y `--change-password`. |
| `--change-password` | Cambia la contraseña y sale por terminal. |
| `--version` | Muestra la versión. |

## Seguridad

- **Cifrado**: Argon2id (64 MiB, 3 pasadas, 4 hilos) + XChaCha20-Poly1305. La cabecera va autenticada como AAD.
- **Formato versionado**: magic, versión, parámetros KDF, salt, nonce y ciphertext. Los parámetros KDF se validan al abrir para evitar consumos abusivos.
- **Escritura atómica** y backups cifrados rotativos del vault.
- **Permisos**: vault `0600`, claves privadas `0600`, públicas/certificados `0644`, `~/.ssh` `0700` si se crea.
- **Loopback only**: la web no se expone a la red. Se validan `Host`, `Origin`, `Sec-Fetch-Site` y `Content-Type` para mitigar CSRF y DNS rebinding.
- **CSP estricta**, sin CDNs ni recursos externos.
- **Sin token**: cualquier usuario local podría acceder mientras el vault esté desbloqueado. Usa el bloqueo por inactividad y no lo dejes corriendo en servidores compartidos.
- **Sin recuperación**: si pierdes la contraseña, no hay forma de abrir el vault. Los backups están cifrados con la misma contraseña.
- **Secretos en memoria**: Go no permite borrar strings de forma fiable. Al bloquear/salir se descarta la clave derivada y el documento descifrado, pero el proceso pudo haber materializado strings de claves privadas. No ejecutes la app en un equipo no confiable.
- **Portapapeles**: copiar una clave privada la deja disponible para otros procesos. La app pide confirmación y avisa.

## Modelo de despliegue

El vault es la fuente de verdad para las entradas que gestiona; `~/.ssh` es el destino.

- Cada clave guarda un `filename` estable. Las nuevas usan `id_<alias>`; las importadas conservan su nombre.
- Rutas: `~/.ssh/<filename>`, `<filename>.pub` y `<filename>-cert.pub`.
- Los hosts viven en un **bloque gestionado** al principio de `~/.ssh/config`, delimitado por marcadores. El resto del fichero no se toca.
- El bloque va al principio porque OpenSSH usa el primer valor que encuentra; así las entradas específicas tienen prioridad sobre los `Host *` del final.
- Editar una entrada desplegada la sincroniza en local. Si el fichero local cambió fuera de la app, se marca **drift** y no se sobrescribe sin confirmación.
- Los ficheros no gestionados se detectan y se pueden importar, pero nunca se borran automáticamente.
- Borrar una entrada del vault pregunta si quieres borrar también su copia local.

## Filas y acciones

- Las tablas usan HTML nativo (`table`, `thead`, `tbody`, `tr`, `th`, `td`) con la columna de acciones fija a la derecha; la cabecera y las celdas comparten el mismo borde.
- Clic en una fila de **Keys**, **Hosts** o **Files** abre el modal unificado para consultar, editar y eliminar.
- El checkbox sigue seleccionando para acciones masivas.
- `Enter` o `Espacio` sobre una fila enfocada también abre el modal.
- Acciones de fila:
  - **Keys**: menú `Copiar` + `Desplegar` / `Quitar local`.
  - **Hosts**: menú `Comando` + `Desplegar` / `Quitar local`.
  - **Files**: `Descargar` + `Desplegar` / `Quitar local`.
- En estado de conflicto/drift: `Resolver`.
- Editar y eliminar están dentro del modal, no en la fila.

### Resolver duplicados

Si un host está en el bloque gestionado y también fuera de él, la app muestra un aviso. El resolvedor:

- Enseña los bloques uno a uno.
- Por defecto **comenta** el bloque antiguo con `# `, que es reversible.
- Permite **eliminarlo** con una segunda confirmación y un backup.
- Si el bloque exterior tiene varios patrones y solo algunos están duplicados, permite **conservar los no duplicados** reescribiendo la línea `Host`.
- No toca el bloque gestionado.
- Comprueba un hash del config antes de escribir; si el fichero cambió, aborta y recarga.

Solo se tienen en cuenta hosts ya desplegados. Los hosts importados pero no desplegados no generan duplicado todavía.

### Ficheros internos

- Se excluyen del escaneo y de Files todos los nombres que contienen `.vault`, además del vault real, su `.lock` y sus `.bak.*`.
- Si el vault ya contiene entradas de Files con esos nombres, se ocultan y aparece un aviso para quitarlas del vault.
- Esa limpieza **no borra el fichero real** de disco.

## Interfaz

- Base visual: [Sumi.css](https://github.com/vladocar/Sumi.css) v1.0.0, vendorizado en `internal/web/static/sumi.css` (MIT, sin CDN).
- Tokens `--s-*`: el tema oscuro usa `--s-bg:#000`, `--s-surface:#2e2e2e`, `--s-card:#121212` y `--s-radius:0`; el claro invierte la escala manteniendo el contraste.
- Selector **Sistema / Claro / Oscuro** en Ajustes. Se guarda en `localStorage`; `Sistema` sigue `prefers-color-scheme`.
- Modales `<dialog><article>`, botones y formularios sobre la base de Sumi. Las tablas y la columna de acciones no duplican bordes ni sombras.
- Los menús **Copiar** y **Comando** son dropdowns de Sumi (`<details class="dropdown">`); el panel se monta en `body` al abrirse para quedar por encima de la tabla.

## Cambios 0.7.3

- En el layout responsive, todas las opciones del menú quedan alineadas a la izquierda y consecutivas.
- Se elimina el reparto automático de espacio (`space-between`) entre Keys/Hosts/Files y Settings/Lock.
- Con etiquetas o en modo solo iconos, los elementos mantienen el mismo orden y una separación uniforme.
- El menú no hace wrap: si no cabe, la barra superior se desplaza horizontalmente.
- En móviles de 360 px todas las opciones caben sin recortes.

## Cambios 0.7.2

- La cabecera principal y el toolbar de cada vista quedan fijos.
- La cabecera de las tablas (`thead`) es sticky dentro del área de la lista.
- Solo se desplaza la zona de filas; la sidebar y el logo permanecen fijos.
- Settings usa su propio scroll y mantiene la cabecera visible.
- Se elimina el scroll del `body` para evitar dobles scrolls y desplazamientos de la sidebar.
- Se mantiene el layout responsive: en ventanas estrechas la sidebar pasa arriba y el contenido sigue siendo el área de scroll.

## Cambios 0.7.1

- En la ventana nativa, solo hace scroll el contenido principal; la sidebar y el logo quedan fijos bajo la titlebar, sin desplazarse hacia los controles de la ventana.
- La columna de acciones es más ancha y los botones de fila tienen un espaciado más compacto. `Command`, `Download`, `Copy` y `Remove local` ya caben en su columna sin invadir la columna de estado.

## Cambios 0.7.0

- El arranque normal ya no pide la contraseña por terminal: el servidor arranca bloqueado y la web app muestra el modal de desbloqueo. Aplica a `sshvault`, `--open` y `--ui`.
- Si el vault no existe, la web app ofrece crearlo con contraseña y confirmación.
- La pantalla de bloqueo y Settings incluyen **Open existing vault…** para abrir un `ssh.vault` de cualquier carpeta.
- En `--ui`, el selector de fichero usa el diálogo nativo de Glaze; en navegador se puede escribir la ruta.
- El vault activo se puede cambiar sin reiniciar; el anterior se cierra y se libera su lock.
- `--change-password` sigue siendo una operación de terminal.

## Cambios 0.6.0

- Nuevo flag `--ui`: arranca el servidor actual y abre una ventana nativa con Glaze.
- `--ui` conserva el servidor, el puerto, la sesión y el apagado ordenado; al cerrar la ventana se apaga el servidor.
- En macOS la ventana usa titlebar transparente, contenido full-size y los botones del sistema integrados sobre el fondo de la app.
- Glaze es CGo-free; el proyecto pasa a requerir Go 1.27.1.
- `--open` sigue abriendo el navegador y es incompatible con `--ui`.
- En Linux, `--ui` necesita WebKitGTK en tiempo de ejecución.

## Cambios 0.5.0

- Toda la interfaz web está en inglés.
- El vault por defecto del CLI es `~/.ssh/ssh.vault`; con `--ssh-dir` es `<ssh-dir>/ssh.vault`.
- `-f`/`--file` y el argumento posicional siguen teniendo prioridad. Si existe `./ssh.vault` pero no el vault por defecto, no se abre automáticamente: se muestra un aviso.
- El primer arranque con el vault por defecto crea `~/.ssh` con permisos `0700` si hace falta.

## Cambios 0.4.1

- El buscador y el botón de filtro comparten altura y línea base en Keys, Hosts y Files.
- Los menús de fila **Copiar** y **Comando** usan el disclosure `<details class="dropdown">` de Sumi; el panel se monta en `body` para no quedar recortado por la tabla.
- Corregida la apertura del editor de hosts que tienen opciones avanzadas.

## Cambios 0.4.0

- Importación: emparejamiento por nombre base antes de `.pub`, incluidos sufijos como `.old` y `.crdownload`; las públicas huérfanas se importan como claves.
- Tablas HTML nativas y corrección del borde en la columna de acciones.
- Migración visual a Sumi.css con los tokens oscuros del proyecto, tema claro inverso y selector Sistema/Claro/Oscuro.

## Backups

- El vault guarda hasta 5 copias cifradas: `<vault>.bak.<timestamp>`.
- Antes de reescribir `~/.ssh/config` o un fichero gestionado se guarda una copia en `~/.ssh/.sshvault-backups/` (hasta 20).
- Las claves privadas no se copian en claro a los backups locales; su versión anterior sigue en los backups cifrados del vault.

## Licencia

sshvault se distribuye bajo **GNU Affero General Public License v3.0 only** (`AGPL-3.0-only`). El texto completo está en [LICENSE](LICENSE). El código fuente de cada release está disponible en el tag correspondiente del repositorio.

Sumi.css se mantiene bajo su licencia MIT original; su aviso está en la cabecera de `internal/web/static/sumi.css`.

## Desarrollo

```bash
make test
make vet
make build
```

La UI es una SPA sin build: HTML, CSS y JavaScript embebidos con `go:embed`. No necesita Node para compilar ni ejecutar. El CSS base de Sumi.css está vendorizado; al actualizarlo, conserva su cabecera de licencia MIT.

## Limitaciones conocidas

- No se firman certificados desde la app; se almacenan, importan y despliegan.
- `Include` y `Match` en configs existentes se preservan fuera del bloque, pero no se gestionan desde la UI.
- Los directorios dentro de `~/.ssh` no se gestionan.
- Sin soporte Windows.
- Límite de 4 MiB por fichero y 32 MiB de vault.
- Si el vault está en un sistema de ficheros sin `flock` fiable, el bloqueo entre procesos puede no funcionar.
