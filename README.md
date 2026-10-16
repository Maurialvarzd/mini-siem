# mini-siem

Un mini SIEM defensivo escrito en Python como proyecto de aprendizaje en ciberseguridad. Lee logs de autenticación SSH, los normaliza a un formato común, los guarda en SQLite, detecta ataques de fuerza bruta con una ventana de tiempo y avisa por consola, archivo y email.

## Qué hace

1. **Colecta:** lee un `auth.log` y convierte cada línea relevante en un evento con formato común.
2. **Almacena:** guarda los eventos en SQLite, ignorando duplicados para que reprocesar un log no infle los conteos.
3. **Detecta:** una regla de fuerza bruta cuenta los intentos fallidos por IP dentro de una ventana deslizante (por defecto, 3 intentos en 60 segundos).
4. **Alerta:** guarda cada alerta sin repetirla y avisa solo las nuevas por consola, archivo (`alerts.log`) y email.

## Ejemplo de salida

```
Eventos nuevos guardados: 5
[HIGH] 2026-10-13 10:15:34 brute_force_ssh desde 192.168.1.50: 3 intentos fallidos en 60s (usuarios probados: admin, root)
```

## Estructura del proyecto

```
mini-siem/
├── collectors/     # leen logs y los convierten en eventos (ssh.py)
├── rules/          # reglas de detección (brute_force.py)
├── storage/        # base de datos SQLite (db.py)
├── alerts/         # formas de avisar: consola, archivo, email
├── sample_logs/    # log de ejemplo para probar
├── models.py       # formato común: Event y Alert
└── main.py         # punto de entrada
```

La idea central: cada colector traduce su log al mismo formato de evento, y las reglas solo trabajan con ese formato. Así se pueden sumar fuentes de logs o reglas nuevas sin tocar lo existente.

## Cómo probarlo

Requiere Python 3.9 o superior. No usa librerías externas.

```
git clone https://github.com/Maurialvarzd/mini-siem.git
cd mini-siem
python main.py
```

Esto procesa `sample_logs/auth_sample.log`. Al correrlo de nuevo, dice `Sin alertas nuevas.`, porque las alertas ya quedaron guardadas.

## Alertas por email 

El envío usa Gmail con una contraseña de aplicación, leída desde variables de entorno (nunca está en el código):

```
EMAIL_USER             # cuenta de Gmail que envía
EMAIL_APP_PASSWORD     # contraseña de aplicación de 16 caracteres
EMAIL_TO               # destinatario de las alertas
```

Si faltan, el programa avisa y sigue funcionando con consola y archivo.

## Decisiones de seguridad

- Consultas SQL parametrizadas: los logs contienen datos controlados por un atacante (nombres de usuario), así que nunca se arma SQL concatenando texto.
- Secretos fuera del código, en variables de entorno, y excluidos del repositorio.
- Conexión SMTP cifrada con verificación de certificado y tiempo de espera limitado.
- Un fallo al enviar el email no interrumpe el SIEM.

## Limitaciones y próximos pasos

- Solo lee logs SSH (`auth.log`), y los logs de syslog no guardan el año, así que se usa el año actual.
- Una sola regla de detección.
- Próximos pasos para el proyecto: dashboard web con Streamlit, más reglas como el login exitoso tras muchos fallidos, probar con el `auth.log` de una VM Ubuntu y enriquecer las IPs con threat intelligence.

## Lo que aprendí durante este proyecto

- **El umbral importa tanto como la detección.** Una regla de fuerza bruta tiene que distinguir un ataque de una persona que se equivocó varias veces con su contraseña. Con un umbral muy bajo se generan falsas alarmas, y con uno muy alto se escapan ataques, así que hay que ajustarlo a cada caso.
- **Cómo organizar un proyecto por capas** (colectores, reglas, almacenamiento, alertas) y trabajar con rutas, módulos e importaciones en Python.
- **Buenas prácticas con secretos:** las credenciales van en variables de entorno y no en el código, y el `.gitignore` se arma antes del primer commit.
- **Flujo básico con Git y GitHub:** repositorio local, commits, autenticación y push.

**Lo que estoy profundizando:** la lógica de ventana deslizante de la regla de fuerza bruta, la normalización de eventos, las consultas SQL parametrizadas y el diseño de reglas de detección. Estoy estudiándolos con una guía propia del proyecto, y esta sección se va a actualizar a medida que los domine.

## Usuario 

Mauricio Alvarez