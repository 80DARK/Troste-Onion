# Seguridad

## Estado

Troste Onion es un prototipo y no ha sido auditado. No lo presentes como garantia de anonimato, seguridad de vida o muerte, proteccion frente a un dispositivo comprometido ni sustituto de una herramienta madura y revisada.

## Modelo de amenazas

El diseno busca proteger:

- El contenido frente al daemon del remitente, Tor y observadores de red.
- El contenido y los metadatos interiores si alguien copia `data/nodes` sin conseguir el codigo.
- La identidad de red del buzon frente al destinatario y los relays intermedios de Tor.
- La integridad y autoria criptografica del sobre mediante AES-GCM y ECDSA.
- La enumeracion trivial de cartas: el protocolo remoto no ofrece listados y usa errores deliberadamente ambiguos.

No protege:

- Un navegador, extension, sistema operativo o daemon ya comprometido.
- Una frase de seguridad debil observada o adivinada fuera de los limites locales.
- La perdida de la identidad privada o de las llaves del Onion Service.
- El analisis de tiempos por un adversario global con suficiente visibilidad.
- La disponibilidad cuando el buzon esta apagado, bloqueado o sin acceso a Tor.
- Al destinatario frente a lo que el propio remitente decida escribir o incluir.

## Controles implementados

- ECDH P-256, HKDF-SHA-256 y AES-256-GCM para el sobre destinatario.
- ECDSA P-256 con SHA-256 para la firma del remitente.
- HKDF-SHA-256 y AES-256-GCM para el sobre de ruta protegido por el codigo.
- Validacion completa de checksum y version de direcciones Onion v3.
- Comparacion constante del hash del secreto.
- Limites de tamano, tiempo, concurrencia y tasa.
- Cuota local por cantidad y bytes totales, con publicacion atomica de cada nodo.
- API local limitada por host, origen, `Sec-Fetch-Site` y cabecera privada.
- CSP estricta, bloqueo de marcos, `nosniff`, `no-store` y sin recursos remotos.
- Credenciales SOCKS aleatorias por consulta para aislar circuitos.
- Vencimiento de 90 dias y limpieza automatica local.

## Operacion

- Actualiza Node.js, Tor y las dependencias con criterio y vuelve a ejecutar `npm test`.
- Protege el directorio `data/` con los permisos del sistema y cifrado de disco.
- No sincronices `data/` con nubes ni repositorios.
- Haz una copia segura de `data/onion-service` solo si necesitas conservar la direccion. Quien tenga esas llaves puede suplantar el buzon.
- Reinicia el servicio si Tor queda detenido y confirma en la interfaz que el estado sea `Buzon Onion publicado`.
- Revoca las cartas que ya no deban estar disponibles.
- Ajusta `TROSTE_MAX_ACTIVE_NODES`, `TROSTE_MAX_TOTAL_NODE_MIB` y `TROSTE_MAX_CONCURRENT_RESOLVES` solo si conoces el costo operativo.

## Reporte responsable

No incluyas cartas, codigos completos, frases de seguridad ni llaves privadas en un reporte. Describe el comportamiento, la version, los pasos minimos para reproducirlo y el impacto esperado.
