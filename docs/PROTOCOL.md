# Protocolo Troste Onion v1

Este documento describe el formato actual. No es todavia un estandar estable.

## Identidad publica

La identidad compartida mantiene el formato `troste-public-identity` v1 y contiene un alias, una llave publica ECDH P-256, una llave publica ECDSA P-256 y su huella SHA-256. Las llaves privadas no salen del navegador.

## Sobre interior

1. El remitente genera una llave ECDH P-256 efimera.
2. Deriva 256 bits con la llave ECDH publica del destinatario.
3. Deriva AES-256-GCM mediante HKDF-SHA-256, salt aleatorio e info `troste-letter-v1`.
4. Cifra la carta y adjunta solo la llave publica efimera, salt, IV y ciphertext.
5. Firma los identificadores y el sobre con ECDSA P-256 SHA-256.

El texto, asunto, estado de animo, fecha formal, saludo y firma visual solo existen dentro del ciphertext.

## Sobre de ruta

El navegador genera un secreto aleatorio de 32 bytes. Con HKDF-SHA-256 deriva una llave AES-256-GCM usando:

```text
salt: 16 bytes aleatorios
info: troste-onion-route-key-v1:<nodeId>
AAD:  troste-onion-route-envelope-v1:<nodeId>
```

El sobre exterior transporta el nodo sellado sin metadatos legibles:

```json
{
  "version": 1,
  "cryptoSuite": "HKDF-SHA256+AES-256-GCM",
  "salt": "base64url",
  "iv": "base64url",
  "ciphertext": "base64url"
}
```

El daemon almacena el SHA-256 de `troste-onion-secret-v1:<nodeId>:<secret>` y nunca el secreto.

## Publicacion local

```http
POST /api/nodes
X-Troste-Local: 1
Content-Type: application/json

{
  "nodeId": "uuid",
  "secretHash": "sha256-hex",
  "expiresAt": "ISO-8601",
  "payload": {}
}
```

Esta API solo escucha en `127.0.0.1` y comprueba host, origen y contexto de la solicitud.

## Entrega remota

Tor publica un unico metodo de lectura:

```http
POST /v1/letters/<nodeId>
Content-Type: application/json

{"secret":"base64url-32-bytes"}
```

Una coincidencia devuelve `{"payload":{...}}`. Un ID inexistente, secreto incorrecto o carta vencida devuelve el mismo error generico. No existen endpoints remotos para listar, publicar, revocar ni consultar estado.

## Resolucion local

El navegador del destinatario envia la direccion, ID y secreto a `POST /api/resolve`. El daemon valida el checksum Onion v3 y usa SOCKS5h con credenciales nuevas para cada consulta. Solo el navegador abre el sobre exterior y luego el interior.

## Revocacion

El remitente puede borrar una carta local mediante `DELETE /api/nodes/<nodeId>` y el secreto completo. Los nodos vencen a los 90 dias y el daemon ejecuta limpieza cada hora mientras esta activo.

## Compatibilidad

Los receptores deben rechazar prefijos, versiones, suites, tamanos, direcciones Onion o firmas desconocidas. Una futura version incompatible debe usar otro prefijo de codigo y endpoints versionados.

