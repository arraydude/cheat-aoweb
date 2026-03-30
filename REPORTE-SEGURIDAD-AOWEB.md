# Reporte de Seguridad - AOWeb (aoweb.app)

**Fecha:** 2026-03-29
**Testeado por:** arraydude (Nahuel Rosso), con asistencia automatizada
**Solicitado por:** Damian Catanzaro (desarrollador)
**Tipo:** Security audit del cliente web - black box + source code analysis

---

## Resumen Ejecutivo

Se realizaron pruebas de seguridad sobre el cliente web de AOWeb (port web de Argentum Online). Se encontraron vulnerabilidades de severidad **media a alta** relacionadas con la falta de validaciones client-side, ausencia de penalizaciones por abuso del protocolo, y exposicion publica de datos del juego. El protocolo binario fue completamente reversado (20 opcodes del cliente, 52 del servidor). El servidor muestra buenas defensas de rate-limiting y posicion autoritativa, pero carece de mecanismos de castigo, deteccion de bots, y proteccion de integridad del cliente.

---

## 1. Arquitectura del Cliente

### Stack Tecnologico
| Componente | Tecnologia |
|---|---|
| Frontend | Next.js 16.2.1 (Turbopack, RSC) |
| React | 19.2.4 + React DOM 19.3.0-canary |
| Rendering | PixiJS v8 (WebGL2, batch renderer) |
| Hosting | Vercel |
| CDN | DigitalOcean Spaces (aoweb.nyc3.cdn.digitaloceanspaces.com) |
| WebSocket | wss://socket.aoweb.app (fallback: wss://hostname:7666) |
| Protocolo | Binario custom (clases `tc` writer / `tu` reader) |
| Canvas | 672x672px, WebGL2 (OpenGL ES 3.0) |
| Build hash | a78b99aea1e4 |

### Endpoints API descubiertos
- `GET /api/auth/me` - Info de sesion
- `POST /api/auth/select-character` - Seleccion de personaje
- `GET /api/auth/game-ticket` - Ticket de autenticacion para WebSocket
- `GET /api/auth/character-settings` - Configuracion del personaje
- `GET /api/runtime-config` - Configuracion de timing del juego (PUBLICO)
- `GET /api/runtime-config/admin` - Panel de admin para modificar config en vivo

### Datos publicos en CDN (sin autenticacion)
- `graficos.json` - 822+ definiciones graficas (sprites, animaciones)
- `spells.json` - Definiciones de hechizos
- `objs.json` - Definiciones de objetos/items
- `npcs.json` - Definiciones de NPCs
- `bodies.json`, `heads.json`, `armas.json`, `escudos.json`

### Estado del Juego (React Refs internos)
El estado del juego vive en `useRef` objects dentro de closures React:
| Ref | Contenido |
|-----|-----------|
| `B.current` | Instancia del game engine (clase `tD`) |
| `P.current` | Conexion WebSocket |
| `H.current` | Snapshot completo del personaje |
| `K.current` | Array de movimientos pendientes (sin ACK) |
| `Z.current` | Contador de move ID |
| `em.current` | Estado de cooldowns de combate |
| `ed.current` | Estado del HUD (HP, mana, gold, inventario) |
| `el.current` | Config de timing en runtime |

---

## 2. Protocolo WebSocket (Completamente Reversado)

### Formato Binario
- **Clase writer `tc`**: `writeByte(1)`, `writeShort(2)`, `writeInt(4)`, `writeDouble(8)`, `writeString(len+utf8)`
- **Clase reader `tu`**: `getByte()`, `getShort()`, `getInt()`, `getDouble()`, `getString()`
- **Endianness**: Little-endian
- **Primer byte**: siempre el opcode/packet ID
- **Sin cifrado** adicional sobre TLS, sin firma, sin sequence validation

### Flujo de Conexion
```
1. GET /api/auth/game-ticket → ticket string
2. new WebSocket("wss://socket.aoweb.app"); ws.binaryType = "arraybuffer"
3. Send: [0x05, string(ticket), byte(typeGame=1), byte(idChar=0)]
4. Recv: Packet 1 (getMyCharacter) + datos iniciales del mapa
5. Keepalive: Send [0x08] cada 15s, Recv [0x09]
```

### Opcodes Cliente → Servidor (20 paquetes)
| ID | Funcion | Payload |
|----|---------|---------|
| 1 | changeHeading | byte(heading) |
| 2 | clickTile | byte(x), byte(y), byte(mode: 0=normal, 2=rightclick) |
| 3 | useItem | int(slot) |
| 4 | equipItem | int(slot) |
| **5** | **login** | string(ticket), byte(typeGame), byte(idChar) |
| **6** | **walk** | byte(heading 1-4), int(moveId) |
| 7 | chat | string(message) |
| **8** | **ping** | (vacio) |
| **9** | **meleeAttack** | (vacio) |
| **10** | **rangeAttack** | byte(targetX), byte(targetY) |
| **11** | **castSpell** | byte(spellSlot), byte(targetX), byte(targetY) |
| 12 | buyFromMerchant | int(slot), short(amount) |
| 13 | pickupItem | (vacio) |
| 14 | sellToMerchant | byte(slot), short(amount) |
| 15 | depositToBank | byte(slot), short(amount) |
| 16 | requestSkillList | (vacio) |
| 17 | toggleSeguro | (vacio) |
| 18 | swapSpells | byte(src), byte(dst) |
| 19 | swapInventory | byte(src), byte(dst) |
| 20 | toggleHiddenSkill | (vacio) |

### Opcodes Servidor → Cliente (52 paquetes, principales)
| ID | Funcion | Contenido clave |
|----|---------|----------------|
| 1 | getMyCharacter | Estado completo (HP, mana, exp, inventario, spells) |
| 2 | getCharacter | Datos visibles de otro jugador/NPC |
| 4 | actPosition | id, x, y (entidad se movio) |
| 5 | changeHeading | id, heading |
| 6 | deleteCharacter | id (entidad salio del rango) |
| 7 | dialog | id, msg, name, color |
| 9 | pong | respuesta a ping |
| 12 | updateHP | hp |
| 14 | updateMana | mana |
| **15** | **telepMe** | map, x, y, heading, lastProcessedMoveId, stateVersion |
| **21** | **actPositionServer** | map, x, y, heading, lastProcessedMoveId, stateVersion |
| 22 | actExp | exp (double) |
| 24 | actGold | gold |
| 28 | error | msg |
| 35 | renderItem | idItem, map, x, y |
| 39 | blockMap | map, x, y, blocked |
| 41 | openTrade | mode, merchant items, player items |
| 43 | closeForce | fuerza desconexion |
| 49 | playSound | id, soundId |

---

## 3. Vulnerabilidad: Speed Hack (Severidad: MEDIA)

### Descripcion
El cliente tiene un rate-limit en `tD.moveTo()`:
```js
if (timestamp() - this.timeWalk < this.timeWalkMS) return; // 100ms default
```
Este check es **client-side only** y se bypasea enviando paquetes directamente al WS.

El `runtime-config` expone publicamente los timings:
```json
{
  "timing": {
    "walkStepMs": 100,
    "actionCooldowns": {
      "meleeMs": 950, "rangeMs": 950,
      "spellMs": 850, "useItemMs": 190
    }
  }
}
```

### Resultados del Test Empirico
Se enviaron paquetes walk (opcode 6) directamente al WebSocket:

| Intervalo | Steps Enviados | ACKs (op 21) | Avg Delta Server | Efectividad |
|-----------|---------------|-------------|-----------------|-------------|
| 100ms (normal) | 15 | **15** | 103ms | 100% |
| 50ms | 15 | **13** | 154ms | 87% |
| 10ms | 15 | **9** | 155ms | 60% |
| 0ms (burst) | 15 | **9** | 144ms | 60% |

### Server-side: Telemetry Thresholds (descubierto en codigo)
El servidor SI tiene mecanismos de deteccion configurables:
```js
telemetryThresholds: {
    positionWindowMs: 6000,      // Ventana de deteccion de speed
    attackWindowMs: 9000,        // Ventana de deteccion de melee spam
    rangeAttackWindowMs: 7000,   // Ventana para ataques a distancia
    attackSpellWindowMs: 7000,   // Ventana para spell spam
    useItemWindowMs: 3800        // Ventana para uso de items
}
```
Estos valores son **modificables en vivo** via panel admin (packet 52).

### Hallazgos
- **POSITIVO**: Server-authoritative position con reconciliacion (patron correcto)
- **POSITIVO**: Rate-limiting server-side (~140-155ms entre pasos aceptados)
- **POSITIVO**: Existen telemetry thresholds configurables
- **NEGATIVO**: No se observo desconexion ni penalizacion durante el test
- **NEGATIVO**: 60% de paquetes burst son aceptados (9/15 en modo 0ms)
- **NEGATIVO**: runtime-config expone timings Y thresholds al atacante

### Impacto
Un bot enviando a 50ms logra 87% de aceptacion, moviendose efectivamente ~20-30% mas rapido. A 0ms burst, 60% de aceptacion permite mover 9 tiles en <100ms que al servidor le toma ~1.3s procesar.

### Recomendacion
1. Implementar kick/ban temporal al superar threshold de paquetes rapidos
2. Penalizacion exponencial (warn → kick 30s → ban 5min → ban 1h)
3. Mover runtime-config a endpoint autenticado, ocultar telemetryThresholds
4. Reducir la ventana de aceptacion de burst (de 60% a ~20%)

---

## 4. Vulnerabilidad: Remocion de Techos/Arboles (Severidad: MEDIA)

### Sistema de Capas (documentado del source code)
El renderer PixiJS v8 usa 4 capas de tiles + containers:

| Capa | Key en tile | Container | zIndex | Funcion |
|------|------------|-----------|--------|---------|
| Layer 1 | `graphics["1"]` | mapContainer | 0 | Suelo |
| Layer 2 | `graphics["2"]` | mapContainer | 2 | Decoraciones de suelo |
| Layer 3 | `graphics["3"]` | mapContainer | `10*y+7` | Arboles, paredes |
| **Layer 4** | `graphics["4"]` | **roofContainer** | `10*y+9` | **Techos** |
| Players | - | playerContainer | `10*y+5` | Personajes |

### Auto-hide de Techos (comportamiento actual)
El metodo `updateRoofVisibility()` en el game loop:
- Chequea si el tile del jugador tiene `trigger === 1` o grafico en layer 4
- Si el jugador esta "indoor", todos los sprites de techo se ponen `alpha = 0`
- Si esta "outdoor", `alpha = 1`
- **No hay toggle manual** para el jugador (la tecla O es para "ocultarse")

### Vectores de Ataque
1. **Shader replacement**: Se extrajo el source de ambos shaders (`batch-vertex`, `batch-fragment`). El atributo `aColor (vec4)` controla alpha por vertice
2. **Container visibility**: `roofContainer.visible = false` (si se accede a la instancia PixiJS)
3. **Modificacion de `updateRoofVisibility()`**: Override para que siempre ponga `alpha = 0`
4. **Layer 3 (arboles)**: Mismo approach, setear alpha de sprites con zIndex `10*y+7`

### Evidencia
- Shaders WebGL extraidos exitosamente via `gl.getShaderSource()`
- No existe Content Security Policy que prevenga inyeccion
- No hay chequeo de integridad del cliente
- Motor bien encapsulado (no hay globales PIXI), pero accesible via extension/userscript

### Impacto
- Ver a traves de techos: ventaja critica en PvP dentro de edificios
- Ver a traves de arboles: ventaja en emboscadas y huida
- Implementable con userscript (Tampermonkey) o extension de Chrome

### Recomendacion
1. **Server-side fog of war**: No enviar datos de entidades cubiertas por techos a otros jugadores
2. Content Security Policy headers restrictivos
3. Considerar enviar solo el estado de entidades que el jugador puede ver legitimamente
4. No depender del cliente para ocultar informacion sensible de combate

---

## 5. Vulnerabilidad: Auto-Aim (Severidad: MEDIA-ALTA)

### Sistema de Combate (documentado del source code)

**Melee** (packet 9, sin payload):
- Triggeado por Espacio con arma cuerpo a cuerpo equipada
- Cooldown client-side: `meleeMs: 950`, cross-cooldown: `meleeToSpellMs: 800`

**Rango** (packet 10):
```
[0x0A, byte(targetX), byte(targetY)]
```
- Requiere arco equipado, click en tile del target
- Cooldown: `rangeMs: 950`

**Hechizo** (packet 11):
```
[0x0B, byte(spellSlot), byte(targetX), byte(targetY)]
```
- Seleccionar spell del spell bar, click en tile
- Cooldown: `spellMs: 850`, check de mana client-side

**Cross-cooldowns**:
- Melee despues de spell: 550ms (`spellToMeleeMs`)
- Spell despues de melee: 550ms (`meleeToSpellMs`)
- Todos estos cooldowns son **client-side only**

### Vector de Ataque Auto-Aim
1. **Parsear** opcodes 2 (getCharacter) y 4 (actPosition) para trackear posiciones de entidades
2. **Mantener** mapa de {entityId: {x, y, name, type}} en tiempo real
3. **Calcular** target optimo: distancia minima, tipo especifico (NPC/jugador)
4. **Enviar** packet 10 (range) o 11 (spell) con las coordenadas exactas del target
5. **Respetar** cooldowns para evadir telemetry thresholds (esperar 950ms+ entre ataques)

### Datos disponibles al bot
- Posiciones X,Y de todas las entidades en rango visual (opcode 4)
- Nombres de NPCs/jugadores (opcode 2, campo string)
- HP del propio jugador (opcode 12), mana (opcode 14)
- Items en el suelo (opcode 35) para auto-loot
- Cooldowns exactos desde runtime-config

### Impacto
- PvP: targeting instantaneo, reaccion perfecta, combo melee+spell optimo
- PvE: farming automatizado 24/7 con targeting perfecto
- Economia: generacion infinita de gold/exp sin intervencion humana

### Recomendacion
1. Deteccion de patrones inhumanos (reaccion < 50ms consistente, accuracy 100%)
2. Varianza server-side en cooldown acceptance (ej: aceptar con +/- 50ms random)
3. Limitar la informacion enviada al cliente (no enviar entidades fuera de line-of-sight)
4. Analisis estadistico de sesiones (KPM constante, zero idle time, patrones repetitivos)

---

## 6. Vulnerabilidad: Cliente Falso / Bot (Severidad: ALTA)

### Descripcion
El protocolo binario fue completamente reversado. Un bot headless es trivial de implementar.

### Flujo de Autenticacion Completo
```
1. POST /api/auth/login (email + password → session cookie)
2. POST /api/auth/select-character (cookie → selecciona personaje)
3. GET /api/auth/game-ticket (cookie → ticket string efimero)
4. new WebSocket("wss://socket.aoweb.app")
5. ws.binaryType = "arraybuffer"
6. Send: new tc(5).writeString(ticket).writeByte(1).writeByte(0).toArrayBuffer()
7. Recv: Packet 1 (estado completo del personaje)
8. Keepalive: Send tc(8) cada 15s
```

### Protocolo 100% Documentado
Los 20 opcodes del cliente y la estructura de cada paquete estan documentados (ver seccion 2). Un bot necesita implementar:
- **Minimo viable**: opcodes 5 (login), 6 (walk), 8 (ping), 9 (melee), 13 (pickup)
- **Bot avanzado**: + opcodes 10, 11 (ranged/spell), 3 (use item), 7 (chat)
- **Parseo server**: opcodes 1, 2, 4, 12, 14, 21, 28 para mantener estado

### Especificacion de la Clase Writer (para replicar)
```
tc(packetId):
  writeByte(v)   → 1 byte Uint8 LE
  writeShort(v)  → 2 bytes Uint16 LE
  writeInt(v)    → 4 bytes Uint32 LE
  writeDouble(v) → 8 bytes Float64 LE
  writeString(s) → writeShort(chars.length) + UTF-8 bytes
```

### Ausencia de Proteccion Anti-Bot
- Sin challenge-response en WS handshake
- Sin fingerprinting del navegador
- Sin CAPTCHA
- Sin verificacion de que el JS del cliente es el oficial
- Sin message signing o HMAC
- Sin rate limiting en el endpoint de game-ticket
- WS URL fallback expuesto: `wss://hostname:7666`

### Impacto
- Bot de farming implementable en **~200 lineas** de Node.js/Python
- Multiples instancias por IP (no hay limite)
- Destruccion de la economia del juego
- Flooding del servidor con conexiones
- 24/7 farming automatizado

### Recomendacion
1. **[CRITICO]** Challenge-response: el servidor envia un desafio criptografico que solo el cliente oficial puede resolver
2. **[ALTO]** Rate limiting por IP en auth endpoints
3. **[ALTO]** Token rotation: game-ticket debe expirar rapido y requerir refresh periodico via el cliente
4. **[MEDIO]** Fingerprinting: enviar canvas hash, user-agent, screen res en el handshake
5. **[MEDIO]** CAPTCHA anti-bot periodico (al detectar patrones sospechosos)
6. **[BAJO]** Ocultar WS fallback URL del source code

---

## 7. Hallazgos Adicionales

### 7.1 Exposicion de Datos Sensibles
- `/api/runtime-config` expone timings, cooldowns, Y telemetry thresholds sin auth
- `/api/runtime-config/admin` existe como endpoint de configuracion en vivo
- Todos los JSON de init son publicos en CDN
- Build hash visible en URLs

### 7.2 Ausencia de Content Security Policy
- No se detectaron headers CSP
- Permite inyeccion de scripts via consola sin restriccion
- Un atacante puede inyectar codigo en el contexto de la pagina
- Facilita la creacion de cheats via userscripts

### 7.3 Motor de Juego Bien Encapsulado (Positivo)
- PixiJS y el game engine NO estan expuestos como globales
- El WebSocket esta en un module closure (React ref `P.current`)
- No hay devtools hooks de PixiJS habilitados
- Prototype patching del WS no funciona (el modulo guarda refs bound)
- Esto **dificulta** la manipulacion casual, pero no la previene

### 7.4 Server-Authoritative Position (Positivo)
- Implementacion correcta de client-side prediction + server reconciliation
- El servidor envia `lastProcessedMoveId` y `stateVersion`
- El cliente aplica movimientos pendientes sobre la posicion del servidor
- State version monotonica previene replay attacks parcialmente

### 7.5 Debug Mode Accesible
- La tecla **P** activa un modo debug que muestra grid de coordenadas sobre el mapa
- Util para un atacante para visualizar posiciones exactas de tiles

### 7.6 Monitoreo de Terceros
- Llamadas a `mntr.cafecito.app/api/event` (analytics de Cafecito)
- Plausible analytics cargado desde CDN

---

## 8. Matriz de Riesgo

| Vulnerabilidad | Severidad | Facilidad | Impacto | Prioridad |
|---|---|---|---|---|
| Cliente Falso/Bot | **Alta** | Facil | Alto | **P1** |
| Auto-Aim | Media-Alta | Media | Alto | **P1** |
| Speed Hack | Media | Facil | Medio | **P2** |
| Exposicion runtime-config | Media | Trivial | Medio | **P2** |
| Remocion de Techos/Arboles | Media | Media | Medio | **P3** |
| Debug Mode accesible | Baja | Trivial | Bajo | **P4** |
| Sin CSP Headers | Baja | Trivial | Bajo | **P4** |

---

## 9. Resumen de Recomendaciones Prioritarias

### P1 - Critico
1. **Anti-bot en WS**: Challenge-response criptografico en el handshake
2. **Rate limiting**: Por IP en endpoints de auth y game-ticket
3. **Deteccion de patrones**: Sistema estadistico para auto-aim/farming bots

### P2 - Alto
4. **Penalizacion de speed hack**: Kick/ban progresivo al superar thresholds
5. **Ocultar configuracion**: runtime-config y telemetryThresholds detras de auth
6. **Token rotation**: Game-ticket con expiracion corta y refresh obligatorio

### P3 - Medio
7. **Fog of war server-side**: No enviar entidades ocultas por techos/paredes
8. **CSP headers**: Prevenir inyeccion de scripts de terceros
9. **Integridad del cliente**: Validacion de shader programs

### P4 - Bajo
10. **Deshabilitar debug mode** en produccion (tecla P)
11. **Ocultar WS fallback URL** del source code

---

## Apendice: Keybindings del Juego (para referencia)
| Tecla | Accion | Packet ID |
|-------|--------|-----------|
| W/A/S/D | Movimiento | 6 |
| Espacio | Atacar/Apuntar | 9, 10, 11 |
| Q | Agarrar item | 13 |
| E | Equipar item | 4 |
| U | Usar item | 3 |
| T | Tirar item | - |
| K | Toggle seguro | 17 |
| O | Ocultarse | 20 |
| M | Mapa | - |
| P | Debug mode | - (client only) |
| Enter | Chat | 7 |

---

*Este reporte fue generado como parte de un security audit autorizado por el desarrollador Damian Catanzaro.*
*Metodologia: Black-box testing + source code analysis del cliente web (259KB main game script).*
