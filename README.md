# AOWeb Security Audit

Security audit of the [AOWeb](https://aoweb.app) web client — a browser-based port of the classic MMORPG Argentum Online, created by [Damian Catanzaro](https://x.com/DamianCatanzaro).

**This audit was authorized by the developer.**

## What's inside

A Chrome extension that demonstrates several client-side vulnerabilities:

### Packet Sniffer
- Full decode of the binary WebSocket protocol (20 client opcodes, 52 server opcodes)
- Live packet log with timestamps, opcode names, and decoded payloads
- Server cooldown tracker (measures actual server-enforced intervals)
- Export/copy captured data as JSON for analysis

### Radar + ESP Overlay
- Mini-radar showing all nearby entities (NPCs and players) with real-time position tracking
- ESP overlay drawn directly on the game canvas with markers and names
- **Invisible player detection** — the server sends position, heading, and name of hidden players. The radar and ESP expose them with a pulsing magenta marker
- Entity list with distance sorting
- Click on radar to set spell target, Ctrl+click to set auto-walk destination
- All radar settings persisted to localStorage

### Speed Hack
- Sends walk packets at configurable intervals, bypassing the client-side 100ms rate limit
- The server rate-limits at ~150ms but does not kick or penalize the player

### Spell Spam + Auto-Target Combo
- Sends spell cast packets bypassing the client-side 850ms cooldown
- **Spell dropdowns** with names loaded from the game's character-settings API
- **Combo system**: casts spell slot 1 first (e.g. a debuff), then spams slot 2 (e.g. damage spell)
- **Auto-target**: locks the nearest entity, follows it if it moves, chains to next target on kill
- **Capture target**: click on the map to select a target and auto-start casting
- All spell config persisted to localStorage

### Auto-Walk with A* Pathfinding
- Set a destination (map, x, y) and the character walks there automatically
- **A* pathfinding** avoids blocked tiles (opcode 39) and entities
- **Reactive obstacle avoidance**: detects when stuck and re-paths around obstacles
- **Cross-map navigation**: hardcoded world map grid (~260 maps) with BFS routing between maps
- Walk to map edge with pathfinding, then cross to the next map
- Ctrl+click on radar to set destination and start walking

### Melee Spam
- Sends melee attack packets at configurable intervals, bypassing the 950ms client cooldown

## Key Vulnerability: Invisibility is Cosmetic

The most critical finding: **invisible players are fully detectable**. The server sends `getCharacter` (opcode 2) and `actPosition` (opcode 4) packets for hidden players, including their name, position, and heading. The client simply doesn't render them — but a modified client sees everything.

## Installation

1. Clone this repo
2. Open `chrome://extensions/` in Chrome
3. Enable **Developer mode**
4. Click **Load unpacked** and select the `extension/` folder
5. Navigate to [aoweb.app](https://aoweb.app), log in, and enter the game

## Controls

| Shortcut | Action |
|----------|--------|
| Shift+P | Toggle audit panel |
| Shift+S | Target selection (click map to set target + auto-cast) / Stop all |
| Shift+A | Toggle auto-target + spell spam |
| Shift+H | Toggle speed hack (WASD to change direction) |
| Shift+G | Toggle auto-walk to destination |
| Shift+R | Toggle radar |
| Shift+E | Copy sniffer data to clipboard |

## UI

The panel features a **tabbed interface** with the radar always visible at the top:

- **Radar**: always visible — mini-map, ESP overlay toggle, entity list
- **Spell tab**: combo spell slots (dropdown with spell names), target capture, auto-target
- **Melee tab**: melee spam with configurable interval
- **Speed tab**: speed hack with configurable interval
- **Walk tab**: auto-walk with map/coordinates, A* pathfinding, cross-map routing
- **Sniffer tab**: packet log, export, server cooldown measurements

All configuration (spell slots, intervals, radar settings) is persisted to localStorage.

## Protocol Reference

### Client → Server

| Opcode | Name | Payload |
|--------|------|---------|
| 1 | changeHeading | byte(heading) |
| 2 | clickTile | byte(x), byte(y), byte(mode) |
| 3 | useItem | int(slot) |
| 4 | equipItem | int(slot) |
| 5 | login | string(ticket), byte(typeGame), byte(idChar) |
| 6 | walk | byte(heading), int(moveId) |
| 7 | chat | string(message) |
| 8 | ping | — |
| 9 | meleeAttack | — |
| 10 | rangeAttack | byte(targetX), byte(targetY) |
| 11 | castSpell | byte(slot), byte(targetX), byte(targetY) |
| 12 | buyMerchant | int(slot), short(amount) |
| 13 | pickupItem | — |
| 14 | sellMerchant | byte(slot), short(amount) |
| 15 | depositBank | byte(slot), short(amount) |
| 16 | requestSkills | — |
| 17 | toggleSeguro | — |
| 18 | swapSpells | byte(src), byte(dst) |
| 19 | swapInventory | byte(src), byte(dst) |
| 20 | toggleHidden | — |

### Binary Format

Little-endian, first byte is always the opcode. Field types:
- `byte`: 1 byte unsigned
- `short`: 2 bytes Uint16 LE
- `int`: 4 bytes Uint32 LE
- `double`: 8 bytes Float64 LE
- `string`: short(charCount) + UTF-8 bytes

## Full Report

See [REPORTE-SEGURIDAD-AOWEB.md](./REPORTE-SEGURIDAD-AOWEB.md) for the complete vulnerability report with risk matrix and remediation recommendations (in Spanish).

## Disclaimer

This tool was built for authorized security testing only. Do not use it to gain unfair advantages against other players. The purpose is to identify and report vulnerabilities to the developer.
