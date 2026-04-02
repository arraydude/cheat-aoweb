// AOWeb Security Audit Extension
// Authorized testing only - requested by developer Damian Catanzaro
(function () {
  "use strict";

  // ========================================
  // 1. Protocol Definitions
  // ========================================
  const CLIENT_OPS = {
    1: "changeHeading", 2: "clickTile", 3: "useItem", 4: "equipItem",
    5: "login", 6: "walk", 7: "chat", 8: "ping", 9: "meleeAttack",
    10: "rangeAttack", 11: "castSpell", 12: "buyMerchant", 13: "pickupItem",
    14: "sellMerchant", 15: "depositBank", 16: "requestSkills", 17: "toggleSeguro",
    18: "swapSpells", 19: "swapInventory", 20: "toggleHidden",
  };
  const SERVER_OPS = {
    1: "getMyCharacter", 2: "getCharacter", 3: "changeRopa", 4: "actPosition",
    5: "changeHeading", 6: "deleteCharacter", 7: "dialog", 8: "console",
    9: "pong", 10: "animFX", 11: "inmo", 12: "updateHP", 13: "updateMaxHP",
    14: "updateMana", 15: "telepMe", 21: "actPositionServer", 22: "actExp",
    23: "actMyLevel", 24: "actGold", 25: "actColorName", 26: "changeHelmet",
    27: "changeWeapon", 28: "error", 30: "getNpc", 31: "changeShield",
    32: "putBodyDead", 33: "revivir", 34: "quitarInvItem", 35: "renderItem",
    36: "deleteItem", 37: "agregarInvItem", 38: "changeArrow", 39: "blockMap",
    41: "openTrade", 42: "aprenderSpell", 43: "closeForce", 44: "nameMap",
    45: "changeBody", 46: "navegando", 47: "updateAgilidad", 48: "updateFuerza",
    49: "playSound", 50: "openBail", 51: "closeBail", 52: "openAdminIntervals",
  };
  const DIR_NAMES = { 1: "N", 2: "S", 3: "E", 4: "W" };

  // ========================================
  // 2. Packet Reader (mirrors game's `tu` class)
  // ========================================
  class PacketReader {
    constructor(buf) {
      this.dv = new DataView(buf);
      this.off = 0;
      this.len = buf.byteLength;
    }
    getByte() { const v = this.dv.getUint8(this.off); this.off += 1; return v; }
    getShort() { const v = this.dv.getUint16(this.off, true); this.off += 2; return v; }
    getInt() { const v = this.dv.getUint32(this.off, true); this.off += 4; return v; }
    getDouble() { const v = this.dv.getFloat64(this.off, true); this.off += 8; return v; }
    getString() {
      const len = this.getShort();
      const bytes = new Uint8Array(this.dv.buffer, this.off, len);
      this.off += len;
      return new TextDecoder().decode(bytes);
    }
    remaining() { return this.len - this.off; }
    rawBytes(n) {
      const bytes = [];
      for (let i = 0; i < Math.min(n, this.remaining()); i++) {
        bytes.push(this.dv.getUint8(this.off + i));
      }
      return bytes;
    }
  }

  // ========================================
  // 3. Packet Writer (mirrors game's `tc` class)
  // ========================================
  function writePacket(opcode, ...writers) {
    let size = 1;
    for (const w of writers) {
      if (w.type === "byte") size += 1;
      else if (w.type === "short") size += 2;
      else if (w.type === "int") size += 4;
    }
    const buf = new ArrayBuffer(size);
    const dv = new DataView(buf);
    let off = 0;
    dv.setUint8(off++, opcode);
    for (const p of writers) {
      if (p.type === "byte") { dv.setUint8(off, p.val); off += 1; }
      else if (p.type === "short") { dv.setUint16(off, p.val, true); off += 2; }
      else if (p.type === "int") { dv.setUint32(off, p.val, true); off += 4; }
    }
    return buf;
  }
  const byte = (v) => ({ type: "byte", val: v });
  const int = (v) => ({ type: "int", val: v });

  // ========================================
  // 4. Sniffer State
  // ========================================
  const sniffer = {
    enabled: true,
    packetLog: [],       // {dir, op, name, decoded, t, size, raw}
    maxLog: 500,
    entities: {},        // {id: {name, x, y, heading, lastSeen}}
    player: { map: 0, x: 0, y: 0, heading: 0, hp: 0, maxHp: 0, mana: 0, maxMana: 0, gold: 0, exp: 0, level: 0 },
    spellDB: {},         // {spellId: {name, manaRequired, ...}} from CDN
    playerSpells: [],    // [{slot, spellId, name}] learned spells in order
    mapName: "",
    serverCooldowns: {}, // track actual server acceptance times per action type
    blockedTiles: {},    // { mapId: Set<"x,y"> }
    mapGraph: {},        // computed from MAP_GRID: { mapId: {n,s,e,w} }
    filterOps: null,     // null = show all, Set of opcodes to show
    hidePing: true,      // hide ping/pong by default
    espEnabled: true,    // ESP overlay on game canvas
  };

  // World map grid - transcribed from the game map image
  // Each row is [maps...], 0 = empty. Adjacency computed automatically.
  const MAP_GRID = [
    /*r0 */ [0,0,137,136,135,134,133,132,131,130,129,128,0,119,110],
    /*r1 */ [0,0,0,0,61,0,47,0,0,0,0,0,0,0,127],
    /*r2 */ [0,0,0,153,60,0,243,0,0,0,0,0,0,0,0,126],
    /*r3 */ [0,0,0,154,66,59,159,160,161,0,0,0,0,0,0,125],
    /*r4 */ [0,242,155,65,58,158,157,195,196,197,149,148,147,124,138],
    /*r5 */ [182,183,209,240,67,57,193,194,244,246,0,0,0,0,123],
    /*r6 */ [0,0,239,237,68,56,191,192,245,247,241,0,0,122,139],
    /*r7 */ [0,0,238,236,69,55,188,189,190,248,111,112,261,0,121],
    /*r8 */ [0,201,235,76,70,54,185,186,187,0,249,114,113,260,0,120],
    /*r9 */ [0,0,234,230,71,53,86,180,253,250,0,0,0,259,0,109],
    /*r10*/ [0,0,233,229,72,7,85,256,254,251,206,207,258,262,263,108],
    /*r11*/ [0,0,232,228,73,6,83,84,255,252,205,204,257,0,0,107],
    /*r12*/ [0,231,0,75,74,5,77,81,82,202,21,203,171,0,0,106],
    /*r13*/ [10,9,0,8,0,1,11,12,13,15,16,17,103,117,104,62,64],
    /*r14*/ [0,227,0,38,39,2,14,18,19,98,20,101,102,118,105,0,63],
    /*r15*/ [282,226,0,46,36,3,25,26,27,97,99,100,0,0,152],
    /*r16*/ [0,225,0,80,35,4,22,23,24,96],
    /*r17*/ [0,211,0,78,34,32,29,28,94,95],
    /*r18*/ [0,212,0,79,87,31,30,91,93,92,224],
    /*r19*/ [0,213,0,210,88,89,90,156,151,150,223,181],
    /*r20*/ [214,215,0,216,217,219,0,220,221,222],
  ];

  // Compute adjacency graph from the grid
  (function buildMapGraph() {
    // Build position lookup: mapId -> {row, col}
    const pos = {};
    for (let r = 0; r < MAP_GRID.length; r++) {
      for (let c = 0; c < MAP_GRID[r].length; c++) {
        const id = MAP_GRID[r][c];
        if (id > 0) pos[id] = { r, c };
      }
    }
    // Compute neighbors
    for (const [id, { r, c }] of Object.entries(pos)) {
      const neighbors = {};
      // North
      if (r > 0 && MAP_GRID[r - 1] && MAP_GRID[r - 1][c] > 0) neighbors.n = MAP_GRID[r - 1][c];
      // South
      if (r < MAP_GRID.length - 1 && MAP_GRID[r + 1] && MAP_GRID[r + 1][c] > 0) neighbors.s = MAP_GRID[r + 1][c];
      // West
      if (c > 0 && MAP_GRID[r][c - 1] > 0) neighbors.w = MAP_GRID[r][c - 1];
      // East
      if (c < MAP_GRID[r].length - 1 && MAP_GRID[r][c + 1] > 0) neighbors.e = MAP_GRID[r][c + 1];
      sniffer.mapGraph[id] = neighbors;
    }
  })();

  function logPacket(dir, op, name, decoded, size, rawBytes) {
    if (!sniffer.enabled) return;
    if (sniffer.hidePing && (op === 8 || op === 9)) return;

    const entry = { dir, op, name, decoded, t: Date.now(), size, raw: rawBytes.slice(0, 30) };
    sniffer.packetLog.push(entry);
    if (sniffer.packetLog.length > sniffer.maxLog) sniffer.packetLog.shift();
    renderSnifferLog();
  }

  // ========================================
  // 5. Packet Decoders
  // ========================================
  function decodeClientPacket(buf) {
    const r = new PacketReader(buf);
    const op = r.getByte();
    const name = CLIENT_OPS[op] || "unknown_" + op;
    let decoded = "";

    try {
      switch (op) {
        case 1: decoded = `heading=${DIR_NAMES[r.getByte()] || "?"}`; break;
        case 2: decoded = `tile=(${r.getByte()},${r.getByte()}) mode=${r.getByte()}`; break;
        case 3: decoded = `slot=${r.getInt()}`; break;
        case 4: decoded = `slot=${r.getInt()}`; break;
        case 6: decoded = `dir=${DIR_NAMES[r.getByte()] || "?"} moveId=${r.getInt()}`; break;
        case 7: decoded = `msg="${r.getString().substring(0, 40)}"`; break;
        case 9: decoded = "(no payload)"; break;
        case 10: decoded = `target=(${r.getByte()},${r.getByte()})`; break;
        case 11: decoded = `slot=${r.getByte()} target=(${r.getByte()},${r.getByte()})`; break;
        case 12: decoded = `slot=${r.getInt()} amount=${r.getShort()}`; break;
        case 13: decoded = "(no payload)"; break;
        case 17: decoded = "(toggle seguro)"; break;
        case 18: decoded = `src=${r.getByte()} dst=${r.getByte()}`; break;
        case 19: decoded = `src=${r.getByte()} dst=${r.getByte()}`; break;
        default: decoded = `[${r.rawBytes(10).join(",")}]`; break;
      }
    } catch (e) { decoded = "(decode error)"; }

    return { op, name, decoded };
  }

  function decodeServerPacket(buf) {
    const r = new PacketReader(buf);
    const op = r.getByte();
    const name = SERVER_OPS[op] || "unknown_" + op;
    let decoded = "";

    try {
      switch (op) {
        case 1: { // getMyCharacter - parse position + extract spells
          try {
            const myId = r.getDouble();
            const myName = r.getString();
            const myHeading = r.getByte();
            const myMap = r.getShort();
            const myX = r.getByte();
            const myY = r.getByte();
            sniffer.player.map = myMap;
            sniffer.player.x = myX;
            sniffer.player.y = myY;
            sniffer.player.heading = myHeading;

            // Extract spells from the packet
            // Spell entries are at the end: short(?), byte(slot), short(spellId), getString(name)
            // Scan for slot=0 + known spellId to find start
            const spellDB = sniffer.spellDB;
            if (Object.keys(spellDB).length > 0) {
              const raw = new Uint8Array(buf);
              const dv2 = new DataView(buf);
              for (let i = 22; i < raw.length - 6; i++) {
                if (raw[i] !== 0) continue; // looking for slot=0
                const possibleId = dv2.getUint16(i + 1, true);
                if (!spellDB[possibleId]) continue;
                // Verify: try reading the name
                const nameLen = dv2.getUint16(i + 3, true);
                if (nameLen < 1 || nameLen > 60) continue;
                // Found slot=0 with valid spell - parse all spells from here
                let off = i - 2; // back 2 for leading short
                const spells = [];
                while (off < raw.length - 5) {
                  const lead = dv2.getUint16(off, true); off += 2;
                  const slot = raw[off]; off += 1;
                  const sid = dv2.getUint16(off, true); off += 2;
                  const nLen = dv2.getUint16(off, true); off += 2;
                  if (nLen < 1 || nLen > 60 || off >= raw.length) break;
                  // Read nLen chars of UTF-8
                  let bRead = 0, cRead = 0;
                  while (cRead < nLen && off + bRead < raw.length) {
                    const b = raw[off + bRead];
                    bRead += (b < 0x80) ? 1 : (b < 0xE0) ? 2 : (b < 0xF0) ? 3 : 4;
                    cRead++;
                  }
                  const sName = new TextDecoder().decode(raw.slice(off, off + bRead));
                  off += bRead;
                  spells.push({ slot, spellId: sid, name: sName });
                  if (slot > 30) break;
                }
                if (spells.length >= 2) {
                  sniffer.playerSpells = spells;
                  console.log("[AOWeb Audit] Parsed", spells.length, "spells from getMyCharacter:", spells.map(s => s.slot + ":" + s.name).join(", "));
                  updateSpellDropdowns();
                  break;
                }
              }
            }
            decoded = `"${myName}" map=${myMap} pos=(${myX},${myY}) spells=${sniffer.playerSpells.length} [${buf.byteLength}b]`;
          } catch (e2) {
            decoded = `[${buf.byteLength}b] (parse error: ${e2.message})`;
          }
          break;
        }
        case 2: { // getCharacter
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          let nameStr = "", heading = 0, x = 0, y = 0, bodyId = 0;
          try {
            nameStr = r.getString();      // name
            heading = r.getByte();         // heading (1=N,2=S,3=E,4=W)
            bodyId = r.getShort();         // body graphic
            x = r.getByte();              // x position
            y = r.getByte();              // y position
          } catch (_) {}
          decoded = `id=${shortId} "${nameStr}" pos=(${x},${y}) dir=${DIR_NAMES[heading] || heading} body=${bodyId}`;
          const ent = sniffer.entities[shortId] || { type: "char", invisible: false };
          ent.name = nameStr || ent.name;
          ent.heading = heading || ent.heading;
          ent.lastSeen = Date.now();
          if (x > 0) ent.x = x;
          if (y > 0) ent.y = y;
          sniffer.entities[shortId] = ent;
          break;
        }
        case 4: { // actPosition
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          const x = r.getByte();
          const y = r.getByte();
          decoded = `id=${shortId} pos=(${x},${y})`;
          const entName = sniffer.entities[shortId]?.name || "";
          if (entName) decoded += ` "${entName}"`;
          if (!sniffer.entities[shortId]) {
            sniffer.entities[shortId] = { name: "", x, y, heading: 0, type: "unknown", lastSeen: Date.now() };
          } else {
            sniffer.entities[shortId].x = x;
            sniffer.entities[shortId].y = y;
            sniffer.entities[shortId].lastSeen = Date.now();
          }
          break;
        }
        case 5: { // changeHeading
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          const heading = r.getByte();
          decoded = `id=${shortId} heading=${DIR_NAMES[heading] || heading}`;
          if (sniffer.entities[shortId]) {
            sniffer.entities[shortId].heading = heading;
            sniffer.entities[shortId].lastSeen = Date.now();
          }
          break;
        }
        case 6: { // deleteCharacter
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          const entName = sniffer.entities[shortId]?.name || "";
          decoded = `id=${shortId}` + (entName ? ` "${entName}"` : "");
          delete sniffer.entities[shortId];
          break;
        }
        case 30: { // getNpc
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          decoded = `id=${shortId} [NPC ${buf.byteLength}b]`;
          if (!sniffer.entities[shortId]) {
            sniffer.entities[shortId] = { name: "NPC", x: 0, y: 0, heading: 0, type: "npc", lastSeen: Date.now() };
          } else {
            sniffer.entities[shortId].type = "npc";
            sniffer.entities[shortId].lastSeen = Date.now();
          }
          break;
        }
        case 7: { // dialog
          const id = r.getDouble();
          const msg = r.getString();
          decoded = `"${msg.substring(0, 50)}"`;
          break;
        }
        case 8: { // console
          const msg = r.getString();
          decoded = `"${msg.substring(0, 60)}"`;
          break;
        }
        case 10: { // animFX
          const id = r.getDouble();
          const shortId = String(id).substring(0, 8);
          const fxGrh = r.getShort();
          decoded = `id=${shortId} fx=${fxGrh}`;
          if (sniffer.entities[shortId]) {
            if (fxGrh === 0) {
              sniffer.entities[shortId].invisible = true;
              decoded += " [INVISIBLE]";
            } else {
              sniffer.entities[shortId].invisible = false;
            }
          }
          if (fxGrh > 0) trackCooldown("spellHit");
          break;
        }
        case 12: { // updateHP
          const hp = r.getShort();
          sniffer.player.hp = hp;
          decoded = `hp=${hp}`;
          break;
        }
        case 13: { // updateMaxHP
          const hp = r.getShort();
          const maxHp = r.getShort();
          sniffer.player.hp = hp;
          sniffer.player.maxHp = maxHp;
          decoded = `hp=${hp}/${maxHp}`;
          break;
        }
        case 14: { // updateMana
          const mana = r.getShort();
          sniffer.player.mana = mana;
          decoded = `mana=${mana}`;
          break;
        }
        case 15: { // telepMe
          const id = r.getDouble();
          const map = r.getShort();
          const x = r.getByte();
          const y = r.getByte();
          const heading = r.getByte();
          sniffer.player.map = map;
          sniffer.player.x = x;
          sniffer.player.y = y;
          sniffer.player.heading = heading;
          decoded = `map=${map} pos=(${x},${y}) dir=${DIR_NAMES[heading] || heading}`;
          break;
        }
        case 21: { // actPositionServer
          const map = r.getShort();
          const x = r.getByte();
          const y = r.getByte();
          const heading = r.getByte();
          const lastMoveId = r.getInt();
          sniffer.player.map = map;
          sniffer.player.x = x;
          sniffer.player.y = y;
          sniffer.player.heading = heading;
          decoded = `map=${map} pos=(${x},${y}) dir=${DIR_NAMES[heading] || heading} ackMove=${lastMoveId}`;
          trackCooldown("walkAck");
          break;
        }
        case 22: {
          const expVal = r.getDouble();
          sniffer.player.exp = expVal;
          decoded = `exp=${expVal}`;
          break;
        }
        case 23: { // actMyLevel - exp, expNextLevel, level, maxHp, maxMana
          const exp23 = r.getDouble();
          const expNext = r.getDouble();
          const level = r.getByte();
          const maxHp = r.getShort();
          const maxMana = r.getShort();
          sniffer.player.exp = exp23;
          sniffer.player.level = level;
          sniffer.player.maxHp = maxHp;
          sniffer.player.maxMana = maxMana;
          decoded = `lvl=${level} maxHp=${maxHp} maxMana=${maxMana}`;
          break;
        }
        case 24: {
          const gold = r.getInt();
          sniffer.player.gold = gold;
          decoded = `gold=${gold}`;
          break;
        }
        case 28: decoded = `"${r.getString().substring(0, 60)}"`; break;
        case 30: { // getNpc
          decoded = `[NPC data ${buf.byteLength}b]`;
          break;
        }
        case 39: { // blockMap
          const bMap = r.getShort();
          const bx = r.getByte();
          const by = r.getByte();
          const blocked = r.getByte();
          if (!sniffer.blockedTiles[bMap]) sniffer.blockedTiles[bMap] = new Set();
          if (blocked) sniffer.blockedTiles[bMap].add(bx + "," + by);
          else sniffer.blockedTiles[bMap].delete(bx + "," + by);
          decoded = `map=${bMap} (${bx},${by}) blocked=${blocked}`;
          break;
        }
        case 42: { // aprenderSpell
          decoded = `[spell data ${buf.byteLength}b]`;
          break;
        }
        case 35: { // renderItem
          const itemId = r.getShort();
          const map = r.getShort();
          const x = r.getByte();
          const y = r.getByte();
          decoded = `item=${itemId} pos=(${x},${y})`;
          break;
        }
        case 44: { // nameMap
          const mapName = r.getString();
          sniffer.mapName = mapName;
          decoded = `"${mapName}"`;
          break;
        }
        case 49: { // playSound
          const id = r.getDouble();
          const soundId = r.getShort();
          decoded = `sound=${soundId}`;
          break;
        }
        default:
          decoded = `[${buf.byteLength}b] ${r.rawBytes(12).join(",")}`;
          break;
      }
    } catch (e) { decoded = `(decode error: ${e.message})`; }

    return { op, name, decoded };
  }

  // Track server-side cooldowns (time between accepted actions)
  function trackCooldown(type) {
    const now = Date.now();
    if (!sniffer.serverCooldowns[type]) {
      sniffer.serverCooldowns[type] = { last: now, deltas: [] };
      return;
    }
    const cd = sniffer.serverCooldowns[type];
    const delta = now - cd.last;
    cd.deltas.push(delta);
    if (cd.deltas.length > 20) cd.deltas.shift();
    cd.last = now;
  }

  // ========================================
  // 6. WebSocket Interceptor
  // ========================================
  const OriginalWebSocket = window.WebSocket;
  let gameWS = null;
  let moveSeq = 1;

  window.WebSocket = new Proxy(OriginalWebSocket, {
    construct(target, args) {
      const ws = new target(...args);
      if (args[0] && args[0].includes("socket.aoweb")) {
        gameWS = ws;
        console.log("[AOWeb Audit] WebSocket captured:", args[0]);
        sniffer.playerSpells = [];

        const origSend = ws.send.bind(ws);
        ws.send = function (data) {
          if (data instanceof ArrayBuffer) {
            const view = new Uint8Array(data);
            // Track walk moveId
            if (view[0] === 6 && data.byteLength >= 6) {
              const dv = new DataView(data);
              const mid = dv.getUint32(2, true);
              if (mid >= moveSeq) moveSeq = mid + 1;
            }
            // Sniff
            const { op, name, decoded } = decodeClientPacket(data);
            logPacket(">>>", op, name, decoded, data.byteLength, Array.from(view.slice(0, 30)));
            hackState.packetsSent++;
          }
          return origSend(data);
        };

        ws.addEventListener("message", (e) => {
          if (!(e.data instanceof ArrayBuffer)) return;
          const view = new Uint8Array(e.data);
          // Sniff
          const { op, name, decoded } = decodeServerPacket(e.data);
          logPacket("<<<", op, name, decoded, e.data.byteLength, Array.from(view.slice(0, 30)));
          hackState.packetsRecv++;
        });
      }
      return ws;
    },
  });

  // Also patch prototype.send for clickTile capture
  const origProtoSend = OriginalWebSocket.prototype.send;
  OriginalWebSocket.prototype.send = function (data) {
    if (data instanceof ArrayBuffer) {
      const view = new Uint8Array(data);
      if (capturingTarget && view[0] === 2 && data.byteLength >= 4) {
        hackState.spellTargetX = view[1];
        hackState.spellTargetY = view[2];
        capturingTarget = false;
        const xInput = document.getElementById("a-tgt-x");
        const yInput = document.getElementById("a-tgt-y");
        if (xInput) xInput.value = hackState.spellTargetX;
        if (yInput) yInput.value = hackState.spellTargetY;
        showToast(`Target: (${hackState.spellTargetX}, ${hackState.spellTargetY}) - casting`);
        startSpellSpam();
        updateSpellButtons();
      }
    }
    return origProtoSend.call(this, data);
  };

  // ========================================
  // 7. Hack State
  // ========================================
  const hackState = {
    speedHackEnabled: false, speedInterval: null, speedDirection: 0, speedMs: 50,
    spellSpamEnabled: false, spellSpamInterval: null, spellSpamMs: 200,
    spellSlot: 0, spellTargetX: 0, spellTargetY: 0,
    autoTargetEnabled: false, autoTargetId: null,
    comboSlot1: 0, comboSlot2: 0, comboPhase: "first", // "first" | "spam"
    // Auto-walk
    autoWalkEnabled: false, autoWalkInterval: null, autoWalkPath: [],
    autoWalkTargetMap: 0, autoWalkTargetX: 0, autoWalkTargetY: 0, autoWalkMs: 150,
    autoWalkStuckCount: 0, autoWalkLastPos: null, autoWalkMapRoute: [], // [{map, x, y}]
    packetsSent: 0, packetsRecv: 0,
  };
  let capturingTarget = false;

  // Persist config to localStorage
  const CONFIG_KEY = "aoweb-audit-config";
  const CONFIG_FIELDS = ["speedMs","spellSpamMs","comboSlot1","comboSlot2","autoWalkMs"];

  function saveConfig() {
    const data = {};
    for (const f of CONFIG_FIELDS) data[f] = hackState[f];
    try { localStorage.setItem(CONFIG_KEY, JSON.stringify(data)); } catch (_) {}
  }

  function loadConfig() {
    try {
      const data = JSON.parse(localStorage.getItem(CONFIG_KEY));
      if (data) {
        for (const f of CONFIG_FIELDS) { if (data[f] !== undefined) hackState[f] = data[f]; }
        hackState.spellSlot = hackState.comboSlot2;
      }
    } catch (_) {}
  }

  loadConfig();

  // Fetch spell database from CDN
  fetch("https://aoweb.nyc3.cdn.digitaloceanspaces.com/init/spells.json")
    .then(r => r.json())
    .then(data => {
      sniffer.spellDB = data;
      console.log("[AOWeb Audit] Loaded", Object.keys(data).length, "spells from CDN");
    })
    .catch(() => {});

  // Fetch character settings to get spell list from macros + known spells
  fetch("/api/auth/character-settings", { credentials: "include" })
    .then(r => r.json())
    .then(data => {
      if (!data.macros) return;
      // Build spell list from macros (they have targetSlot + label)
      const spellMap = new Map(); // slot -> {slot, name, spellId}
      for (const m of data.macros) {
        if (m.targetType === "spell" && m.targetSlot !== undefined) {
          spellMap.set(m.targetSlot, { slot: m.targetSlot, name: m.label, spellId: m.targetId || 0 });
        }
      }
      // Also fill in from spellDB for any spells we know about
      // We'll also try to get the full spell list from the CDN data later
      if (spellMap.size > 0) {
        sniffer.playerSpells = [...spellMap.values()].sort((a, b) => a.slot - b.slot);
        console.log("[AOWeb Audit] Loaded", sniffer.playerSpells.length, "spells from character-settings");
        updateSpellDropdowns();
      }
    })
    .catch(() => {});

  // Persist radar config
  const RADAR_CONFIG_KEY = "aoweb-audit-radar";
  function saveRadarConfig() {
    const data = {};
    for (const id of ["a-radar-show","a-radar-names","a-esp-show","a-radar-entities"]) {
      const el = document.getElementById(id);
      if (el) data[id] = el.checked;
    }
    try { localStorage.setItem(RADAR_CONFIG_KEY, JSON.stringify(data)); } catch (_) {}
  }
  function loadRadarConfig() {
    try {
      const data = JSON.parse(localStorage.getItem(RADAR_CONFIG_KEY));
      if (!data) return;
      for (const [id, checked] of Object.entries(data)) {
        const el = document.getElementById(id);
        if (el) {
          el.checked = checked;
          el.dispatchEvent(new Event("change"));
        }
      }
    } catch (_) {}
  }

  // ========================================
  // 8. Hack Functions
  // ========================================
  function sendWalk(dir) {
    if (!gameWS || gameWS.readyState !== 1) return;
    gameWS.send(writePacket(6, byte(dir), int(moveSeq++)));
  }
  function sendSpell(slot, x, y) {
    if (!gameWS || gameWS.readyState !== 1) return;
    gameWS.send(writePacket(11, byte(slot), byte(x), byte(y)));
  }
  function sendMelee() {
    if (!gameWS || gameWS.readyState !== 1) return;
    gameWS.send(writePacket(9));
  }

  function startSpeedHack(dir) {
    stopSpeedHack();
    hackState.speedDirection = dir;
    hackState.speedHackEnabled = true;
    sendWalk(dir);
    hackState.speedInterval = setInterval(() => sendWalk(hackState.speedDirection), hackState.speedMs);
    updateUI();
  }
  function stopSpeedHack() {
    hackState.speedHackEnabled = false;
    hackState.speedDirection = 0;
    clearInterval(hackState.speedInterval);
    hackState.speedInterval = null;
    updateUI();
  }
  // Find nearest entity with a known position
  function findNearestEntity() {
    const p = sniffer.player;
    const now = Date.now();
    let best = null, bestDist = Infinity;
    for (const [id, ent] of Object.entries(sniffer.entities)) {
      if (ent.x <= 0 || now - ent.lastSeen > 15000) continue;
      const dist = Math.abs(ent.x - p.x) + Math.abs(ent.y - p.y);
      if (dist > 0 && dist < bestDist) { // dist > 0 to skip self
        bestDist = dist;
        best = { id, ent, dist };
      }
    }
    return best;
  }

  function spellSpamTick() {
    if (!gameWS || gameWS.readyState !== 1) return;

    // Auto-target mode: follow the locked entity
    if (hackState.autoTargetEnabled) {
      const locked = hackState.autoTargetId;
      const ent = locked ? sniffer.entities[locked] : null;

      // If locked entity is gone (dead/out of range), pick next nearest
      if (!ent || Date.now() - ent.lastSeen > 10000 || ent.x <= 0) {
        const next = findNearestEntity();
        if (next) {
          hackState.autoTargetId = next.id;
          hackState.spellTargetX = next.ent.x;
          hackState.spellTargetY = next.ent.y;
          hackState.comboPhase = "first"; // reset combo for new target
          updateAutoTargetUI();
        } else {
          // No targets available, keep waiting
          return;
        }
      } else {
        // Update target coords in case entity moved
        hackState.spellTargetX = ent.x;
        hackState.spellTargetY = ent.y;
      }
    }

    if (hackState.spellTargetX || hackState.spellTargetY) {
      // Combo: first cast uses slot1, then switch to slot2
      if (hackState.autoTargetEnabled && hackState.comboPhase === "first") {
        sendSpell(hackState.comboSlot1, hackState.spellTargetX, hackState.spellTargetY);
        hackState.comboPhase = "spam";
      } else if (hackState.autoTargetEnabled) {
        sendSpell(hackState.comboSlot2, hackState.spellTargetX, hackState.spellTargetY);
      } else {
        sendSpell(hackState.spellSlot, hackState.spellTargetX, hackState.spellTargetY);
      }
    }
  }

  function startSpellSpam() {
    stopSpellSpam();
    hackState.spellSpamEnabled = true;
    spellSpamTick();
    hackState.spellSpamInterval = setInterval(spellSpamTick, hackState.spellSpamMs);
    updateUI();
  }
  function stopSpellSpam() {
    hackState.spellSpamEnabled = false;
    clearInterval(hackState.spellSpamInterval);
    hackState.spellSpamInterval = null;
    updateUI();
  }

  function startAutoTarget() {
    const nearest = findNearestEntity();
    if (!nearest) return;
    hackState.autoTargetEnabled = true;
    hackState.autoTargetId = nearest.id;
    hackState.comboPhase = "first";
    hackState.spellTargetX = nearest.ent.x;
    hackState.spellTargetY = nearest.ent.y;
    updateAutoTargetUI();
    if (!hackState.spellSpamEnabled) startSpellSpam();
    else updateUI();
  }
  function stopAutoTarget() {
    hackState.autoTargetEnabled = false;
    hackState.autoTargetId = null;
    stopSpellSpam();
    updateAutoTargetUI();
  }
  function updateAutoTargetUI() {
    // Sync coord inputs
    const xInput = document.getElementById("a-tgt-x");
    const yInput = document.getElementById("a-tgt-y");
    if (xInput) xInput.value = hackState.spellTargetX;
    if (yInput) yInput.value = hackState.spellTargetY;
    updateSpellButtons();
  }

  function updateSpellDropdowns() {
    const spells = sniffer.playerSpells;
    if (spells.length === 0) return;
    for (const selId of ["a-combo-s1", "a-combo-s2"]) {
      const sel = document.getElementById(selId);
      if (!sel) continue;
      const currentVal = parseInt(sel.value) || 0;
      sel.innerHTML = spells.map(s =>
        `<option value="${s.slot}"${s.slot === currentVal ? " selected" : ""}>${s.slot}: ${s.name}</option>`
      ).join("");
    }
  }

  function updateSpellButtons() {
    const offDiv = document.getElementById("a-spell-btns-off");
    const onDiv = document.getElementById("a-spell-btns-on");
    const stopBtn = document.getElementById("a-spl-btn");
    if (!offDiv || !onDiv) return;

    const isActive = hackState.spellSpamEnabled || hackState.autoTargetEnabled || capturingTarget;

    if (isActive) {
      offDiv.style.display = "none";
      onDiv.style.display = "block";
      // Show what's active in the stop button
      if (capturingTarget) {
        stopBtn.textContent = "Click en mapa... (Detener)";
      } else if (hackState.autoTargetEnabled && hackState.autoTargetId) {
        const ent = sniffer.entities[hackState.autoTargetId];
        const name = ent?.name || hackState.autoTargetId;
        stopBtn.textContent = `Atacando: ${name} (Detener)`;
      } else {
        stopBtn.textContent = "Detener";
      }
    } else {
      offDiv.style.display = "block";
      onDiv.style.display = "none";
    }
  }

  // ========================================
  // 8b. A* Pathfinding + Auto-Walk
  // ========================================

  function isTileBlocked(x, y) {
    const map = sniffer.player.map;
    // Check blocked tiles from server
    if (sniffer.blockedTiles[map] && sniffer.blockedTiles[map].has(x + "," + y)) return true;
    // Check entity positions (temporary obstacles)
    const now = Date.now();
    for (const [, ent] of Object.entries(sniffer.entities)) {
      if (ent.x === x && ent.y === y && now - ent.lastSeen < 5000) return true;
    }
    return false;
  }

  function dirToOffset(dir) {
    if (dir === 1) return { dx: 0, dy: -1 }; // N
    if (dir === 2) return { dx: 0, dy: 1 };  // S
    if (dir === 3) return { dx: 1, dy: 0 };  // E
    if (dir === 4) return { dx: -1, dy: 0 }; // W
    return { dx: 0, dy: 0 };
  }

  function offsetToDir(dx, dy) {
    if (dx === 0 && dy === -1) return 1; // N
    if (dx === 0 && dy === 1) return 2;  // S
    if (dx === 1 && dy === 0) return 3;  // E
    if (dx === -1 && dy === 0) return 4; // W
    return 0;
  }

  function findPath(fromX, fromY, toX, toY) {
    // A* pathfinding - returns array of directions [1,2,3,4,...]
    if (fromX === toX && fromY === toY) return [];

    // Limit search area
    const maxDist = Math.abs(toX - fromX) + Math.abs(toY - fromY);
    const maxNodes = Math.max(5000, maxDist * maxDist);

    const key = (x, y) => x + "," + y;
    const open = [{ x: fromX, y: fromY, g: 0, f: 0, parent: null, dir: 0 }];
    const closed = new Set();
    const gScores = new Map();
    gScores.set(key(fromX, fromY), 0);

    const neighbors = [
      { dx: 0, dy: -1, dir: 1 }, // N
      { dx: 0, dy: 1, dir: 2 },  // S
      { dx: 1, dy: 0, dir: 3 },  // E
      { dx: -1, dy: 0, dir: 4 }, // W
    ];

    let iterations = 0;
    while (open.length > 0 && iterations < maxNodes) {
      iterations++;
      // Find node with lowest f
      let bestIdx = 0;
      for (let i = 1; i < open.length; i++) {
        if (open[i].f < open[bestIdx].f) bestIdx = i;
      }
      const current = open.splice(bestIdx, 1)[0];
      const ck = key(current.x, current.y);

      if (current.x === toX && current.y === toY) {
        // Reconstruct path
        const dirs = [];
        let node = current;
        while (node.parent) {
          dirs.unshift(node.dir);
          node = node.parent;
        }
        return dirs;
      }

      closed.add(ck);

      for (const n of neighbors) {
        const nx = current.x + n.dx;
        const ny = current.y + n.dy;
        const nk = key(nx, ny);

        if (closed.has(nk)) continue;
        if (nx < 1 || ny < 1 || nx > 200 || ny > 200) continue;
        // Allow target tile even if "blocked" (might be an NPC we want to reach near)
        if (!(nx === toX && ny === toY) && isTileBlocked(nx, ny)) continue;

        const g = current.g + 1;
        if (gScores.has(nk) && g >= gScores.get(nk)) continue;

        gScores.set(nk, g);
        const h = Math.abs(nx - toX) + Math.abs(ny - toY);
        open.push({ x: nx, y: ny, g, f: g + h, parent: current, dir: n.dir });
      }
    }

    return null; // No path found
  }

  // BFS to find route between maps using the grid graph
  // Returns array of {toMap, dir} hops, where dir is the direction to walk to reach toMap
  function findMapRoute(fromMap, toMap) {
    if (fromMap === toMap) return [];
    const queue = [{ map: fromMap, path: [] }];
    const visited = new Set([fromMap]);
    while (queue.length > 0) {
      const { map, path } = queue.shift();
      const neighbors = sniffer.mapGraph[map];
      if (!neighbors) continue;
      for (const [dir, neighborMap] of Object.entries(neighbors)) {
        if (visited.has(neighborMap)) continue;
        const hop = { toMap: neighborMap, dir }; // dir: "n","s","e","w"
        const newPath = [...path, hop];
        if (neighborMap === toMap) return newPath;
        visited.add(neighborMap);
        queue.push({ map: neighborMap, path: newPath });
      }
    }
    return null;
  }

  function autoWalkTick() {
    if (!gameWS || gameWS.readyState !== 1) { stopAutoWalk(); return; }
    const p = sniffer.player;
    const targetMap = hackState.autoWalkTargetMap || p.map;
    const tx = hackState.autoWalkTargetX;
    const ty = hackState.autoWalkTargetY;

    // Determine immediate target: if on different map, walk to the map transition point
    let immediateX = tx, immediateY = ty;

    if (p.map !== targetMap) {
      // Need cross-map navigation
      if (hackState.autoWalkMapRoute.length === 0) {
        const route = findMapRoute(p.map, targetMap);
        if (!route) {
          showToast(`No route from map ${p.map} to map ${targetMap}`);
          stopAutoWalk();
          return;
        }
        hackState.autoWalkMapRoute = route;
      }

      // Consume hops we already transitioned through
      while (hackState.autoWalkMapRoute.length > 0) {
        const hop = hackState.autoWalkMapRoute[0];
        // Check if we already passed this hop (we're on or past this map)
        if (hop.toMap === p.map) {
          hackState.autoWalkMapRoute.shift();
          hackState.autoWalkPath = []; // recalculate on new map
          continue;
        }
        break;
      }

      if (hackState.autoWalkMapRoute.length > 0) {
        // Use A* to walk to the map edge in the direction of next hop
        const nextHop = hackState.autoWalkMapRoute[0];
        // Calculate edge target: walk to the extreme coordinate in that direction
        // Maps are roughly 100x100 tiles (1-100 range)
        if (nextHop.dir === "n") immediateX = p.x, immediateY = 1;
        else if (nextHop.dir === "s") immediateX = p.x, immediateY = 100;
        else if (nextHop.dir === "e") immediateX = 100, immediateY = p.y;
        else if (nextHop.dir === "w") immediateX = 1, immediateY = p.y;
        // Fall through to A* pathfinding below
      }
    }

    // Arrived at final destination?
    if (p.map === targetMap && p.x === tx && p.y === ty) {
      showToast(`Arrived at map ${targetMap} (${tx}, ${ty})`);
      stopAutoWalk();
      return;
    }

    // At map edge and need to cross? Send one more step in the edge direction
    if (hackState.autoWalkMapRoute.length > 0) {
      const nextHop = hackState.autoWalkMapRoute[0];
      const edgeDir = { n: 1, s: 2, e: 3, w: 4 }[nextHop.dir];
      const atEdge = (nextHop.dir === "n" && p.y <= 1) ||
                     (nextHop.dir === "s" && p.y >= 100) ||
                     (nextHop.dir === "e" && p.x >= 100) ||
                     (nextHop.dir === "w" && p.x <= 1);
      if (atEdge) {
        sendWalk(edgeDir);
        updateAutoWalkUI();
        return;
      }
    }

    // Detect stuck
    const curPos = p.map + ":" + p.x + "," + p.y;
    if (hackState.autoWalkLastPos === curPos) {
      hackState.autoWalkStuckCount++;
      if (hackState.autoWalkStuckCount >= 3) {
        if (hackState.autoWalkPath.length > 0) {
          const failedDir = hackState.autoWalkPath[0];
          const off = dirToOffset(failedDir);
          const bx = p.x + off.dx;
          const by = p.y + off.dy;
          if (!sniffer.blockedTiles[p.map]) sniffer.blockedTiles[p.map] = new Set();
          sniffer.blockedTiles[p.map].add(bx + "," + by);
        }
        hackState.autoWalkPath = [];
        hackState.autoWalkStuckCount = 0;
      }
    } else {
      hackState.autoWalkStuckCount = 0;
      hackState.autoWalkLastPos = curPos;
      if (hackState.autoWalkPath.length > 0) hackState.autoWalkPath.shift();
      // Map changed? recalculate
      if (p.map !== targetMap) {
        hackState.autoWalkMapRoute = [];
      }
    }

    // Recalculate path if needed
    if (hackState.autoWalkPath.length === 0) {
      const path = findPath(p.x, p.y, immediateX, immediateY);
      if (!path || path.length === 0) {
        showToast("No path found on this map!");
        stopAutoWalk();
        return;
      }
      hackState.autoWalkPath = path;
    }

    const nextDir = hackState.autoWalkPath[0];
    if (nextDir) sendWalk(nextDir);

    updateAutoWalkUI();
  }

  function startAutoWalk() {
    stopAutoWalk();
    if (!hackState.autoWalkTargetX && !hackState.autoWalkTargetY) return;
    if (!hackState.autoWalkTargetMap) hackState.autoWalkTargetMap = sniffer.player.map;
    hackState.autoWalkEnabled = true;
    hackState.autoWalkPath = [];
    hackState.autoWalkMapRoute = [];
    hackState.autoWalkStuckCount = 0;
    hackState.autoWalkLastPos = null;
    autoWalkTick();
    hackState.autoWalkInterval = setInterval(autoWalkTick, hackState.autoWalkMs);
    updateAutoWalkUI();
  }

  function stopAutoWalk() {
    hackState.autoWalkEnabled = false;
    hackState.autoWalkPath = [];
    clearInterval(hackState.autoWalkInterval);
    hackState.autoWalkInterval = null;
    updateAutoWalkUI();
  }

  function updateAutoWalkUI() {
    const btn = document.getElementById("a-walk-btn");
    if (!btn) return;
    if (hackState.autoWalkEnabled) {
      const rem = hackState.autoWalkPath.length;
      const mapHops = hackState.autoWalkMapRoute.length;
      const status = mapHops > 0 ? `${rem} steps, ${mapHops} maps left` : `${rem} steps`;
      btn.textContent = `Walking... (${status})`;
      btn.classList.add("on");
    } else {
      btn.textContent = "Walk To";
      btn.classList.remove("on");
    }
    const routesEl = document.getElementById("a-walk-routes");
    if (routesEl) {
      const mapCount = Object.keys(sniffer.mapGraph).length;
      if (hackState.autoWalkEnabled && hackState.autoWalkMapRoute.length > 0) {
        const maps = hackState.autoWalkMapRoute.map(h => h.toMap).join(" → ");
        routesEl.textContent = `Ruta: map ${sniffer.player.map} → ${maps}`;
      } else {
        routesEl.textContent = `${mapCount} mapas en el grafo`;
      }
    }
  }

  // ========================================
  // 9. Keyboard Hooks
  // ========================================
  const directionKeys = { w: 1, s: 2, d: 3, a: 4 };
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA") return;
    if (e.key === "H" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      hackState.speedHackEnabled ? stopSpeedHack() : startSpeedHack(hackState.speedDirection || 1);
      return;
    }
    if (hackState.speedHackEnabled && directionKeys[e.key]) {
      e.preventDefault(); e.stopPropagation();
      if (directionKeys[e.key] !== hackState.speedDirection) startSpeedHack(directionKeys[e.key]);
      return;
    }
    // Shift+S = toggle target selection / stop everything
    if (e.key === "S" && e.shiftKey && !hackState.speedHackEnabled) {
      e.preventDefault(); e.stopPropagation();
      if (!capturingTarget && !hackState.spellSpamEnabled && !hackState.autoTargetEnabled) {
        capturingTarget = true;
        updateSpellButtons();
        showToast("Click en el mapa para seleccionar target");
      } else {
        capturingTarget = false;
        stopAutoTarget();
        stopSpellSpam();
        hackState.spellTargetX = 0;
        hackState.spellTargetY = 0;
        const xInput = document.getElementById("a-tgt-x");
        const yInput = document.getElementById("a-tgt-y");
        if (xInput) xInput.value = 0;
        if (yInput) yInput.value = 0;
        updateSpellButtons();
        showToast("Spell spam detenido");
      }
      return;
    }
    // Shift+A = toggle auto-cast
    if (e.key === "A" && e.shiftKey && !hackState.speedHackEnabled) {
      e.preventDefault(); e.stopPropagation();
      if (hackState.autoTargetEnabled) stopAutoTarget();
      else startAutoTarget();
      return;
    }
    if (e.key === "P" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      togglePanel();
      return;
    }
    // Shift+G = toggle auto-walk
    if (e.key === "G" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      hackState.autoWalkEnabled ? stopAutoWalk() : startAutoWalk();
      return;
    }
    // Shift+R = toggle radar
    if (e.key === "R" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      const cb = document.getElementById("a-radar-show");
      if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event("change")); }
      return;
    }
    // Shift+E = copy sniffer data to clipboard
    if (e.key === "E" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      copySnifferToClipboard();
      return;
    }
  }, true);

  // ========================================
  // 10. UI Panel
  // ========================================
  let panelEl = null;
  let activeTab = "spell";
  const PANEL_CSS = `
    #aoweb-audit-panel {
      position:fixed; top:10px; right:10px; z-index:999999;
      background:rgba(0,0,0,0.94); color:#e0c080; border:1px solid #8b6914;
      border-radius:6px; padding:10px; font-family:monospace; font-size:11px;
      width:340px; max-height:90vh; overflow-y:auto; user-select:none; cursor:move;
    }
    #aoweb-audit-panel h3 { margin:0 0 6px; color:#ffd700; font-size:13px; text-align:center; }
    #aoweb-audit-panel .sec { margin:6px 0; padding:5px; border:1px solid #3a3000; border-radius:4px; }
    #aoweb-audit-panel .sec-title { color:#aaa; font-size:9px; text-transform:uppercase; margin-bottom:3px; letter-spacing:1px; }
    #aoweb-audit-panel label { display:block; margin:2px 0; color:#ccc; font-size:10px; }
    #aoweb-audit-panel input[type="number"] {
      width:55px; background:#1a1a00; color:#ffd700; border:1px solid #555;
      padding:1px 3px; border-radius:3px; font-family:monospace; font-size:10px;
    }
    #aoweb-audit-panel button {
      background:#3a3000; color:#ffd700; border:1px solid #8b6914;
      padding:3px 8px; border-radius:3px; cursor:pointer; font-family:monospace; font-size:10px; margin:1px;
    }
    #aoweb-audit-panel button:hover { background:#554a00; }
    #aoweb-audit-panel button.on { background:#006600; border-color:#00aa00; color:#0f0; }
    #aoweb-audit-panel button.danger { background:#660000; border-color:#aa0000; color:#f44; }
    #aoweb-audit-panel .st { color:#888; font-size:9px; }
    #aoweb-audit-panel .v { color:#ffd700; }
    #aoweb-audit-panel .hk { color:#555; font-size:8px; }
    #aoweb-audit-panel .con { color:#0f0; }
    #aoweb-audit-panel .dis { color:#f00; }
    /* Tabs */
    #audit-tabs { display:flex; gap:2px; margin:6px 0 4px; flex-wrap:wrap; }
    #audit-tabs button { flex:1; min-width:0; padding:4px 2px; font-size:9px; text-align:center; border-bottom:2px solid transparent; }
    #audit-tabs button.tab-active { background:#2a2a00; border-bottom:2px solid #ffd700; color:#ffd700; }
    .tab-content { display:none; }
    .tab-content.tab-visible { display:block; }
    /* Sniffer log */
    #audit-sniffer-log {
      background:#0a0a00; border:1px solid #333; border-radius:3px;
      max-height:200px; overflow-y:auto; padding:3px; font-size:9px; line-height:1.3;
    }
    #audit-sniffer-log .pkt { border-bottom:1px solid #1a1a00; padding:1px 0; }
    #audit-sniffer-log .send { color:#ff9944; }
    #audit-sniffer-log .recv { color:#44aaff; }
    #audit-sniffer-log .op { color:#ffd700; font-weight:bold; }
    #audit-sniffer-log .dec { color:#aaa; }
    #audit-sniffer-log .ts { color:#555; }
    /* Entity list */
    #audit-entity-list {
      background:#0a0a00; border:1px solid #333; border-radius:3px;
      max-height:120px; overflow-y:auto; padding:3px; font-size:9px;
    }
    #audit-entity-list .ent { color:#88cc88; padding:1px 0; }
    #audit-entity-list .ent-name { color:#ffd700; }
    /* Cooldown tracker */
    #audit-cooldowns { font-size:9px; color:#aaa; }
    #audit-cooldowns .cd-val { color:#ff6666; }
    /* Radar */
    #audit-radar-wrap { position:relative; }
    #audit-radar {
      background:rgba(0,10,0,0.85); border:1px solid #335533; border-radius:4px;
      display:block; margin:0 auto; cursor:crosshair;
    }
  `;

  function switchTab(tab) {
    activeTab = tab;
    document.querySelectorAll("#aoweb-audit-panel .tab-content").forEach(el => el.classList.remove("tab-visible"));
    document.querySelectorAll("#audit-tabs button").forEach(btn => btn.classList.remove("tab-active"));
    const content = document.getElementById("tab-" + tab);
    const btn = document.getElementById("tabbtn-" + tab);
    if (content) content.classList.add("tab-visible");
    if (btn) btn.classList.add("tab-active");
  }

  function createPanel() {
    if (panelEl) return;
    panelEl = document.createElement("div");
    panelEl.id = "aoweb-audit-panel";
    panelEl.innerHTML = `
      <style>${PANEL_CSS}</style>
      <h3>AOWeb Security Audit</h3>
      <div class="st">
        WS:<span id="a-ws" class="dis">?</span>
        | Pos:<span id="a-pos" class="v">?</span>
        | HP:<span id="a-hp" class="v">?</span>
        | MP:<span id="a-mp" class="v">?</span>
        | Gold:<span id="a-gold" class="v">?</span>
        <br>TX:<span id="a-tx" class="v">0</span> RX:<span id="a-rx" class="v">0</span>
        | Map:<span id="a-map" class="v">?</span>
      </div>

      <!-- RADAR (always visible) -->
      <div class="sec">
        <div class="sec-title">Radar <span class="hk">Shift+R | click=target | ctrl+click=walk</span></div>
        <label style="display:inline"><input type="checkbox" id="a-radar-show" checked> Radar</label>
        <label style="display:inline;margin-left:6px"><input type="checkbox" id="a-radar-names" checked> Nombres</label>
        <label style="display:inline;margin-left:6px"><input type="checkbox" id="a-esp-show" checked> <span style="color:#ff44cc">ESP</span></label>
        <label style="display:inline;margin-left:6px"><input type="checkbox" id="a-radar-entities" checked> Entidades</label>
        <div id="audit-radar-wrap">
          <canvas id="audit-radar" width="310" height="310"></canvas>
        </div>
        <div id="audit-entity-list"></div>
      </div>

      <!-- TABS -->
      <div id="audit-tabs">
        <button id="tabbtn-spell" class="tab-active">Spell</button>
        <button id="tabbtn-melee">Melee</button>
        <button id="tabbtn-speed">Speed</button>
        <button id="tabbtn-walk">Walk</button>
        <button id="tabbtn-sniffer">Sniffer</button>
      </div>

      <!-- TAB: SPELL SPAM -->
      <div id="tab-spell" class="tab-content tab-visible">
        <div class="sec">
          <div class="sec-title">Spell Spam <span class="hk">Shift+S=target | Shift+A=cast</span></div>
          <label>Intervalo: <input type="number" id="a-spl-ms" value="200" min="0" max="2000" step="50">ms</label>
          <label>Slot 1 (inicial): <select id="a-combo-s1" style="background:#1a1a00;color:#ffd700;border:1px solid #555;border-radius:3px;font-family:monospace;font-size:10px;max-width:130px"><option value="0">0: (cargando...)</option></select></label>
          <label>Slot 2 (spam): <select id="a-combo-s2" style="background:#1a1a00;color:#ffd700;border:1px solid #555;border-radius:3px;font-family:monospace;font-size:10px;max-width:130px"><option value="0">0: (cargando...)</option></select></label>
          <label>Target X:<input type="number" id="a-tgt-x" value="0" min="0" max="255">
            Y:<input type="number" id="a-tgt-y" value="0" min="0" max="255"></label>
          <div id="a-spell-btns-off">
            <button id="a-tgt-btn">Capturar Target</button>
            <button id="a-autotgt-btn" style="background:#440044;border-color:#aa00aa;color:#ff88ff">Auto-Target + Spam</button>
          </div>
          <div id="a-spell-btns-on" style="display:none">
            <button id="a-spl-btn" class="danger">Detener</button>
          </div>
          <span class="hk">normal=850ms | auto-target sigue al target</span>
        </div>
      </div>

      <!-- TAB: MELEE SPAM -->
      <div id="tab-melee" class="tab-content">
        <div class="sec">
          <div class="sec-title">Melee Spam</div>
          <label>Intervalo: <input type="number" id="a-mel-ms" value="400" min="0" max="2000" step="50">ms</label>
          <button id="a-mel-btn">Activar</button>
          <span class="hk">normal=950ms</span>
        </div>
      </div>

      <!-- TAB: SPEED HACK -->
      <div id="tab-speed" class="tab-content">
        <div class="sec">
          <div class="sec-title">Speed Hack <span class="hk">Shift+H | WASD</span></div>
          <label>Intervalo: <input type="number" id="a-spd-ms" value="50" min="1" max="1000" step="10">ms</label>
          <button id="a-spd-btn">Activar</button>
          <span class="hk">normal=100ms server~150ms</span>
        </div>
      </div>

      <!-- TAB: AUTO-WALK -->
      <div id="tab-walk" class="tab-content">
        <div class="sec">
          <div class="sec-title">Auto-Walk <span class="hk">Shift+G | Ctrl+click radar</span></div>
          <label>Map:<input type="number" id="a-walk-map" value="0" min="0" max="999" style="width:40px">
            X:<input type="number" id="a-walk-x" value="0" min="0" max="255">
            Y:<input type="number" id="a-walk-y" value="0" min="0" max="255">
            <input type="number" id="a-walk-ms" value="150" min="50" max="1000" step="50" style="width:40px">ms</label>
          <button id="a-walk-btn">Walk To</button>
          <button id="a-walk-stop">Stop</button>
          <span class="hk" id="a-walk-status"></span>
          <div class="hk" id="a-walk-routes"></div>
        </div>
      </div>

      <!-- TAB: SNIFFER -->
      <div id="tab-sniffer" class="tab-content">
        <div class="sec">
          <div class="sec-title">Packet Sniffer <span class="hk">Shift+E = export</span></div>
          <button id="a-sniff-toggle">Pausar</button>
          <button id="a-sniff-clear">Limpiar</button>
          <button id="a-sniff-copy">Copiar al Clipboard</button>
          <button id="a-sniff-download">Descargar JSON</button>
          <label style="display:inline"><input type="checkbox" id="a-sniff-showlog"> Mostrar log</label>
          <div id="a-sniff-toast" style="display:none;color:#0f0;font-size:9px;margin-top:2px"></div>
          <div id="audit-sniffer-log" style="display:none">
            <label style="margin:2px 0"><input type="checkbox" id="a-sniff-ping" checked> Ocultar ping/pong</label>
            <div id="audit-sniffer-log-entries"></div>
          </div>
        </div>
        <div class="sec">
          <div class="sec-title">Server Cooldowns (medidos)</div>
          <div id="audit-cooldowns"></div>
        </div>
      </div>

      <div class="hk" style="text-align:center;margin-top:4px">Shift+P=panel | Shift+E=export</div>
    `;
    document.body.appendChild(panelEl);

    // Tab click handlers
    document.querySelectorAll("#audit-tabs button").forEach(btn => {
      btn.addEventListener("click", () => switchTab(btn.id.replace("tabbtn-", "")));
    });

    // Restore saved config into inputs
    document.getElementById("a-spd-ms").value = hackState.speedMs;
    document.getElementById("a-spl-ms").value = hackState.spellSpamMs;
    document.getElementById("a-walk-ms").value = hackState.autoWalkMs;
    // Combo dropdowns are restored after spells load (see restoreDropdowns interval)

    setupPanelEvents();
    loadRadarConfig();
  }

  function setupPanelEvents() {
    // Draggable
    let isDrag = false, dx, dy;
    panelEl.addEventListener("mousedown", (e) => {
      if (["INPUT","BUTTON","LABEL"].includes(e.target.tagName)) return;
      isDrag = true; dx = e.clientX - panelEl.offsetLeft; dy = e.clientY - panelEl.offsetTop;
    });
    document.addEventListener("mousemove", (e) => {
      if (!isDrag) return;
      panelEl.style.left = (e.clientX - dx) + "px";
      panelEl.style.top = (e.clientY - dy) + "px";
      panelEl.style.right = "auto";
    });
    document.addEventListener("mouseup", () => { isDrag = false; });

    // Speed hack
    const spdMs = document.getElementById("a-spd-ms");
    spdMs.addEventListener("change", () => {
      hackState.speedMs = parseInt(spdMs.value) || 50;
      saveConfig();
      if (hackState.speedHackEnabled) startSpeedHack(hackState.speedDirection);
    });
    document.getElementById("a-spd-btn").addEventListener("click", () => {
      hackState.speedHackEnabled ? stopSpeedHack() : startSpeedHack(1);
    });

    // Spell spam
    document.getElementById("a-spl-ms").addEventListener("change", (e) => {
      hackState.spellSpamMs = parseInt(e.target.value) || 200;
      saveConfig();
      if (hackState.spellSpamEnabled) startSpellSpam();
    });
    document.getElementById("a-combo-s1").addEventListener("change", (e) => {
      hackState.comboSlot1 = parseInt(e.target.value) || 0;
      saveConfig();
    });
    document.getElementById("a-combo-s2").addEventListener("change", (e) => {
      hackState.comboSlot2 = parseInt(e.target.value) || 0;
      hackState.spellSlot = hackState.comboSlot2;
      saveConfig();
    });
    // Retry loading spells from API if not loaded yet
    const spellRetry = setInterval(() => {
      if (sniffer.playerSpells.length > 0) { clearInterval(spellRetry); return; }
      fetch("/api/auth/character-settings", { credentials: "include" })
        .then(r => r.json())
        .then(data => {
          if (!data.macros) return;
          const spellMap = new Map();
          for (const m of data.macros) {
            if (m.targetType === "spell" && m.targetSlot !== undefined) {
              spellMap.set(m.targetSlot, { slot: m.targetSlot, name: m.label, spellId: m.targetId || 0 });
            }
          }
          if (spellMap.size > 0) {
            sniffer.playerSpells = [...spellMap.values()].sort((a, b) => a.slot - b.slot);
            updateSpellDropdowns();
            clearInterval(spellRetry);
          }
        }).catch(() => {});
    }, 3000);
    document.getElementById("a-tgt-x").addEventListener("change", (e) => {
      hackState.spellTargetX = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-tgt-y").addEventListener("change", (e) => {
      hackState.spellTargetY = parseInt(e.target.value) || 0;
    });
    // Detener button - stops everything
    document.getElementById("a-spl-btn").addEventListener("click", () => {
      capturingTarget = false;
      stopAutoTarget();
      stopSpellSpam();
      hackState.spellTargetX = 0;
      hackState.spellTargetY = 0;
      const xInput = document.getElementById("a-tgt-x");
      const yInput = document.getElementById("a-tgt-y");
      if (xInput) xInput.value = 0;
      if (yInput) yInput.value = 0;
      updateSpellButtons();
    });
    // Capturar Target button
    document.getElementById("a-tgt-btn").addEventListener("click", () => {
      capturingTarget = true;
      updateSpellButtons();
    });
    document.getElementById("a-autotgt-btn").addEventListener("click", () => {
      startAutoTarget();
    });

    // Melee spam
    let meleeInt = null;
    document.getElementById("a-mel-btn").addEventListener("click", (e) => {
      if (meleeInt) {
        clearInterval(meleeInt); meleeInt = null;
        e.target.textContent = "Activar"; e.target.classList.remove("on");
      } else {
        const ms = parseInt(document.getElementById("a-mel-ms").value) || 400;
        sendMelee();
        meleeInt = setInterval(sendMelee, ms);
        e.target.textContent = "Detener"; e.target.classList.add("on");
      }
    });

    // Sniffer controls
    document.getElementById("a-sniff-toggle").addEventListener("click", (e) => {
      sniffer.enabled = !sniffer.enabled;
      e.target.textContent = sniffer.enabled ? "Pausar" : "Reanudar";
      e.target.classList.toggle("on", !sniffer.enabled);
    });
    document.getElementById("a-sniff-clear").addEventListener("click", () => {
      sniffer.packetLog = [];
      sniffer.serverCooldowns = {};
      sniffer.entities = {};
      renderSnifferLog();
    });
    document.getElementById("a-sniff-copy").addEventListener("click", copySnifferToClipboard);
    document.getElementById("a-sniff-download").addEventListener("click", exportSnifferData);
    document.getElementById("a-sniff-ping").addEventListener("change", (e) => {
      sniffer.hidePing = e.target.checked;
    });
    document.getElementById("a-sniff-showlog").addEventListener("change", (e) => {
      document.getElementById("audit-sniffer-log").style.display = e.target.checked ? "block" : "none";
    });

    // Radar controls - all save to localStorage
    const radarCheckboxes = ["a-radar-show", "a-radar-names", "a-esp-show", "a-radar-entities"];
    document.getElementById("a-radar-show").addEventListener("change", (e) => {
      document.getElementById("audit-radar-wrap").style.display = e.target.checked ? "block" : "none";
      saveRadarConfig();
    });
    document.getElementById("a-radar-names").addEventListener("change", () => saveRadarConfig());
    document.getElementById("a-esp-show").addEventListener("change", (e) => {
      sniffer.espEnabled = e.target.checked;
      if (!e.target.checked && overlayCanvas) {
        const ctx = overlayCanvas.getContext("2d");
        ctx.clearRect(0, 0, overlayCanvas.width, overlayCanvas.height);
      }
      saveRadarConfig();
    });
    document.getElementById("a-radar-entities").addEventListener("change", (e) => {
      document.getElementById("audit-entity-list").style.display = e.target.checked ? "block" : "none";
      saveRadarConfig();
    });
    // Click on radar to set spell target
    // Click on radar: normal click = spell target, Ctrl+click = auto-walk destination
    document.getElementById("audit-radar").addEventListener("click", (e) => {
      const canvas = e.target;
      const rect = canvas.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const scale = canvas.width / RADAR_SIZE;
      const tileX = Math.round(sniffer.player.x + (cx / scale - RADAR_SIZE / 2));
      const tileY = Math.round(sniffer.player.y + (cy / scale - RADAR_SIZE / 2));

      if (e.ctrlKey || e.metaKey) {
        // Ctrl+click = set auto-walk destination
        hackState.autoWalkTargetX = tileX;
        hackState.autoWalkTargetY = tileY;
        document.getElementById("a-walk-x").value = tileX;
        document.getElementById("a-walk-y").value = tileY;
        startAutoWalk();
        showToast(`Walking to (${tileX}, ${tileY})`);
      } else {
        hackState.spellTargetX = tileX;
        hackState.spellTargetY = tileY;
        const xInput = document.getElementById("a-tgt-x");
        const yInput = document.getElementById("a-tgt-y");
        if (xInput) xInput.value = tileX;
        if (yInput) yInput.value = tileY;
        showToast(`Spell target: (${tileX}, ${tileY})`);
      }
    });

    // Auto-walk controls
    document.getElementById("a-walk-map").addEventListener("change", (e) => {
      hackState.autoWalkTargetMap = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-walk-x").addEventListener("change", (e) => {
      hackState.autoWalkTargetX = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-walk-y").addEventListener("change", (e) => {
      hackState.autoWalkTargetY = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-walk-ms").addEventListener("change", (e) => {
      hackState.autoWalkMs = parseInt(e.target.value) || 150;
      saveConfig();
    });
    document.getElementById("a-walk-btn").addEventListener("click", () => {
      hackState.autoWalkEnabled ? stopAutoWalk() : startAutoWalk();
    });
    document.getElementById("a-walk-stop").addEventListener("click", stopAutoWalk);
  }

  // ========================================
  // 11. Sniffer UI Rendering
  // ========================================
  let logRenderPending = false;
  function renderSnifferLog() {
    if (logRenderPending) return;
    logRenderPending = true;
    requestAnimationFrame(() => {
      logRenderPending = false;
      const el = document.getElementById("audit-sniffer-log-entries");
      if (!el) return;

      // Show last 50 packets
      const recent = sniffer.packetLog.slice(-50);
      el.innerHTML = recent.map(p => {
        const cls = p.dir === ">>>" ? "send" : "recv";
        const time = new Date(p.t).toLocaleTimeString("en", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit", fractionalSecondDigits: 3 });
        return `<div class="pkt ${cls}"><span class="ts">${time}</span> ${p.dir} <span class="op">[${p.op}]</span> ${p.name} <span class="dec">${p.decoded}</span> <span class="ts">${p.size}b</span></div>`;
      }).join("");

      // Auto-scroll to bottom
      el.scrollTop = el.scrollHeight;
    });
  }

  // ========================================
  // 11b. Radar Rendering
  // ========================================
  const RADAR_SIZE = 31; // tiles visible in each direction (31x31 grid)
  const RADAR_PX = 310;  // canvas pixel size
  const TILE_PX = RADAR_PX / RADAR_SIZE; // ~10px per tile

  function renderRadar() {
    const canvas = document.getElementById("audit-radar");
    if (!canvas || canvas.offsetParent === null) return; // hidden
    const ctx = canvas.getContext("2d");
    const p = sniffer.player;
    const half = Math.floor(RADAR_SIZE / 2);
    const showNames = document.getElementById("a-radar-names")?.checked;

    // Clear
    ctx.fillStyle = "rgba(0, 10, 0, 0.9)";
    ctx.fillRect(0, 0, RADAR_PX, RADAR_PX);

    // Grid lines (subtle)
    ctx.strokeStyle = "rgba(50, 80, 50, 0.3)";
    ctx.lineWidth = 0.5;
    for (let i = 0; i <= RADAR_SIZE; i++) {
      const px = i * TILE_PX;
      ctx.beginPath(); ctx.moveTo(px, 0); ctx.lineTo(px, RADAR_PX); ctx.stroke();
      ctx.beginPath(); ctx.moveTo(0, px); ctx.lineTo(RADAR_PX, px); ctx.stroke();
    }

    // Center crosshair (player position)
    const centerPx = half * TILE_PX + TILE_PX / 2;
    ctx.strokeStyle = "rgba(100, 200, 100, 0.4)";
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(centerPx, 0); ctx.lineTo(centerPx, RADAR_PX); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(0, centerPx); ctx.lineTo(RADAR_PX, centerPx); ctx.stroke();

    // Draw spell target
    if (hackState.spellTargetX || hackState.spellTargetY) {
      const tx = (hackState.spellTargetX - p.x + half) * TILE_PX;
      const ty = (hackState.spellTargetY - p.y + half) * TILE_PX;
      if (tx >= 0 && tx < RADAR_PX && ty >= 0 && ty < RADAR_PX) {
        ctx.strokeStyle = "#ff0000";
        ctx.lineWidth = 2;
        ctx.strokeRect(tx, ty, TILE_PX, TILE_PX);
        ctx.strokeStyle = "#ff000066";
        ctx.beginPath(); ctx.moveTo(tx + TILE_PX / 2, 0); ctx.lineTo(tx + TILE_PX / 2, RADAR_PX); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0, ty + TILE_PX / 2); ctx.lineTo(RADAR_PX, ty + TILE_PX / 2); ctx.stroke();
      }
    }

    // Draw entities
    const now = Date.now();
    const ents = Object.entries(sniffer.entities).filter(([, e]) => now - e.lastSeen < 30000 && e.x > 0);

    for (const [id, ent] of ents) {
      const dx = ent.x - p.x;
      const dy = ent.y - p.y;
      if (Math.abs(dx) > half || Math.abs(dy) > half) continue;

      const ex = (dx + half) * TILE_PX;
      const ey = (dy + half) * TILE_PX;

      // Color by type
      const isNpc = ent.type === "npc" || ent.name === "NPC";
      const isInvisible = ent.invisible === true;
      const age = (now - ent.lastSeen) / 1000;
      const alpha = Math.max(0.3, 1 - age / 30);

      if (isInvisible) {
        // Pulsing red/magenta for invisible entities
        const pulse = 0.5 + 0.5 * Math.sin(now / 150);
        ctx.fillStyle = `rgba(255, 0, ${Math.round(180 * pulse)}, ${alpha})`;
      } else if (isNpc) {
        ctx.fillStyle = `rgba(80, 160, 255, ${alpha})`; // blue for NPC
      } else {
        ctx.fillStyle = `rgba(255, 200, 50, ${alpha})`; // gold for player
      }

      // Draw dot (bigger for invisible)
      const dotSize = isInvisible ? TILE_PX * 0.55 : TILE_PX * 0.4;
      ctx.beginPath();
      ctx.arc(ex + TILE_PX / 2, ey + TILE_PX / 2, dotSize, 0, Math.PI * 2);
      ctx.fill();

      // Ring around invisible entities
      if (isInvisible) {
        const ringPulse = 0.4 + 0.6 * Math.sin(now / 300);
        ctx.strokeStyle = `rgba(255, 50, 200, ${ringPulse})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(ex + TILE_PX / 2, ey + TILE_PX / 2, TILE_PX * 0.8, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Heading indicator
      if (ent.heading) {
        const hx = ent.heading === 3 ? 1 : ent.heading === 4 ? -1 : 0;
        const hy = ent.heading === 2 ? 1 : ent.heading === 1 ? -1 : 0;
        ctx.strokeStyle = ctx.fillStyle;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(ex + TILE_PX / 2, ey + TILE_PX / 2);
        ctx.lineTo(ex + TILE_PX / 2 + hx * TILE_PX * 0.6, ey + TILE_PX / 2 + hy * TILE_PX * 0.6);
        ctx.stroke();
      }

      // Name label
      if (showNames && ent.name) {
        ctx.fillStyle = isInvisible ? "#ff44cc" : isNpc ? "#88bbff" : "#ffdd88";
        ctx.font = "8px monospace";
        ctx.textAlign = "center";
        ctx.fillText(ent.name.substring(0, 12), ex + TILE_PX / 2, ey - 2);
      }
    }

    // Draw player (center, green triangle)
    ctx.fillStyle = "#00ff00";
    ctx.beginPath();
    const px = centerPx, py = centerPx;
    const h = sniffer.player.heading;
    if (h === 1) { // North
      ctx.moveTo(px, py - 5); ctx.lineTo(px - 4, py + 4); ctx.lineTo(px + 4, py + 4);
    } else if (h === 2) { // South
      ctx.moveTo(px, py + 5); ctx.lineTo(px - 4, py - 4); ctx.lineTo(px + 4, py - 4);
    } else if (h === 3) { // East
      ctx.moveTo(px + 5, py); ctx.lineTo(px - 4, py - 4); ctx.lineTo(px - 4, py + 4);
    } else if (h === 4) { // West
      ctx.moveTo(px - 5, py); ctx.lineTo(px + 4, py - 4); ctx.lineTo(px + 4, py + 4);
    } else {
      ctx.arc(px, py, 4, 0, Math.PI * 2);
    }
    ctx.fill();

    // Player label
    ctx.fillStyle = "#00ff00";
    ctx.font = "bold 9px monospace";
    ctx.textAlign = "center";
    ctx.fillText(`(${p.x},${p.y})`, centerPx, RADAR_PX - 3);

    // Draw auto-walk path
    if (hackState.autoWalkEnabled && hackState.autoWalkPath.length > 0) {
      ctx.strokeStyle = "rgba(0, 255, 100, 0.6)";
      ctx.lineWidth = 2;
      ctx.setLineDash([3, 3]);
      ctx.beginPath();
      let wx = p.x, wy = p.y;
      ctx.moveTo((wx - p.x + half) * TILE_PX + TILE_PX / 2, (wy - p.y + half) * TILE_PX + TILE_PX / 2);
      for (const dir of hackState.autoWalkPath) {
        const off = dirToOffset(dir);
        wx += off.dx;
        wy += off.dy;
        const sx = (wx - p.x + half) * TILE_PX + TILE_PX / 2;
        const sy = (wy - p.y + half) * TILE_PX + TILE_PX / 2;
        if (sx >= 0 && sx <= RADAR_PX && sy >= 0 && sy <= RADAR_PX) {
          ctx.lineTo(sx, sy);
        }
      }
      ctx.stroke();
      ctx.setLineDash([]);

      // Draw destination marker
      const dtx = (hackState.autoWalkTargetX - p.x + half) * TILE_PX + TILE_PX / 2;
      const dty = (hackState.autoWalkTargetY - p.y + half) * TILE_PX + TILE_PX / 2;
      if (dtx >= 0 && dtx <= RADAR_PX && dty >= 0 && dty <= RADAR_PX) {
        ctx.fillStyle = "#00ff66";
        ctx.beginPath();
        ctx.arc(dtx, dty, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#00ff66";
        ctx.font = "bold 8px monospace";
        ctx.textAlign = "center";
        ctx.fillText("DEST", dtx, dty - 7);
      }
    }

    // Coord axis labels
    ctx.fillStyle = "#446644";
    ctx.font = "7px monospace";
    ctx.textAlign = "left";
    ctx.fillText(`${p.x - half}`, 2, centerPx - 2);
    ctx.textAlign = "right";
    ctx.fillText(`${p.x + half}`, RADAR_PX - 2, centerPx - 2);
    ctx.textAlign = "center";
    ctx.fillText(`${p.y - half}`, centerPx, 9);
    ctx.fillText(`${p.y + half}`, centerPx, RADAR_PX - 12);
  }

  // ========================================
  // 11c. ESP Overlay (draws on top of game canvas)
  // ========================================
  const GAME_TILE = 32; // pixels per tile in game canvas
  const GAME_TILES_VISIBLE = 21; // 672/32 = 21 tiles visible
  const GAME_CENTER = 10; // player is at tile index 10 (0-indexed)
  let overlayCanvas = null;

  function ensureOverlay() {
    const gameCanvas = document.querySelector("canvas:not(#audit-esp-overlay)");
    if (!gameCanvas) return null;

    // Check if overlay is still correctly attached as sibling of game canvas
    if (overlayCanvas && overlayCanvas.parentElement === gameCanvas.parentElement) {
      // Ensure size matches (in case canvas was resized)
      if (overlayCanvas.width !== gameCanvas.width || overlayCanvas.height !== gameCanvas.height) {
        overlayCanvas.width = gameCanvas.width;
        overlayCanvas.height = gameCanvas.height;
      }
      return overlayCanvas;
    }

    // Remove stale overlay if it exists somewhere else
    document.getElementById("audit-esp-overlay")?.remove();

    overlayCanvas = document.createElement("canvas");
    overlayCanvas.id = "audit-esp-overlay";
    overlayCanvas.width = gameCanvas.width;
    overlayCanvas.height = gameCanvas.height;
    overlayCanvas.style.cssText = "position:absolute;top:0;left:0;pointer-events:none;z-index:10;";

    const parent = gameCanvas.parentElement;
    if (parent) {
      parent.style.position = "relative";
      parent.appendChild(overlayCanvas);
    }
    return overlayCanvas;
  }

  function renderESP() {
    if (!sniffer.espEnabled) return;
    const canvas = ensureOverlay();
    if (!canvas) return;

    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    const p = sniffer.player;
    const now = Date.now();
    const ents = Object.entries(sniffer.entities).filter(([, e]) => now - e.lastSeen < 15000 && e.x > 0);

    for (const [id, ent] of ents) {
      const dx = ent.x - p.x;
      const dy = ent.y - p.y;

      // Check if on screen (within 10 tiles of player)
      if (Math.abs(dx) > GAME_CENTER || Math.abs(dy) > GAME_CENTER) continue;

      const sx = (GAME_CENTER + dx) * GAME_TILE + GAME_TILE / 2;
      const sy = (GAME_CENTER + dy) * GAME_TILE + GAME_TILE / 2;

      const isNpc = ent.type === "npc" || ent.name === "NPC";
      const isInvisible = ent.invisible === true;

      if (isInvisible) {
        // Pulsing red circle + crosshair for invisible
        const pulse = 0.5 + 0.5 * Math.sin(now / 150);
        const alpha = 0.6 + 0.4 * pulse;

        // Outer ring
        ctx.strokeStyle = `rgba(255, 50, 200, ${alpha})`;
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(sx, sy, 18 + 4 * pulse, 0, Math.PI * 2);
        ctx.stroke();

        // Inner filled dot
        ctx.fillStyle = `rgba(255, 0, 180, ${alpha * 0.6})`;
        ctx.beginPath();
        ctx.arc(sx, sy, 8, 0, Math.PI * 2);
        ctx.fill();

        // Crosshair lines
        ctx.strokeStyle = `rgba(255, 50, 200, ${alpha * 0.5})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(sx - 24, sy); ctx.lineTo(sx + 24, sy);
        ctx.moveTo(sx, sy - 24); ctx.lineTo(sx, sy + 24);
        ctx.stroke();

        // Name tag with background
        const name = ent.name || id;
        ctx.font = "bold 11px monospace";
        const textW = ctx.measureText(name + " [INVIS]").width;
        ctx.fillStyle = `rgba(80, 0, 40, ${alpha * 0.8})`;
        ctx.fillRect(sx - textW / 2 - 3, sy - 32, textW + 6, 14);
        ctx.fillStyle = `rgba(255, 100, 220, ${alpha})`;
        ctx.textAlign = "center";
        ctx.fillText(name + " [INVIS]", sx, sy - 21);

      } else if (isNpc) {
        // Skip NPCs in ESP overlay
        continue;
      } else {
        // Gold marker for other players
        ctx.strokeStyle = "rgba(255, 200, 50, 0.7)";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(sx, sy, 14, 0, Math.PI * 2);
        ctx.stroke();

        ctx.fillStyle = "rgba(255, 200, 50, 0.4)";
        ctx.beginPath();
        ctx.arc(sx, sy, 5, 0, Math.PI * 2);
        ctx.fill();

        // Name
        if (ent.name) {
          ctx.fillStyle = "rgba(255, 220, 100, 0.8)";
          ctx.font = "10px monospace";
          ctx.textAlign = "center";
          ctx.fillText(ent.name, sx, sy - 18);
        }
      }
    }
  }

  function updateUI() {
    const set = (id, txt) => { const e = document.getElementById(id); if (e) e.textContent = txt; };
    const cls = (id, c) => { const e = document.getElementById(id); if (e) e.className = c; };

    if (gameWS && gameWS.readyState === 1) { set("a-ws", "ON"); cls("a-ws", "con"); }
    else { set("a-ws", "OFF"); cls("a-ws", "dis"); }

    const p = sniffer.player;
    set("a-pos", `(${p.x},${p.y})`);
    set("a-hp", `${p.hp}/${p.maxHp}`);
    set("a-mp", `${p.mana}/${p.maxMana || "?"}`);
    set("a-gold", p.gold);
    set("a-map", `${p.map} ${sniffer.mapName}`);
    set("a-tx", hackState.packetsSent);
    set("a-rx", hackState.packetsRecv);

    // Speed button
    const spdBtn = document.getElementById("a-spd-btn");
    if (spdBtn) {
      if (hackState.speedHackEnabled) {
        spdBtn.textContent = "Detener (" + (DIR_NAMES[hackState.speedDirection] || "?") + ")";
        spdBtn.classList.add("on");
      } else { spdBtn.textContent = "Activar"; spdBtn.classList.remove("on"); }
    }
    // Spell buttons
    updateSpellButtons();

    // Entities
    const entEl = document.getElementById("audit-entity-list");
    if (entEl) {
      const now = Date.now();
      const ents = Object.entries(sniffer.entities)
        .filter(([, e]) => now - e.lastSeen < 30000)
        .sort(([, a], [, b]) => {
          const da = Math.abs(a.x - p.x) + Math.abs(a.y - p.y);
          const db = Math.abs(b.x - p.x) + Math.abs(b.y - p.y);
          return da - db;
        });
      entEl.innerHTML = ents.slice(0, 15).map(([id, e]) => {
        const dist = Math.abs(e.x - p.x) + Math.abs(e.y - p.y);
        const invTag = e.invisible ? ' <span style="color:#ff44cc">[INVIS]</span>' : '';
        return `<div class="ent"><span class="ent-name">${e.name || id}</span> (${e.x},${e.y}) dist=${dist}${invTag}</div>`;
      }).join("") || '<div style="color:#555">sin entidades</div>';
    }

    // Cooldowns
    const cdEl = document.getElementById("audit-cooldowns");
    if (cdEl) {
      const cds = Object.entries(sniffer.serverCooldowns).map(([type, cd]) => {
        const avg = cd.deltas.length > 0 ? Math.round(cd.deltas.reduce((a, b) => a + b, 0) / cd.deltas.length) : 0;
        const min = cd.deltas.length > 0 ? Math.min(...cd.deltas) : 0;
        const max = cd.deltas.length > 0 ? Math.max(...cd.deltas) : 0;
        return `<div>${type}: avg=<span class="cd-val">${avg}ms</span> min=${min} max=${max} (${cd.deltas.length} samples)</div>`;
      });
      cdEl.innerHTML = cds.join("") || '<div style="color:#555">sin datos aun</div>';
    }
  }

  // ========================================
  // 12. Export
  // ========================================
  function buildExportData() {
    return {
      timestamp: new Date().toISOString(),
      player: sniffer.player,
      mapName: sniffer.mapName,
      entities: sniffer.entities,
      serverCooldowns: Object.fromEntries(
        Object.entries(sniffer.serverCooldowns).map(([k, v]) => [k, { deltas: v.deltas, avg: v.deltas.length ? Math.round(v.deltas.reduce((a, b) => a + b, 0) / v.deltas.length) : 0 }])
      ),
      packetLog: sniffer.packetLog.slice(-200),
      stats: {
        packetsSent: hackState.packetsSent,
        packetsRecv: hackState.packetsRecv,
        speedMs: hackState.speedMs,
        spellSpamMs: hackState.spellSpamMs,
      },
    };
  }

  function showToast(msg) {
    const el = document.getElementById("a-sniff-toast");
    if (!el) return;
    el.textContent = msg;
    el.style.display = "block";
    setTimeout(() => { el.style.display = "none"; }, 3000);
  }

  function copySnifferToClipboard() {
    const json = JSON.stringify(buildExportData(), null, 2);
    navigator.clipboard.writeText(json).then(() => {
      showToast("Copiado al clipboard (" + json.length + " chars). Pegalo en el chat.");
    }).catch(() => {
      // Fallback: select from textarea
      const ta = document.createElement("textarea");
      ta.value = json;
      ta.style.cssText = "position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:80vw;height:60vh;z-index:9999999;font-family:monospace;font-size:10px;background:#111;color:#0f0;padding:10px;border:2px solid #ffd700";
      document.body.appendChild(ta);
      ta.select();
      showToast("No se pudo copiar automaticamente. Selecciona todo (Cmd+A) y copia (Cmd+C), luego cierra con Escape.");
      const close = (e) => { if (e.key === "Escape") { ta.remove(); document.removeEventListener("keydown", close); } };
      document.addEventListener("keydown", close);
    });
  }

  function exportSnifferData() {
    const json = JSON.stringify(buildExportData(), null, 2);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aoweb-audit-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    console.log("[AOWeb Audit] Exported", sniffer.packetLog.length, "packets +", Object.keys(sniffer.entities).length, "entities");
  }

  // Expose to window for console access
  window.__aoweb_audit = { sniffer, hackState, gameWS: () => gameWS, exportSnifferData };

  // ========================================
  // 13. Init
  // ========================================
  function togglePanel() {
    if (!panelEl) createPanel();
    else panelEl.style.display = panelEl.style.display === "none" ? "block" : "none";
  }

  function waitForGame() {
    const init = () => { createPanel(); updateUI(); console.log("[AOWeb Audit] Panel ready."); };
    if (window.location.pathname === "/play") {
      setTimeout(init, 2000);
    } else {
      const obs = new MutationObserver(() => {
        if (window.location.pathname === "/play" && !panelEl) setTimeout(init, 2000);
      });
      obs.observe(document, { childList: true, subtree: true });
    }
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", waitForGame);
  else waitForGame();

  setInterval(updateUI, 500);
  setInterval(renderRadar, 200); // radar at ~5fps
  setInterval(renderESP, 100);   // ESP overlay at ~10fps
  console.log("[AOWeb Audit] Extension loaded.");
})();
