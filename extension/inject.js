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
    mapName: "",
    serverCooldowns: {}, // track actual server acceptance times per action type
    filterOps: null,     // null = show all, Set of opcodes to show
    hidePing: true,      // hide ping/pong by default
    espEnabled: true,    // ESP overlay on game canvas
  };

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
        case 22: decoded = `exp=${r.getDouble()}`; break;
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
        const xInput = document.getElementById("audit-target-x");
        const yInput = document.getElementById("audit-target-y");
        if (xInput) xInput.value = hackState.spellTargetX;
        if (yInput) yInput.value = hackState.spellTargetY;
        const btn = document.getElementById("audit-set-target");
        if (btn) {
          btn.textContent = "Target: (" + hackState.spellTargetX + ", " + hackState.spellTargetY + ")";
          btn.classList.remove("danger");
        }
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
    packetsSent: 0, packetsRecv: 0,
  };
  let capturingTarget = false;

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
    const btn = document.getElementById("a-autotgt-btn");
    if (!btn) return;
    if (hackState.autoTargetEnabled && hackState.autoTargetId) {
      const ent = sniffer.entities[hackState.autoTargetId];
      const name = ent?.name || hackState.autoTargetId;
      btn.textContent = `Atacando: ${name}`;
      btn.classList.add("on");
    } else {
      btn.textContent = "Auto-Target + Spam";
      btn.classList.remove("on");
    }
    // Sync coord inputs
    const xInput = document.getElementById("a-tgt-x");
    const yInput = document.getElementById("a-tgt-y");
    if (xInput) xInput.value = hackState.spellTargetX;
    if (yInput) yInput.value = hackState.spellTargetY;
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
    if (e.key === "X" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      hackState.spellSpamEnabled ? stopSpellSpam() : startSpellSpam();
      return;
    }
    if (e.key === "P" && e.shiftKey) {
      e.preventDefault(); e.stopPropagation();
      togglePanel();
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

      <!-- HACKS -->
      <div class="sec">
        <div class="sec-title">Speed Hack <span class="hk">Shift+H | WASD</span></div>
        <label>Intervalo: <input type="number" id="a-spd-ms" value="50" min="1" max="1000" step="10">ms</label>
        <button id="a-spd-btn">Activar</button>
        <span class="hk">normal=100ms server~150ms</span>
      </div>
      <div class="sec">
        <div class="sec-title">Spell Spam <span class="hk">Shift+X</span></div>
        <label>Intervalo: <input type="number" id="a-spl-ms" value="200" min="0" max="2000" step="50">ms</label>
        <label>Slot 1 (inicial): <input type="number" id="a-combo-s1" value="0" min="0" max="20">
          Slot 2 (spam): <input type="number" id="a-combo-s2" value="0" min="0" max="20"></label>
        <label>Target X:<input type="number" id="a-tgt-x" value="0" min="0" max="255">
          Y:<input type="number" id="a-tgt-y" value="0" min="0" max="255"></label>
        <button id="a-spl-btn">Activar</button>
        <button id="a-tgt-btn">Capturar Target</button>
        <button id="a-autotgt-btn" style="background:#440044;border-color:#aa00aa;color:#ff88ff">Auto-Target + Spam</button>
        <span class="hk">normal=850ms | auto-target sigue al target si se mueve</span>
      </div>
      <div class="sec">
        <div class="sec-title">Melee Spam</div>
        <label>Intervalo: <input type="number" id="a-mel-ms" value="400" min="0" max="2000" step="50">ms</label>
        <button id="a-mel-btn">Activar</button>
        <span class="hk">normal=950ms</span>
      </div>

      <!-- SNIFFER -->
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

      <!-- RADAR -->
      <div class="sec">
        <div class="sec-title">Radar <span class="hk">Shift+R = toggle | click = set target</span></div>
        <label style="display:inline"><input type="checkbox" id="a-radar-show" checked> Mini-radar</label>
        <label style="display:inline;margin-left:6px"><input type="checkbox" id="a-radar-names" checked> Nombres</label>
        <label style="display:inline;margin-left:6px"><input type="checkbox" id="a-esp-show" checked> <span style="color:#ff44cc">ESP overlay</span></label>
        <div id="audit-radar-wrap">
          <canvas id="audit-radar" width="310" height="310"></canvas>
        </div>
        <div id="audit-entity-list"></div>
      </div>

      <!-- COOLDOWNS -->
      <div class="sec">
        <div class="sec-title">Server Cooldowns (medidos)</div>
        <div id="audit-cooldowns"></div>
      </div>

      <div class="hk" style="text-align:center;margin-top:4px">Shift+P=panel | Shift+E=export</div>
    `;
    document.body.appendChild(panelEl);
    setupPanelEvents();
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
      if (hackState.speedHackEnabled) startSpeedHack(hackState.speedDirection);
    });
    document.getElementById("a-spd-btn").addEventListener("click", () => {
      hackState.speedHackEnabled ? stopSpeedHack() : startSpeedHack(1);
    });

    // Spell spam
    document.getElementById("a-spl-ms").addEventListener("change", (e) => {
      hackState.spellSpamMs = parseInt(e.target.value) || 200;
      if (hackState.spellSpamEnabled) startSpellSpam();
    });
    document.getElementById("a-combo-s1").addEventListener("change", (e) => {
      hackState.comboSlot1 = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-combo-s2").addEventListener("change", (e) => {
      hackState.comboSlot2 = parseInt(e.target.value) || 0;
      hackState.spellSlot = hackState.comboSlot2; // manual spam uses slot2
    });
    document.getElementById("a-tgt-x").addEventListener("change", (e) => {
      hackState.spellTargetX = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-tgt-y").addEventListener("change", (e) => {
      hackState.spellTargetY = parseInt(e.target.value) || 0;
    });
    document.getElementById("a-spl-btn").addEventListener("click", () => {
      if (hackState.spellSpamEnabled || hackState.autoTargetEnabled) {
        stopAutoTarget();
        stopSpellSpam();
        hackState.spellTargetX = 0;
        hackState.spellTargetY = 0;
        const xInput = document.getElementById("a-tgt-x");
        const yInput = document.getElementById("a-tgt-y");
        if (xInput) xInput.value = 0;
        if (yInput) yInput.value = 0;
        const tgtBtn = document.getElementById("a-tgt-btn");
        if (tgtBtn) { tgtBtn.textContent = "Capturar Target"; tgtBtn.classList.remove("danger"); }
      } else {
        startSpellSpam();
      }
    });
    document.getElementById("a-tgt-btn").addEventListener("click", () => {
      capturingTarget = true;
      document.getElementById("a-tgt-btn").textContent = "Click en mapa...";
      document.getElementById("a-tgt-btn").classList.add("danger");
    });
    document.getElementById("a-autotgt-btn").addEventListener("click", () => {
      if (hackState.autoTargetEnabled) stopAutoTarget();
      else startAutoTarget();
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

    // Radar controls
    document.getElementById("a-radar-show").addEventListener("change", (e) => {
      document.getElementById("audit-radar-wrap").style.display = e.target.checked ? "block" : "none";
    });
    document.getElementById("a-esp-show").addEventListener("change", (e) => {
      sniffer.espEnabled = e.target.checked;
      if (!e.target.checked && overlayCanvas) {
        const ctx = overlayCanvas.getContext("2d");
        ctx.clearRect(0, 0, overlayCanvas.width, overlayCanvas.height);
      }
    });
    // Click on radar to set spell target
    document.getElementById("audit-radar").addEventListener("click", (e) => {
      const canvas = e.target;
      const rect = canvas.getBoundingClientRect();
      const cx = e.clientX - rect.left;
      const cy = e.clientY - rect.top;
      const scale = canvas.width / RADAR_SIZE;
      const tileX = Math.round(sniffer.player.x + (cx / scale - RADAR_SIZE / 2));
      const tileY = Math.round(sniffer.player.y + (cy / scale - RADAR_SIZE / 2));
      hackState.spellTargetX = tileX;
      hackState.spellTargetY = tileY;
      const xInput = document.getElementById("a-tgt-x");
      const yInput = document.getElementById("a-tgt-y");
      if (xInput) xInput.value = tileX;
      if (yInput) yInput.value = tileY;
      showToast(`Target seteado: (${tileX}, ${tileY})`);
    });
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
    // Spell button
    const splBtn = document.getElementById("a-spl-btn");
    if (splBtn) {
      splBtn.textContent = hackState.spellSpamEnabled ? "Detener" : "Activar";
      splBtn.classList.toggle("on", hackState.spellSpamEnabled);
    }

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
