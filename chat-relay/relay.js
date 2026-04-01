/**
 * PARAMANT Chat Relay — v1.0.0
 * Volledig geïsoleerd van sector relays en blob transport.
 * Alleen WebSocket chat. Burn-on-read. RAM only.
 * Port: 3010
 */

'use strict';

const http    = require('http');
const { WebSocketServer } = require('ws');
const crypto  = require('crypto');

const PORT        = parseInt(process.env.CHAT_PORT || '3010', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const ROOM_TTL_MS = 30 * 60 * 1000;
const MSG_TTL_MS  =  5 * 60 * 1000;
const MAX_MSG_LEN = 4096;
const MAX_ROOM_MEMBERS = 50;
const RATE_LIMIT_MS = 500;

const log = (lvl, msg) => console.log(JSON.stringify({ ts: new Date().toISOString(), level: lvl, msg }));

const rooms   = new Map(); // roomId → { members: Map<ws, {handle}>, msgs: [], lastActivity }
const clients = new Map(); // ws → { roomId, handle, lastMsg }

function sanitizeRoom(id) {
  if (!id) return null;
  if (/^[a-z0-9]{8,32}$/.test(id)) return id;
  return null;
}

function sanitizeHandle(h) {
  if (!h) return null;
  return String(h).replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 24) || null;
}

function getOrCreateRoom(roomId) {
  if (!rooms.has(roomId)) {
    rooms.set(roomId, { members: new Map(), msgs: [], lastActivity: Date.now() });
    log('info', `room_created: ${roomId}`);
  }
  return rooms.get(roomId);
}

function broadcast(room, payload, exclude = null) {
  const data = JSON.stringify(payload);
  room.members.forEach((_, ws) => {
    if (ws !== exclude && ws.readyState === 1) ws.send(data);
  });
}

function cleanRooms() {
  const now = Date.now();
  rooms.forEach((room, roomId) => {
    room.msgs = room.msgs.filter(m => now - m.ts < MSG_TTL_MS);
    if (room.members.size === 0 && now - room.lastActivity > ROOM_TTL_MS) {
      rooms.delete(roomId);
      log('info', `room_expired: ${roomId}`);
    }
  });
}

function handleLeave(ws, client) {
  if (!client.roomId) return;
  const room = rooms.get(client.roomId);
  if (room) {
    room.members.delete(ws);
    broadcast(room, { type: 'system', text: `${client.handle} heeft de room verlaten` });
    if (room.members.size === 0) {
      room.msgs = [];
      log('info', `room_empty_burned: ${client.roomId}`);
    }
  }
  client.roomId = null;
  client.handle = null;
}

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://paramant.app');
  res.setHeader('Access-Control-Allow-Headers', 'content-type,x-admin-token');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (req.url === '/health') {
    return res.end(JSON.stringify({ ok: true, version: '1.0.0', rooms: rooms.size, clients: clients.size, uptime_s: Math.floor(process.uptime()) }));
  }

  if (req.url === '/admin/rooms') {
    const token = req.headers['x-admin-token'] || '';
    if (!ADMIN_TOKEN || token !== ADMIN_TOKEN) { res.writeHead(401); return res.end(JSON.stringify({ error: 'unauthorized' })); }
    const data = [];
    rooms.forEach((room, id) => data.push({ roomId: id, members: room.members.size, msgs: room.msgs.length, idleMs: Date.now() - room.lastActivity }));
    return res.end(JSON.stringify({ rooms: data }));
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'not found' }));
});

const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
  clients.set(ws, { roomId: null, handle: null, lastMsg: 0 });

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }
    const client = clients.get(ws);
    if (!client) return;

    const now = Date.now();
    if (now - client.lastMsg < RATE_LIMIT_MS) return;
    client.lastMsg = now;

    if (msg.type === 'join') {
      const roomId = sanitizeRoom(msg.room);
      const handle = sanitizeHandle(msg.handle);
      if (!roomId || !handle) return ws.send(JSON.stringify({ type: 'error', text: 'Ongeldige room of naam' }));

      const room = getOrCreateRoom(roomId);
      if (room.members.size >= MAX_ROOM_MEMBERS) return ws.send(JSON.stringify({ type: 'error', text: 'Room vol' }));

      if (client.roomId && rooms.has(client.roomId)) {
        const oldRoom = rooms.get(client.roomId);
        oldRoom.members.delete(ws);
        broadcast(oldRoom, { type: 'system', text: `${client.handle} heeft de room verlaten` });
      }

      client.roomId = roomId;
      client.handle = handle;
      room.members.set(ws, { handle });
      room.lastActivity = now;

      ws.send(JSON.stringify({ type: 'joined', room: roomId, handle, members: room.members.size }));
      broadcast(room, { type: 'system', text: `${handle} is verbonden` }, ws);
      log('info', `join: ${handle} → ${roomId} (${room.members.size} members)`);
      return;
    }

    if (msg.type === 'chat') {
      if (!client.roomId || !client.handle) return;
      const room = rooms.get(client.roomId);
      if (!room) return;
      const text = String(msg.text || '').slice(0, MAX_MSG_LEN).trim();
      if (!text) return;
      const packet = { type: 'chat', handle: client.handle, text, ts: now };
      room.msgs.push(packet);
      room.lastActivity = now;
      room.members.forEach((_, mws) => { if (mws.readyState === 1) mws.send(JSON.stringify(packet)); });
      return;
    }

    if (msg.type === 'leave') { handleLeave(ws, client); return; }
  });

  ws.on('close', () => { const c = clients.get(ws); if (c) handleLeave(ws, c); clients.delete(ws); });
  ws.on('error', () => { clients.delete(ws); });
});

setInterval(cleanRooms, 5 * 60 * 1000);

server.listen(PORT, '127.0.0.1', () => {
  log('info', `chat_relay_started port=${PORT}`);
});

process.on('SIGTERM', () => {
  rooms.forEach(room => { room.msgs = []; });
  log('info', 'shutdown');
  process.exit(0);
});
