const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const Database = require('better-sqlite3');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });
const db = new Database('campusspace.db');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 0. SECURITY: PASSWORD HASHING & SESSION TOKENS
// ==========================================
const activeSessions = new Map();

function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(plain, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(plain, stored) {
  if (!stored) return false;
  if (!stored.includes(':')) return plain === stored;
  const [salt, key] = stored.split(':');
  const hashBuffer = crypto.scryptSync(plain, salt, 64);
  const keyBuffer = Buffer.from(key, 'hex');
  return keyBuffer.length === hashBuffer.length && crypto.timingSafeEqual(keyBuffer, hashBuffer);
}

function createSessionToken(user) {
  const token = crypto.randomBytes(24).toString('hex');
  activeSessions.set(token, user);
  return token;
}

function getAuthUser(req) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  return token ? activeSessions.get(token) : null;
}

function requireAuth(req, res, next) {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ success: false, message: 'Unauthorized: Valid session token required.' });
  req.authUser = user;
  next();
}

function requireAdmin(req, res, next) {
  const user = getAuthUser(req);
  if (!user || user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Forbidden: Administrator privileges required.' });
  }
  req.authUser = user;
  next();
}

// ==========================================
// 1. INITIALIZE DATABASE TABLES & MIGRATIONS
// ==========================================
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT DEFAULT 'student',
    department TEXT,
    assigned_room_id TEXT,
    presence_status TEXT DEFAULT 'In Office'
  );

  CREATE TABLE IF NOT EXISTS buildings (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    code TEXT NOT NULL,
    description TEXT NOT NULL,
    color TEXT NOT NULL,
    coordinates TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS rooms (
    id TEXT PRIMARY KEY,
    building_id TEXT NOT NULL,
    room_number TEXT NOT NULL,
    capacity INTEGER NOT NULL,
    status TEXT DEFAULT 'available',
    is_suspended INTEGER DEFAULT 0,
    suspend_reason TEXT,
    course_code TEXT,
    instructor TEXT,
    schedule_time TEXT,
    FOREIGN KEY (building_id) REFERENCES buildings(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id TEXT NOT NULL,
    day_of_week TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    course_code TEXT NOT NULL,
    instructor TEXT NOT NULL,
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    room_id TEXT NOT NULL,
    details TEXT NOT NULL,
    performed_by TEXT DEFAULT 'System',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// Safe migrations if upgrading an existing campusspace.db
try { db.exec(`ALTER TABLE users ADD COLUMN department TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN assigned_room_id TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN presence_status TEXT DEFAULT 'In Office'`); } catch (e) {}
try { db.exec(`ALTER TABLE rooms ADD COLUMN is_suspended INTEGER DEFAULT 0`); } catch (e) {}
try { db.exec(`ALTER TABLE rooms ADD COLUMN suspend_reason TEXT`); } catch (e) {}

// Auto-hash any legacy plaintext passwords safely
const existingUsers = db.prepare('SELECT id, password FROM users').all();
for (const u of existingUsers) {
  if (u.password && !u.password.includes(':')) {
    db.prepare('UPDATE users SET password = ? WHERE id = ?').run(hashPassword(u.password), u.id);
  }
}

const userCount = db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
if (userCount === 0) {
  const insertUser = db.prepare('INSERT INTO users (username, password, full_name, role, department, assigned_room_id, presence_status) VALUES (?, ?, ?, ?, ?, ?, ?)');
  insertUser.run('admin', hashPassword('admin123'), 'D.A.D/S.I.J', 'admin', 'Administration', null, 'On Duty');
  insertUser.run('student', hashPassword('student123'), 'Student Account', 'student', 'BSIT', null, 'Active');

  const insertBldg = db.prepare('INSERT INTO buildings (id, name, code, description, color, coordinates) VALUES (?, ?, ?, ?, ?, ?)');
  insertBldg.run('bldg-annex', 'SJIT Annex Basic Education Building', 'ANNEX', 'Basic Education wing located along Montilla Blvd.', '#4ade80', '[[8.95104, 125.53921], [8.95104, 125.53951], [8.95074, 125.53951], [8.95074, 125.53921]]');
  insertBldg.run('bldg-cea', 'College of Engineering and Architecture', 'CEA', 'Engineering & Architecture laboratories at 40 T. Calo St.', '#f97316', '[[8.95133, 125.54001], [8.95133, 125.54025], [8.95109, 125.54025], [8.95109, 125.54001]]');
  insertBldg.run('bldg-nas', 'NAS Building (Rooms 201 - 507)', 'NAS', 'Main multi-story academic wing housing NAS 201 through 507.', '#eab308', '[[8.95146, 125.54148], [8.95146, 125.54168], [8.95126, 125.54168], [8.95126, 125.54148]]');
  insertBldg.run('bldg-lcs', 'LCS Academic & Computer Wing', 'LCS', 'Computer laboratories and lecture halls near the central quadrangle.', '#38bdf8', '[[8.95122, 125.54075], [8.95122, 125.54098], [8.95102, 125.54098], [8.95102, 125.54075]]');

  const insertRoom = db.prepare('INSERT INTO rooms (id, building_id, room_number, capacity) VALUES (?, ?, ?, ?)');
  insertRoom.run('NAS-201', 'bldg-nas', 'NAS 201', 45);
  insertRoom.run('NAS-304', 'bldg-nas', 'NAS 304', 40);
  insertRoom.run('NAS-507', 'bldg-nas', 'NAS 507', 50);
  insertRoom.run('CEA-101', 'bldg-cea', 'CEA 101', 40);
  insertRoom.run('LCS-102', 'bldg-lcs', 'LCS 102', 35);
  insertRoom.run('ANNEX-202', 'bldg-annex', 'ANNEX 202', 45);
}

// Seed default Teacher accounts if none exist yet
const teacherCount = db.prepare(`SELECT COUNT(*) AS count FROM users WHERE role = 'teacher'`).get().count;
if (teacherCount === 0) {
  const insertTeacher = db.prepare('INSERT INTO users (username, password, full_name, role, department, assigned_room_id, presence_status) VALUES (?, ?, ?, ?, ?, ?, ?)');
  insertTeacher.run('montalban', hashPassword('teacher123'), 'Engr. Montalban', 'teacher', 'College of Engineering & IT', 'NAS-201', 'In Class');
  insertTeacher.run('navarro', hashPassword('teacher123'), 'Prof. Navarro', 'teacher', 'Computer Studies Dept.', 'NAS-507', 'In Office');
}

// Seed multi-slot schedules safely (verifies room exists first)
const scheduleCount = db.prepare('SELECT COUNT(*) AS count FROM schedules').get().count;
if (scheduleCount === 0) {
  const roomExists = db.prepare('SELECT id FROM rooms WHERE id = ?');
  const insertSched = db.prepare('INSERT INTO schedules (room_id, day_of_week, start_time, end_time, course_code, instructor) VALUES (?, ?, ?, ?, ?, ?)');

  const seedSchedules = [
    ['NAS-201', 'Daily', '08:00 AM', '11:00 AM', 'IT 311 - Network Administration', 'Engr. Montalban'],
    ['NAS-201', 'Daily', '01:00 PM', '04:00 PM', 'IT 312 - Systems Administration', 'Engr. Montalban'],
    ['NAS-507', 'Daily', '01:00 PM', '04:00 PM', 'CS 401 - Spatial Databases', 'Prof. Navarro'],
    ['LCS-102', 'Daily', '02:00 PM', '05:00 PM', 'MS 101 - Python Programming', 'Inst. Villanueva']
  ];

  for (const [roomId, day, start, end, course, instructor] of seedSchedules) {
    if (roomExists.get(roomId)) {
      insertSched.run(roomId, day, start, end, course, instructor);
    }
  }
}

// ==========================================
// DYNAMIC SCHEDULE & LIVE STATUS ENGINE
// ==========================================
const DAYS_OF_WEEK = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];

function parseTimeToMinutes(timeStr) {
  if (!timeStr) return null;
  const match = timeStr.trim().match(/^(\d{1,2}):(\d{2})\s*(AM|PM)$/i);
  if (!match) return null;
  let hours = parseInt(match[1], 10);
  const mins = parseInt(match[2], 10);
  const period = match[3].toUpperCase();
  if (period === 'PM' && hours !== 12) hours += 12;
  if (period === 'AM' && hours === 12) hours = 0;
  return hours * 60 + mins;
}

function getTodayName() {
  return DAYS_OF_WEEK[new Date().getDay()];
}

function computeEnrichedRooms() {
  const rooms = db.prepare(`
    SELECT r.*, b.name AS building_name, b.code AS building_code
    FROM rooms r
    JOIN buildings b ON r.building_id = b.id
    ORDER BY r.room_number ASC
  `).all();

  const allSchedules = db.prepare('SELECT * FROM schedules ORDER BY id ASC').all();
  const now = new Date();
  const today = getTodayName();
  const nowMins = now.getHours() * 60 + now.getMinutes();

  return rooms.map(room => {
    const roomSchedules = allSchedules
      .filter(s => s.room_id === room.id)
      .sort((a, b) => (parseTimeToMinutes(a.start_time) || 0) - (parseTimeToMinutes(b.start_time) || 0));

    const todaysSchedules = roomSchedules.filter(
      s => s.day_of_week.toLowerCase() === 'daily' || s.day_of_week.toLowerCase() === today.toLowerCase()
    );

    const activeSlot = todaysSchedules.find(s => {
      const start = parseTimeToMinutes(s.start_time);
      const end = parseTimeToMinutes(s.end_time);
      return start !== null && end !== null && nowMins >= start && nowMins < end;
    });

    const nextSlot = todaysSchedules.find(s => {
      const start = parseTimeToMinutes(s.start_time);
      return start !== null && start > nowMins;
    });

    let status = 'available';
    let course_code = null;
    let instructor = null;
    let schedule_time = null;

    if (room.is_suspended) {
      status = 'suspended';
      course_code = `SUSPENDED (${room.suspend_reason || 'Facility Maintenance'})`;
      instructor = 'Admin Lock';
      schedule_time = 'All Day';
    } else if (activeSlot) {
      status = 'occupied';
      course_code = activeSlot.course_code;
      instructor = activeSlot.instructor;
      schedule_time = `${activeSlot.start_time} - ${activeSlot.end_time}`;
    }

    return {
      ...room,
      status,
      course_code,
      instructor,
      schedule_time,
      schedules: roomSchedules,
      next_slot: nextSlot ? `${nextSlot.course_code} (${nextSlot.start_time})` : null
    };
  });
}

// Automatically broadcast when a class begins or finishes on the clock
let lastStatusSnapshot = '';
setInterval(() => {
  const enriched = computeEnrichedRooms();
  const snapshot = enriched.map(r => `${r.id}:${r.status}`).join('|');
  if (lastStatusSnapshot && snapshot !== lastStatusSnapshot) {
    broadcastCampusUpdate('Room schedule transition updated automatically', 'Campus Clock');
  }
  lastStatusSnapshot = snapshot;
}, 30000);

// ==========================================
// REAL-TIME SOCKET.IO BROADCAST HELPER
// ==========================================
function broadcastCampusUpdate(eventSummary, actor = 'System') {
  io.emit('campus_updated', {
    message: eventSummary,
    actor,
    timestamp: new Date().toLocaleTimeString()
  });
}

io.on('connection', (socket) => {
  socket.emit('connected_clients', io.engine.clientsCount);
  socket.on('disconnect', () => {
    io.emit('connected_clients', io.engine.clientsCount);
  });
});

// ==========================================
// 2. AUTHENTICATION & TEACHER PRESENCE
// ==========================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const row = db.prepare(`
    SELECT u.id, u.username, u.password, u.full_name, u.role, u.department, u.assigned_room_id, u.presence_status,
           r.room_number AS assigned_room_number, b.name AS assigned_building_name, b.id AS assigned_building_id
    FROM users u
    LEFT JOIN rooms r ON u.assigned_room_id = r.id
    LEFT JOIN buildings b ON r.building_id = b.id
    WHERE u.username = ?
  `).get(username);

  if (row && verifyPassword(password, row.password)) {
    const { password: _, ...user } = row;
    const token = createSessionToken(user);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('USER_LOGIN', user.assigned_room_id || 'AUTH', `${user.full_name} signed in as ${user.role.toUpperCase()}`, user.full_name);
    res.json({ success: true, user, token });
  } else {
    res.json({ success: false, message: 'Invalid username or password.' });
  }
});

app.post('/api/visitor-signin', (req, res) => {
  const { visitor_name, purpose } = req.body;
  const cleanName = (visitor_name || '').trim().slice(0, 80);
  const cleanPurpose = (purpose || 'Campus Visit').trim().slice(0, 120);

  if (!cleanName) {
    return res.status(400).json({ success: false, message: 'Please enter your full name.' });
  }

  const user = {
    id: 'visitor-' + Date.now(),
    username: 'visitor',
    full_name: `Visitor: ${cleanName}`,
    role: 'visitor',
    purpose: cleanPurpose
  };
  const token = createSessionToken(user);

  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('VISITOR_ENTRY', 'GATE', `Visitor "${cleanName}" signed in — Purpose: ${cleanPurpose}`, cleanName);

  broadcastCampusUpdate(`Visitor ${cleanName} checked in (${cleanPurpose})`, 'Main Gate');
  res.json({ success: true, user, token });
});

app.post('/api/teacher-presence', requireAuth, (req, res) => {
  if (req.authUser.role !== 'teacher') {
    return res.status(403).json({ success: false, message: 'Only teacher accounts can update presence status.' });
  }
  const { presence_status } = req.body;
  const allowed = ['In Office', 'In Class', 'Out of Campus'];
  if (!allowed.includes(presence_status)) {
    return res.status(400).json({ success: false, message: 'Invalid presence status.' });
  }

  db.prepare('UPDATE users SET presence_status = ? WHERE id = ?').run(presence_status, req.authUser.id);
  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('TEACHER_STATUS', req.authUser.assigned_room_id || 'FACULTY', `${req.authUser.full_name} is now ${presence_status}`, req.authUser.full_name);

  broadcastCampusUpdate(`${req.authUser.full_name} is now "${presence_status}"`, req.authUser.full_name);
  res.json({ success: true, presence_status });
});

app.get('/api/campus', (req, res) => {
  const enrichedRooms = computeEnrichedRooms();

  const buildings = db.prepare('SELECT * FROM buildings ORDER BY id ASC').all().map(b => ({
    ...b,
    coordinates: JSON.parse(b.coordinates),
    rooms: enrichedRooms.filter(r => r.building_id === b.id)
  }));

  const teachers = db.prepare(`
    SELECT u.id, u.username, u.full_name, u.department, u.assigned_room_id, u.presence_status,
           r.room_number AS assigned_room_number,
           b.name AS building_name, b.code AS building_code, b.id AS building_id
    FROM users u
    LEFT JOIN rooms r ON u.assigned_room_id = r.id
    LEFT JOIN buildings b ON r.building_id = b.id
    WHERE u.role = 'teacher'
    ORDER BY u.full_name ASC
  `).all().map(t => {
    const liveRoom = enrichedRooms.find(r => r.id === t.assigned_room_id);
    return { ...t, room_status: liveRoom ? liveRoom.status : null };
  });

  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100').all();
  res.json({ buildings, teachers, logs, current_day: getTodayName() });
});

// ==========================================
// 3. STUDENT / VISITOR / TEACHER J.A.R.V.I.S. AI ENDPOINT
// ==========================================
function evaluateClassPunctuality(scheduleTime) {
  if (!scheduleTime || !scheduleTime.includes('-')) return null;
  const [startStr, endStr] = scheduleTime.split('-').map(s => s.trim());
  const startMins = parseTimeToMinutes(startStr);
  const endMins = parseTimeToMinutes(endStr);
  if (startMins === null || endMins === null) return null;

  const now = new Date();
  const nowMins = now.getHours() * 60 + now.getMinutes();

  if (nowMins < startMins) {
    const diff = startMins - nowMins;
    return `✅ **You are ON TIME.** Class starts at **${startStr}** (in **${diff} minute(s)**).`;
  } else if (nowMins >= startMins && nowMins < endMins) {
    const lateMins = nowMins - startMins;
    if (lateMins === 0) return `⏰ **Class is starting RIGHT NOW** (${startStr}). Head inside immediately!`;
    return `🚨 **You are LATE by ${lateMins} minute(s)!** Class began at **${startStr}** and ends at **${endStr}**.`;
  } else {
    return `ℹ️ That scheduled session (**${scheduleTime}**) has already concluded for today.`;
  }
}

app.post('/api/student-ai', (req, res) => {
  const { message } = req.body;
  const q = (message || '').toLowerCase().trim();
  const buildings = db.prepare('SELECT * FROM buildings').all();
  const rooms = computeEnrichedRooms();
  const teachers = db.prepare(`
    SELECT u.full_name, u.department, u.presence_status, r.room_number, b.name AS building_name, b.id AS bldg_id
    FROM users u
    LEFT JOIN rooms r ON u.assigned_room_id = r.id
    LEFT JOIN buildings b ON r.building_id = b.id
    WHERE u.role = 'teacher'
  `).all();

  const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const today = getTodayName();

  // 1. TEACHER LOOKUP
  const matchedTeacher = teachers.find(t => {
    const lastName = t.full_name.split(' ').pop().toLowerCase();
    return q.includes(t.full_name.toLowerCase()) || (lastName.length > 2 && q.includes(lastName));
  });

  if (matchedTeacher) {
    const presence = matchedTeacher.presence_status || 'In Office';
    if (matchedTeacher.room_number) {
      return res.json({
        reply: `👨‍🏫 **${matchedTeacher.full_name}** (${matchedTeacher.department || 'Faculty'}) is currently **${presence}** at **${matchedTeacher.room_number}** inside **${matchedTeacher.building_name}**.\n🧭 Plotting walkable pathway route now.`,
        action: { type: 'ROUTE', buildingId: matchedTeacher.bldg_id }
      });
    }
    return res.json({
      reply: `👨‍🏫 **${matchedTeacher.full_name}** (${matchedTeacher.department || 'Faculty'}) is marked **${presence}** and does not have an assigned room posted.`
    });
  }

  // 2. FIND AVAILABLE / FREE ROOM
  if (q.match(/free room|available room|empty room|study room/)) {
    const capMatch = q.match(/(\d+)\s*(people|students|seats|pax)?/);
    const minCap = capMatch ? parseInt(capMatch[1], 10) : 1;
    const freeRooms = rooms.filter(r => r.status === 'available' && r.capacity >= minCap);

    if (freeRooms.length > 0) {
      const top = freeRooms[0];
      const list = freeRooms.map(r => `• **${r.room_number}** (${r.building_code}, ${r.capacity} seats)`).join('\n');
      return res.json({
        reply: `Found **${freeRooms.length}** available room(s)${minCap > 1 ? ` for ${minCap}+ seats` : ''}:\n${list}\n🧭 Routing you to **${top.room_number}** in **${top.building_name}**.`,
        action: { type: 'ROUTE', buildingId: top.building_id }
      });
    }
    return res.json({ reply: `No available rooms found matching ${minCap}+ capacity right now.` });
  }

  // 3. ROOM OR COURSE LOOKUP
  const matchedRoom = rooms.find(r =>
    q.includes(r.room_number.toLowerCase()) ||
    q.includes(r.room_number.toLowerCase().replace(/\s+/g, '')) ||
    (r.course_code && q.includes(r.course_code.toLowerCase().split('-')[0].trim()))
  );

  if (matchedRoom) {
    let statusDetail = '';
    if (matchedRoom.status === 'suspended') {
      statusDetail = `🚧 **${matchedRoom.room_number}** is temporarily **SUSPENDED** (${matchedRoom.suspend_reason || 'Maintenance'}).`;
    } else if (matchedRoom.status === 'occupied' && matchedRoom.schedule_time) {
      const punctuality = evaluateClassPunctuality(matchedRoom.schedule_time) || `Class scheduled: ${matchedRoom.schedule_time}.`;
      statusDetail = `Currently hosting **${matchedRoom.course_code}** (${matchedRoom.instructor}).\n${punctuality}`;
    } else {
      const nextNote = matchedRoom.next_slot ? ` Next class: **${matchedRoom.next_slot}**.` : '';
      statusDetail = `✅ **${matchedRoom.room_number}** is currently **AVAILABLE** (no active class right now).${nextNote}`;
    }

    return res.json({
      reply: `**${matchedRoom.room_number}** is located inside **${matchedRoom.building_name}**.\n${statusDetail}\n🧭 Calculating walkable route now.`,
      action: { type: 'ROUTE', buildingId: matchedRoom.building_id }
    });
  }

  // 4. PUNCTUALITY CHECK
  if (q.match(/late|time|clock|punctual|on time|schedule/)) {
    const ongoing = rooms.filter(r => r.status === 'occupied' && r.schedule_time);
    if (ongoing.length > 0) {
      const list = ongoing.map(r => {
        const evalText = evaluateClassPunctuality(r.schedule_time) || r.schedule_time;
        return `• **${r.room_number}** (${r.course_code}): ${evalText}`;
      }).join('\n');
      return res.json({
        reply: `Current campus time is **${today}, ${nowStr}**.\nHere is your live class punctuality check:\n${list}`
      });
    }
    return res.json({ reply: `Current campus time is **${today}, ${nowStr}**. No classes are active right now—you are not late!` });
  }

  // 5. BUILDING LOOKUP
  const targetBldg = buildings.find(b => q.includes(b.code.toLowerCase()) || q.includes(b.name.toLowerCase()));
  if (targetBldg) {
    return res.json({
      reply: `**${targetBldg.name}** (${targetBldg.code}) — ${targetBldg.description}.\n🧭 Walkable campus path plotted.`,
      action: { type: 'ROUTE', buildingId: targetBldg.id }
    });
  }

  return res.json({
    reply: `At your service! Current time is **${today}, ${nowStr}**. Ask me **"Where is Engr. Montalban?"**, **"Find a free room"**, or **"Directions to CEA"**.`
  });
});

// ==========================================
// 4. AUTHORIZED ADMIN J.A.R.V.I.S. AI ENDPOINT
// ==========================================
app.post('/api/admin-ai', requireAdmin, (req, res) => {
  const { message } = req.body;
  const raw = (message || '').trim();
  const q = raw.toLowerCase();
  const rooms = computeEnrichedRooms();
  const buildings = db.prepare('SELECT * FROM buildings').all();
  const teachers = db.prepare(`SELECT * FROM users WHERE role = 'teacher'`).all();
  const actor = req.authUser.full_name || 'Admin J.A.R.V.I.S.';

  // 1. UNSUSPEND / CLEAR / UNLOCK ROOM (Fixed unsuspend match!)
  if (q.includes('unsuspend') || q.includes('clear') || q.includes('unlock') || q.includes('free room') || q.includes('vacate')) {
    if (q.includes('clear all')) {
      db.prepare(`UPDATE rooms SET is_suspended = 0, suspend_reason = NULL, status = 'available', course_code = NULL, instructor = NULL, schedule_time = NULL`).run();
      db.prepare('DELETE FROM schedules').run();
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('CLEAR_ALL', 'ALL', 'J.A.R.V.I.S. cleared all campus schedules and locks', actor);
      broadcastCampusUpdate('All campus rooms cleared to AVAILABLE', actor);

      return res.json({
        reply: '✅ **All Campus Rooms Cleared:** Every schedule and maintenance lock has been cleared.',
        action: { type: 'REFRESH' }
      });
    }

    const targetRoom = rooms.find(r => q.includes(r.room_number.toLowerCase()) || q.includes(r.room_number.toLowerCase().replace(/\s+/g, '')));
    if (targetRoom) {
      if (q.includes('unsuspend') || q.includes('unlock')) {
        db.prepare(`UPDATE rooms SET is_suspended = 0, suspend_reason = NULL WHERE id = ?`).run(targetRoom.id);
        db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
          .run('UNSUSPEND_ROOM', targetRoom.id, `J.A.R.V.I.S. unsuspended ${targetRoom.room_number}`, actor);
        broadcastCampusUpdate(`${targetRoom.room_number} unsuspended and restored`, actor);

        return res.json({
          reply: `✅ **Room Unsuspended:** **${targetRoom.room_number}** maintenance lock lifted and synced to live schedule.`,
          action: { type: 'REFRESH' }
        });
      }

      db.prepare(`UPDATE rooms SET is_suspended = 0, suspend_reason = NULL, status = 'available', course_code = NULL, instructor = NULL, schedule_time = NULL WHERE id = ?`).run(targetRoom.id);
      db.prepare('DELETE FROM schedules WHERE room_id = ?').run(targetRoom.id);
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('CLEAR_ROOM', targetRoom.id, `J.A.R.V.I.S. cleared ${targetRoom.room_number} to AVAILABLE`, actor);
      broadcastCampusUpdate(`${targetRoom.room_number} cleared to AVAILABLE`, actor);

      return res.json({
        reply: `✅ **Room Cleared:** **${targetRoom.room_number}** is now **AVAILABLE**.`,
        action: { type: 'REFRESH' }
      });
    }
    return res.json({ reply: 'Specify which room to unsuspend or clear (e.g., *"Unsuspend Annex 202"* or *"Clear NAS 201"*).' });
  }

  // 2. SUSPEND / LOCK ROOM FOR MAINTENANCE
  if (q.startsWith('suspend') || q.includes('maintenance') || q.includes('lock room')) {
    const targetRoom = rooms.find(r => q.includes(r.room_number.toLowerCase()) || q.includes(r.room_number.toLowerCase().replace(/\s+/g, '')));
    if (targetRoom) {
      const reason = raw.split(/for|due to/i)[1]?.trim() || 'Facility Maintenance';
      db.prepare(`UPDATE rooms SET is_suspended = 1, suspend_reason = ? WHERE id = ?`).run(reason, targetRoom.id);
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('SUSPEND_ROOM', targetRoom.id, `J.A.R.V.I.S. suspended ${targetRoom.room_number}: ${reason}`, actor);
      broadcastCampusUpdate(`${targetRoom.room_number} suspended (${reason})`, actor);

      return res.json({
        reply: `🚧 **Room Suspended:** **${targetRoom.room_number}** locked for **${reason}** and synced live to all clients.`,
        action: { type: 'REFRESH' }
      });
    }
    return res.json({ reply: 'Specify a room to suspend (e.g., *"Suspend Annex 202 for maintenance"*).' });
  }

  // 3. ASSIGN TEACHER TO ROOM VIA CHAT
  if (q.startsWith('assign teacher') || (q.startsWith('assign ') && teachers.some(t => q.includes(t.full_name.toLowerCase()) || q.includes(t.full_name.split(' ').pop().toLowerCase())))) {
    const matchedTeacher = teachers.find(t => q.includes(t.full_name.toLowerCase()) || q.includes(t.full_name.split(' ').pop().toLowerCase()));
    const matchedRoom = rooms.find(r => q.includes(r.room_number.toLowerCase()) || q.includes(r.room_number.toLowerCase().replace(/\s+/g, '')));
    if (matchedTeacher && matchedRoom) {
      db.prepare('UPDATE users SET assigned_room_id = ? WHERE id = ?').run(matchedRoom.id, matchedTeacher.id);
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('ASSIGN_TEACHER_ROOM', matchedRoom.id, `J.A.R.V.I.S. assigned ${matchedTeacher.full_name} to ${matchedRoom.room_number}`, actor);
      broadcastCampusUpdate(`${matchedTeacher.full_name} assigned to ${matchedRoom.room_number}`, actor);

      return res.json({
        reply: `👨‍🏫 **Teacher Room Assigned:** **${matchedTeacher.full_name}** is now assigned to **${matchedRoom.room_number}**.`,
        action: { type: 'REFRESH' }
      });
    }
  }

  // 4. FIND AVAILABLE ROOM BY CAPACITY
  if (q.match(/find|search|available|free/) && q.match(/room|seat|capacity|people|students/)) {
    const capMatch = q.match(/(\d+)/);
    const needed = capMatch ? parseInt(capMatch[1], 10) : 1;
    const matches = rooms.filter(r => r.status === 'available' && r.capacity >= needed);
    if (matches.length > 0) {
      const summary = matches.map(r => `• **${r.room_number}** (${r.capacity} seats)`).join('\n');
      return res.json({
        reply: `🔍 Found **${matches.length}** available room(s) for **${needed}+** capacity:\n${summary}`,
        action: { type: 'ROUTE', buildingId: matches[0].building_id }
      });
    }
    return res.json({ reply: `⚠️ No available rooms currently support **${needed}** seats.` });
  }

  // 5. ADD NEW BUILDING VIA CHAT
  if (q.startsWith('add building') || q.startsWith('new building') || q.startsWith('create building')) {
    const parts = raw.replace(/^(add|new|create)\s+building\s*/i, '').split('|').map(s => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      const name = parts[0];
      const code = parts[1].toUpperCase();
      const description = parts[2] || `${name} academic facility`;
      const lat = parseFloat(parts[3]) || 8.95135;
      const lng = parseFloat(parts[4]) || 125.54050;
      const offset = 0.00012;
      const coords = [
        [lat + offset, lng - offset],
        [lat + offset, lng + offset],
        [lat - offset, lng + offset],
        [lat - offset, lng - offset]
      ];
      const id = 'bldg-' + Date.now();
      db.prepare('INSERT INTO buildings (id, name, code, description, color, coordinates) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, name, code, description, '#38bdf8', JSON.stringify(coords));
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('ADD_BUILDING', id, `J.A.R.V.I.S. created building ${name} (${code})`, actor);
      broadcastCampusUpdate(`New building ${name} (${code}) added`, actor);

      return res.json({
        reply: `✅ **Building Created:** **${name}** (${code}) has been plotted and pushed live to all users.`,
        action: { type: 'REFRESH' }
      });
    }
    return res.json({
      reply: 'Opening the **Add New Building** form—or type:\n`Add building Science Wing | SCI | Science Labs` to create it directly.',
      action: { type: 'OPEN_MODAL', modal: 'buildingModal' }
    });
  }

  // 6. EDIT BUILDING VIA CHAT
  if (q.startsWith('edit building') || q.startsWith('update building')) {
    const parts = raw.replace(/^(edit|update)\s+building\s*/i, '').split('|').map(s => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      const targetQuery = parts[0].toLowerCase();
      const targetBldg = buildings.find(b => b.code.toLowerCase() === targetQuery || b.name.toLowerCase().includes(targetQuery));
      if (targetBldg) {
        const newName = parts[1] || targetBldg.name;
        const newDesc = parts[2] || targetBldg.description;
        db.prepare('UPDATE buildings SET name = ?, description = ? WHERE id = ?')
          .run(newName, newDesc, targetBldg.id);
        db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
          .run('EDIT_BUILDING', targetBldg.id, `J.A.R.V.I.S. updated building ${targetBldg.code} to ${newName}`, actor);
        broadcastCampusUpdate(`Building ${targetBldg.code} updated`, actor);

        return res.json({
          reply: `✏️ **Building Updated:** **${newName}** (${targetBldg.code}) synced live.`,
          action: { type: 'REFRESH' }
        });
      }
    }
    return res.json({
      reply: 'Use format: `Edit building SCI | New Building Name | New Description` or click the **✏️** button next to any building.'
    });
  }

  // 7. DELETE BUILDING VIA CHAT
  if (q.startsWith('delete building') || q.startsWith('remove building')) {
    const targetQuery = raw.replace(/^(delete|remove)\s+building\s*/i, '').trim().toLowerCase();
    const targetBldg = buildings.find(
      b => b.code.toLowerCase() === targetQuery || b.name.toLowerCase().includes(targetQuery)
    );
    if (targetBldg) {
      db.prepare('DELETE FROM rooms WHERE building_id = ?').run(targetBldg.id);
      db.prepare('DELETE FROM buildings WHERE id = ?').run(targetBldg.id);
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('DELETE_BUILDING', targetBldg.id, `J.A.R.V.I.S. deleted building ${targetBldg.name} (${targetBldg.code})`, actor);
      broadcastCampusUpdate(`Building ${targetBldg.code} removed`, actor);

      return res.json({
        reply: `🗑️ **Building Deleted:** **${targetBldg.name}** (${targetBldg.code}) and its rooms have been removed.`,
        action: { type: 'REFRESH' }
      });
    }
    return res.json({ reply: 'Specify which building code or name to delete (e.g., *"Delete building SCI"*).' });
  }

  // 8. ADD NEW ROOM VIA CHAT
  if (q.startsWith('add room') || q.startsWith('new room') || q.startsWith('create room')) {
    const parts = raw.replace(/^(add|new|create)\s+room\s*/i, '').split('|').map(s => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      const roomNum = parts[0].toUpperCase();
      const bldgCode = parts[1].toLowerCase();
      const cap = parseInt(parts[2], 10) || 40;
      const targetBldg = buildings.find(b => b.code.toLowerCase() === bldgCode || b.name.toLowerCase().includes(bldgCode));
      if (targetBldg) {
        const id = 'RM-' + Math.floor(1000 + Math.random() * 9000);
        db.prepare('INSERT INTO rooms (id, building_id, room_number, capacity, status) VALUES (?, ?, ?, ?, ?)')
          .run(id, targetBldg.id, roomNum, cap, 'available');
        db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
          .run('ADD_ROOM', id, `J.A.R.V.I.S. added room ${roomNum} to ${targetBldg.code}`, actor);
        broadcastCampusUpdate(`New room ${roomNum} added to ${targetBldg.code}`, actor);

        return res.json({
          reply: `✅ **Room Added:** **${roomNum}** (Capacity: ${cap}) is now registered under **${targetBldg.name}**.`,
          action: { type: 'REFRESH' }
        });
      }
    }
    return res.json({
      reply: 'Opening the **Add New Room** form—or type:\n`Add room NAS 405 | NAS | 45` to add it directly.',
      action: { type: 'OPEN_MODAL', modal: 'roomModal' }
    });
  }

  // 9. EDIT ROOM VIA CHAT
  if (q.startsWith('edit room') || q.startsWith('update room')) {
    const parts = raw.replace(/^(edit|update)\s+room\s*/i, '').split('|').map(s => s.trim()).filter(Boolean);
    if (parts.length >= 2) {
      const targetQuery = parts[0].toLowerCase();
      const targetRoom = rooms.find(
        r => r.room_number.toLowerCase() === targetQuery || r.room_number.toLowerCase().replace(/\s+/g, '') === targetQuery.replace(/\s+/g, '')
      );
      if (targetRoom) {
        const newNumber = parts[1].toUpperCase();
        const newCap = parseInt(parts[2], 10) || targetRoom.capacity;
        db.prepare('UPDATE rooms SET room_number = ?, capacity = ? WHERE id = ?')
          .run(newNumber, newCap, targetRoom.id);
        db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
          .run('EDIT_ROOM', targetRoom.id, `J.A.R.V.I.S. updated ${targetRoom.room_number} to ${newNumber} (Cap: ${newCap})`, actor);
        broadcastCampusUpdate(`Room ${newNumber} updated`, actor);

        return res.json({
          reply: `✏️ **Room Updated:** **${newNumber}** (Capacity: ${newCap}) saved.`,
          action: { type: 'REFRESH' }
        });
      }
    }
    return res.json({
      reply: 'Use format: `Edit room NAS 405 | NAS 406 | 50` or click the **✏️** button next to any room.'
    });
  }

  // 10. DELETE ROOM VIA CHAT
  if (q.startsWith('delete room') || q.startsWith('remove room')) {
    const targetQuery = raw.replace(/^(delete|remove)\s+room\s*/i, '').trim().toLowerCase();
    const targetRoom = rooms.find(
      r => r.room_number.toLowerCase() === targetQuery || r.room_number.toLowerCase().replace(/\s+/g, '') === targetQuery.replace(/\s+/g, '')
    );
    if (targetRoom) {
      db.prepare('DELETE FROM rooms WHERE id = ?').run(targetRoom.id);
      db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
        .run('DELETE_ROOM', targetRoom.id, `J.A.R.V.I.S. deleted room ${targetRoom.room_number}`, actor);
      broadcastCampusUpdate(`Room ${targetRoom.room_number} deleted`, actor);

      return res.json({
        reply: `🗑️ **Room Deleted:** **${targetRoom.room_number}** has been permanently removed.`,
        action: { type: 'REFRESH' }
      });
    }
    return res.json({ reply: 'Specify which room to delete (e.g., *"Delete room NAS 405"*).' });
  }

  // 11. SET SCHEDULE VIA CHAT (Multi-slot supported!)
  if (q.includes('set schedule') || q.includes('assign') || q.includes('schedule room') || q.includes('book room')) {
    const parts = raw.replace(/^(set\s+schedule|assign|schedule\s+room|book\s+room)\s*(for)?\s*/i, '').split('|').map(s => s.trim()).filter(Boolean);
    if (parts.length >= 4) {
      const roomQuery = parts[0].toLowerCase();
      const targetRoom = rooms.find(r => r.room_number.toLowerCase() === roomQuery || r.room_number.toLowerCase().replace(/\s+/g, '') === roomQuery.replace(/\s+/g, ''));
      if (targetRoom) {
        let dayOfWeek = 'Daily', course, instructor, timeSlot;
        if (parts.length >= 5) {
          dayOfWeek = parts[1];
          course = parts[2];
          instructor = parts[3];
          timeSlot = parts[4];
        } else {
          course = parts[1];
          instructor = parts[2];
          timeSlot = parts[3];
        }
        const [startStr, endStr] = timeSlot.includes('-') ? timeSlot.split('-').map(s => s.trim()) : [timeSlot, '05:00 PM'];
        db.prepare('INSERT INTO schedules (room_id, day_of_week, start_time, end_time, course_code, instructor) VALUES (?, ?, ?, ?, ?, ?)')
          .run(targetRoom.id, dayOfWeek, startStr, endStr, course, instructor);
        db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
          .run('ADD_SCHEDULE', targetRoom.id, `J.A.R.V.I.S. added ${dayOfWeek} slot ${course} (${timeSlot}) in ${targetRoom.room_number}`, actor);
        broadcastCampusUpdate(`Schedule added to ${targetRoom.room_number} (${course})`, actor);

        return res.json({
          reply: `✅ **Schedule Added:** **${targetRoom.room_number}** booked for **${course}** (${dayOfWeek}, **${timeSlot}**) with **${instructor}**.`,
          action: { type: 'REFRESH' }
        });
      }
    }

    const matchedRoom = rooms.find(r => q.includes(r.room_number.toLowerCase()));
    if (matchedRoom) {
      return res.json({
        reply: `Opening the **Room Schedule Manager** for **${matchedRoom.room_number}**.`,
        action: { type: 'OPEN_SCHEDULE', roomId: matchedRoom.id }
      });
    }
    const firstAvail = rooms.find(r => r.status === 'available') || rooms[0];
    if (firstAvail) {
      return res.json({
        reply: `Opening the **Room Schedule Manager** for **${firstAvail.room_number}**.`,
        action: { type: 'OPEN_SCHEDULE', roomId: firstAvail.id }
      });
    }
  }

  // 12. OCCUPANCY SUMMARY
  if (q.includes('occupancy') || q.includes('summary') || q.includes('status') || q.includes('report')) {
    const total = rooms.length;
    const occ = rooms.filter(r => r.status === 'occupied').length;
    const susp = rooms.filter(r => r.status === 'suspended').length;
    const avail = rooms.filter(r => r.status === 'available').length;
    return res.json({
      reply: `**Authorized Facility Report (${getTodayName()}):**\n• Buildings: **${buildings.length}** | Teachers: **${teachers.length}**\n• Total Rooms: **${total}** | Available: **${avail}** | Occupied: **${occ}** | Suspended: **${susp}**`
    });
  }

  return res.json({
    reply: `At your service, Administrator. Try:\n• **"Assign Engr. Montalban to CEA 101"**\n• **"Suspend Annex 202 for maintenance"**\n• **"Unsuspend Annex 202"**\n• **"Find free room for 45 students"**`
  });
});

// ==========================================
// 5. TEACHER MANAGEMENT ENDPOINTS (ADMIN ASSIGN ROOMS)
// ==========================================
app.post('/api/teachers', requireAdmin, (req, res) => {
  const { full_name, username, password, department, assigned_room_id } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  try {
    const info = db.prepare('INSERT INTO users (username, password, full_name, role, department, assigned_room_id, presence_status) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(username.trim(), hashPassword(password), full_name.trim(), 'teacher', department || 'Faculty', assigned_room_id || null, 'In Office');

    const room = assigned_room_id ? db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(assigned_room_id) : null;
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('ADD_TEACHER', assigned_room_id || 'FACULTY', `Added teacher ${full_name} (${room ? room.room_number : 'No Room'})`, actor);

    broadcastCampusUpdate(`Faculty ${full_name} added (${room ? room.room_number : 'Unassigned'})`, actor);
    res.json({ success: true, id: info.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ success: false, message: 'Username already exists or invalid data.' });
  }
});

app.put('/api/teachers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { full_name, department, assigned_room_id } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const existing = db.prepare(`SELECT * FROM users WHERE id = ? AND role = 'teacher'`).get(id);
  if (!existing) return res.status(404).json({ success: false, message: 'Teacher not found.' });

  try {
    db.prepare('UPDATE users SET full_name = ?, department = ?, assigned_room_id = ? WHERE id = ?')
      .run(full_name.trim(), department || 'Faculty', assigned_room_id || null, id);

    const room = assigned_room_id ? db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(assigned_room_id) : null;
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('ASSIGN_TEACHER_ROOM', assigned_room_id || 'FACULTY', `Assigned ${full_name} to ${room ? room.room_number : 'Unassigned'}`, actor);

    broadcastCampusUpdate(`${full_name} assigned to ${room ? room.room_number : 'Unassigned'}`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/teachers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const actor = req.authUser.full_name || 'Admin';
  const teacher = db.prepare(`SELECT full_name FROM users WHERE id = ? AND role = 'teacher'`).get(id);
  if (!teacher) return res.status(404).json({ success: false, message: 'Teacher not found.' });

  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('DELETE_TEACHER', 'FACULTY', `Removed teacher ${teacher.full_name}`, actor);
  broadcastCampusUpdate(`Faculty ${teacher.full_name} removed`, actor);
  res.json({ success: true });
});

// ==========================================
// 6. ADMIN BUILDING, ROOM & SCHEDULE CRUD ENDPOINTS
// ==========================================
app.post('/api/buildings', requireAdmin, (req, res) => {
  const { name, code, description, color, lat, lng } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const id = 'bldg-' + Date.now();
  const latitude = parseFloat(lat);
  const longitude = parseFloat(lng);
  const offset = 0.00012;
  const coords = [
    [latitude + offset, longitude - offset],
    [latitude + offset, longitude + offset],
    [latitude - offset, longitude + offset],
    [latitude - offset, longitude - offset]
  ];

  try {
    db.prepare('INSERT INTO buildings (id, name, code, description, color, coordinates) VALUES (?, ?, ?, ?, ?, ?)')
      .run(id, name, code.toUpperCase(), description, color, JSON.stringify(coords));
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('ADD_BUILDING', id, `Created building ${name} (${code.toUpperCase()})`, actor);
    broadcastCampusUpdate(`Building ${name} (${code.toUpperCase()}) added`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/api/buildings/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { name, code, description, color, lat, lng } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const existing = db.prepare('SELECT * FROM buildings WHERE id = ?').get(id);

  if (!existing) {
    return res.status(404).json({ success: false, message: 'Building not found.' });
  }

  const latitude = parseFloat(lat);
  const longitude = parseFloat(lng);
  const offset = 0.00012;
  const coords = [
    [latitude + offset, longitude - offset],
    [latitude + offset, longitude + offset],
    [latitude - offset, longitude + offset],
    [latitude - offset, longitude - offset]
  ];

  try {
    db.prepare('UPDATE buildings SET name = ?, code = ?, description = ?, color = ?, coordinates = ? WHERE id = ?')
      .run(name, code.toUpperCase(), description, color, JSON.stringify(coords), id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('EDIT_BUILDING', id, `Edited building ${name} (${code.toUpperCase()})`, actor);
    broadcastCampusUpdate(`Building ${name} (${code.toUpperCase()}) updated`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/buildings/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const actor = req.authUser.full_name || 'Admin';
  const bldg = db.prepare('SELECT name, code FROM buildings WHERE id = ?').get(id);

  if (!bldg) {
    return res.status(404).json({ success: false, message: 'Building not found.' });
  }

  try {
    db.prepare('DELETE FROM rooms WHERE building_id = ?').run(id);
    db.prepare('DELETE FROM buildings WHERE id = ?').run(id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('DELETE_BUILDING', id, `Deleted building ${bldg.name} (${bldg.code})`, actor);
    broadcastCampusUpdate(`Building ${bldg.name} (${bldg.code}) deleted`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.post('/api/rooms', requireAdmin, (req, res) => {
  const { building_id, room_number, capacity } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const id = 'RM-' + Math.floor(1000 + Math.random() * 9000);
  try {
    db.prepare('INSERT INTO rooms (id, building_id, room_number, capacity, status) VALUES (?, ?, ?, ?, ?)')
      .run(id, building_id, room_number, parseInt(capacity, 10), 'available');
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('ADD_ROOM', id, `Added room ${room_number} (Cap: ${capacity})`, actor);
    broadcastCampusUpdate(`Room ${room_number} added`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.put('/api/rooms/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { building_id, room_number, capacity } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const existing = db.prepare('SELECT * FROM rooms WHERE id = ?').get(id);

  if (!existing) {
    return res.status(404).json({ success: false, message: 'Room not found.' });
  }

  try {
    db.prepare('UPDATE rooms SET building_id = ?, room_number = ?, capacity = ? WHERE id = ?')
      .run(building_id, room_number, parseInt(capacity, 10), id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('EDIT_ROOM', id, `Edited room ${room_number} (Cap: ${capacity})`, actor);
    broadcastCampusUpdate(`Room ${room_number} updated`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

app.delete('/api/rooms/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const actor = req.authUser.full_name || 'Admin';
  const room = db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(id);

  if (!room) {
    return res.status(404).json({ success: false, message: 'Room not found.' });
  }

  try {
    db.prepare('UPDATE users SET assigned_room_id = NULL WHERE assigned_room_id = ?').run(id);
    db.prepare('DELETE FROM rooms WHERE id = ?').run(id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('DELETE_ROOM', id, `Deleted room ${room.room_number}`, actor);
    broadcastCampusUpdate(`Room ${room.room_number} deleted`, actor);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Multi-Slot Schedule Endpoints
app.post('/api/schedules', requireAdmin, (req, res) => {
  const { room_id, day_of_week, start_time, end_time, course_code, instructor } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const room = db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(room_id);
  if (!room) return res.status(404).json({ success: false, message: 'Room not found.' });

  if (parseTimeToMinutes(start_time) === null || parseTimeToMinutes(end_time) === null) {
    return res.status(400).json({ success: false, message: 'Use HH:MM AM/PM format (e.g., 08:00 AM).' });
  }

  db.prepare('INSERT INTO schedules (room_id, day_of_week, start_time, end_time, course_code, instructor) VALUES (?, ?, ?, ?, ?, ?)')
    .run(room_id, day_of_week || 'Daily', start_time.trim(), end_time.trim(), course_code.trim(), instructor.trim());

  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('ADD_SCHEDULE', room_id, `Added ${day_of_week} slot ${course_code} (${start_time} - ${end_time}) to ${room.room_number}`, actor);

  broadcastCampusUpdate(`Schedule added to ${room.room_number} (${course_code})`, actor);
  res.json({ success: true });
});

app.delete('/api/schedules/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const actor = req.authUser.full_name || 'Admin';
  const sched = db.prepare('SELECT s.*, r.room_number FROM schedules s JOIN rooms r ON s.room_id = r.id WHERE s.id = ?').get(id);
  if (!sched) return res.status(404).json({ success: false, message: 'Schedule slot not found.' });

  db.prepare('DELETE FROM schedules WHERE id = ?').run(id);
  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('DELETE_SCHEDULE', sched.room_id, `Removed ${sched.course_code} (${sched.start_time} - ${sched.end_time}) from ${sched.room_number}`, actor);

  broadcastCampusUpdate(`Removed schedule slot from ${sched.room_number}`, actor);
  res.json({ success: true });
});

// Backward-compatible assign-class endpoint (appends to schedules table)
app.post('/api/assign-class', requireAdmin, (req, res) => {
  const { room_id, course_code, instructor, schedule_time, day_of_week } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const room = db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(room_id);
  const [startStr, endStr] = (schedule_time || '').includes('-')
    ? schedule_time.split('-').map(s => s.trim())
    : ['08:00 AM', '11:00 AM'];

  db.prepare('INSERT INTO schedules (room_id, day_of_week, start_time, end_time, course_code, instructor) VALUES (?, ?, ?, ?, ?, ?)')
    .run(room_id, day_of_week || 'Daily', startStr, endStr, course_code, instructor);
  db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
    .run('SET_SCHEDULE', room_id, `Assigned ${course_code} (${schedule_time}) to ${room ? room.room_number : room_id}`, actor);
  broadcastCampusUpdate(`${room ? room.room_number : room_id} scheduled (${course_code})`, actor);
  res.json({ success: true });
});

app.post('/api/update-status', requireAdmin, (req, res) => {
  const { room_id, status, reason } = req.body;
  const actor = req.authUser.full_name || 'Admin';
  const room = db.prepare('SELECT room_number FROM rooms WHERE id = ?').get(room_id);

  if (status === 'suspended') {
    db.prepare(`UPDATE rooms SET is_suspended = 1, suspend_reason = ? WHERE id = ?`).run(reason || 'Facility Maintenance', room_id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('SUSPEND_ROOM', room_id, `Suspended ${room ? room.room_number : room_id}`, actor);
    broadcastCampusUpdate(`${room ? room.room_number : room_id} suspended`, actor);
  } else {
    db.prepare(`UPDATE rooms SET is_suspended = 0, suspend_reason = NULL, status = 'available' WHERE id = ?`).run(room_id);
    db.prepare('INSERT INTO audit_logs (action_type, room_id, details, performed_by) VALUES (?, ?, ?, ?)')
      .run('UNSUSPEND_ROOM', room_id, `Restored ${room ? room.room_number : room_id} to live schedule`, actor);
    broadcastCampusUpdate(`${room ? room.room_number : room_id} restored`, actor);
  }
  res.json({ success: true });
});

app.delete('/api/history', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM audit_logs').run();
  broadcastCampusUpdate('Audit logs cleared', req.authUser.full_name || 'Admin');
  res.json({ success: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`SJIT CampusSpace (Socket.io Live) running at http://localhost:${PORT}`));