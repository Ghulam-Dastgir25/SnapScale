const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { nanoid } = require("nanoid");
const { JSONFilePreset } = require("lowdb/node");

// ✅ Azure uses PORT env var
const PORT = process.env.PORT || 7071;

// ✅ Use a writable/persistent location on Azure Linux App Service:
// /home is writable and persists across restarts (unlike your app folder)
const DATA_DIR =
  process.env.SNAP_DATA_DIR ||
  path.join(process.env.HOME || "/home", "snapscale");

fs.mkdirSync(DATA_DIR, { recursive: true });

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Serve frontend from backend (one origin)
app.use("/", express.static(path.join(__dirname, "..", "frontend")));

// ✅ Uploads folder (keep local uploads behavior)
const uploadsDir = path.join(__dirname, "uploads");
fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(uploadsDir));

// ✅ LowDB file moved to DATA_DIR (Azure safe)
const dbPath = path.join(DATA_DIR, "db.json");
let db;

function ensureUploadsDir() {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// ✅ Validation helpers
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}
// Strong password: min 8, 1 upper, 1 lower, 1 number
function isStrongPassword(pw) {
  if (typeof pw !== "string") return false;
  if (pw.length < 8) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  return true;
}

async function initDb() {
  db = await JSONFilePreset(dbPath, { users: [], sessions: [], media: [] });
  await db.read();
  db.data.users ||= [];
  db.data.sessions ||= [];
  db.data.media ||= [];

  // ✅ Ensure creator account exists (always)
  const creatorEmail = "creator@snayscale.com";
  const hasCreator = db.data.users.some(
    (u) => (u.email || "").toLowerCase() === creatorEmail
  );
  if (!hasCreator) {
    db.data.users.push({
      id: "creator-1",
      email: creatorEmail,
      password: "Creator123!",
      role: "creator",
      createdAt: 0,
    });
  }

  await db.write();
}

// ---------- Auth helpers ----------
function getToken(req) {
  const h = req.headers.authorization || "";
  if (h.startsWith("Bearer ")) return h.slice(7);
  return null;
}

async function requireAuth(req, res, next) {
  await db.read();
  const token = getToken(req);
  if (!token) return res.status(401).json({ error: "Login required" });

  const session = db.data.sessions.find((s) => s.token === token);
  if (!session) return res.status(401).json({ error: "Invalid session" });

  const user = db.data.users.find((u) => u.id === session.userId);
  if (!user) return res.status(401).json({ error: "User not found" });

  req.user = { id: user.id, email: user.email, role: user.role };
  req.token = token;
  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: "Login required" });
    if (req.user.role !== role)
      return res.status(403).json({ error: `Requires role: ${role}` });
    next();
  };
}

// ---------- Upload ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureUploadsDir();
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const ext = (path.extname(file.originalname) || ".jpg").toLowerCase();
    const safeExt = [".jpg", ".jpeg", ".png", ".webp"].includes(ext)
      ? ext
      : ".jpg";
    cb(null, `${nanoid()}${safeExt}`);
  },
});
const upload = multer({ storage });

// ---------- Utils ----------
function computeVoteCounts(item) {
  const votes = item.votes || {};
  let likes = 0,
    dislikes = 0;
  for (const v of Object.values(votes)) {
    if (v === "like") likes++;
    if (v === "dislike") dislikes++;
  }
  return { likes, dislikes };
}

// ---------- Health ----------
app.get("/api/health", (req, res) =>
  res.json({ ok: true, time: Date.now() })
);

// ---------- Auth endpoints ----------
app.post("/api/auth/register", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  if (!isValidEmail(email)) {
    return res
      .status(400)
      .json({ error: "Invalid email. Use format: name@example.com" });
  }

  if (!isStrongPassword(password)) {
    return res.status(400).json({
      error: "Weak password. Min 8 chars + uppercase + lowercase + number.",
    });
  }

  await db.read();
  if (db.data.users.some((u) => u.email === email))
    return res.status(409).json({ error: "Email already registered" });

  db.data.users.push({
    id: nanoid(),
    email,
    password,
    role: "consumer",
    createdAt: Date.now(),
  });
  await db.write();
  res.status(201).json({ ok: true });
});

app.post("/api/auth/login", async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  await db.read();
  const user = db.data.users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: "Invalid email or password" });

  const token = nanoid();
  db.data.sessions.push({ token, userId: user.id, createdAt: Date.now() });
  await db.write();

  res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  await db.read();
  db.data.sessions = db.data.sessions.filter((s) => s.token !== req.token);
  await db.write();
  res.json({ ok: true });
});

// ---------- Media endpoints ----------
app.get("/api/media", requireAuth, async (req, res) => {
  await db.read();
  const q = String(req.query.q || "").toLowerCase();

  const items = db.data.media
    .filter((m) => {
      if (!q) return true;
      const hay = [m.title, m.location, m.caption, m.people]
        .map((x) => String(x || "").toLowerCase())
        .join(" | ");
      return hay.includes(q);
    })
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0))
    .map((m) => {
      const counts = computeVoteCounts(m);
      return {
        ...m,
        likes: counts.likes,
        dislikes: counts.dislikes,
        myVote: (m.votes || {})[req.user.id] || null,
      };
    });

  res.json({ items });
});

app.post(
  "/api/media",
  requireAuth,
  requireRole("creator"),
  upload.single("image"),
  async (req, res) => {
    await db.read();
    if (!req.file)
      return res.status(400).json({ error: "Missing image (field name: image)" });

    const item = {
      id: nanoid(),
      creatorId: req.user.id,
      title: String(req.body.title || "").trim(),
      caption: String(req.body.caption || "").trim(),
      location: String(req.body.location || "").trim(),
      people: String(req.body.people || "").trim(),
      imageUrl: `/uploads/${req.file.filename}`,
      createdAt: Date.now(),
      comments: [],
      votes: {},
    };

    if (!item.title) return res.status(400).json({ error: "Title is required" });

    db.data.media.push(item);
    await db.write();

    const counts = computeVoteCounts(item);
    res.status(201).json({
      item: { ...item, likes: counts.likes, dislikes: counts.dislikes, myVote: null },
    });
  }
);

app.post("/api/media/:id/comment", requireAuth, async (req, res) => {
  await db.read();
  const item = db.data.media.find((m) => m.id === req.params.id);
  if (!item) return res.status(404).json({ error: "Not found" });

  const text = String(req.body.text || "").trim();
  if (!text) return res.status(400).json({ error: "Comment text required" });

  item.comments.push({
    id: nanoid(),
    userEmail: req.user.email,
    text,
    createdAt: Date.now(),
  });
  await db.write();

  const counts = computeVoteCounts(item);
  res.json({
    item: {
      ...item,
      likes: counts.likes,
      dislikes: counts.dislikes,
      myVote: (item.votes || {})[req.user.id] || null,
    },
  });
});

app.post("/api/media/:id/vote", requireAuth, async (req, res) => {
  await db.read();
  const item = db.data.media.find((m) => m.id === req.params.id);
  if (!item) return res.status(404).json({ error: "Not found" });

  const value = String(req.body.value || "");
  if (!["like", "dislike", "clear"].includes(value))
    return res.status(400).json({ error: "Vote must be like, dislike, or clear" });

  item.votes ||= {};
  if (value === "clear") delete item.votes[req.user.id];
  else item.votes[req.user.id] = value;

  await db.write();

  const counts = computeVoteCounts(item);
  res.json({
    item: {
      ...item,
      likes: counts.likes,
      dislikes: counts.dislikes,
      myVote: (item.votes || {})[req.user.id] || null,
    },
  });
});

// ✅ Start after DB init + bind to 0.0.0.0 (Azure safe)
initDb()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`SnapScale API running on port ${PORT}`);
      console.log(`Health: /api/health`);
    });
  })
  .catch((err) => {
    console.error("Failed to init DB:", err);
    process.exit(1);
  });
