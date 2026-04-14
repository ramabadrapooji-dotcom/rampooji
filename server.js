const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
let dbConnected = false;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Health check endpoint for Railway
app.get('/health', (req, res) => res.status(200).send('OK'));

app.use((req, res, next) => {
    if (!dbConnected && req.path !== '/' && req.path !== '/health' && !req.path.startsWith('/static')) {
        return res.status(503).json({
            success: false,
            message: "Database is unavailable. Please check your data mount."
        });
    }
    next();
});

// Initialize SQLite Database
const db = new sqlite3.Database('./app_data.db', (err) => {
    if (err) {
        console.error("Database error:", err.message);
    } else {
        dbConnected = true;
        console.log("✅ Connected to SQLite database");
        initializeDatabase();
    }
});

function initializeDatabase() {
    db.serialize(() => {
        // Create users table
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create user_names table
        db.run(`
            CREATE TABLE IF NOT EXISTS user_names (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name_entry TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
    });
}

// ─── API: Register a new account ────────────────────────────────────
app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required." });
    }
    if (username.length < 3) {
        return res.json({ success: false, message: "Username must be at least 3 characters." });
    }
    if (password.length < 4) {
        return res.json({ success: false, message: "Password must be at least 4 characters." });
    }

    try {
        db.get("SELECT id FROM users WHERE username = ?", [username], async (err, row) => {
            if (err) return res.json({ success: false, message: "Server error." });
            if (row) return res.json({ success: false, message: "Username already taken. Try a different one." });

            const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

            db.run("INSERT INTO users (username, password_hash) VALUES (?, ?)", [username, passwordHash], function(err) {
                if (err) {
                    return res.json({ success: false, message: "Server error during registration." });
                }
                res.json({
                    success: true,
                    userId: this.lastID,
                    username: username,
                    message: "Account created successfully! You are now logged in."
                });
            });
        });
    } catch (e) {
        res.json({ success: false, message: "Server error." });
    }
});

// ─── API: Login with existing credentials ───────────────────────────
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required." });
    }

    db.get("SELECT id, username, password_hash FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) return res.json({ success: false, message: "Server error." });
        if (!row) return res.json({ success: false, message: "Account not found. Please register first." });

        const match = await bcrypt.compare(password, row.password_hash);
        if (match) {
            res.json({ success: true, userId: row.id, username: row.username, message: "Login successful!" });
        } else {
            res.json({ success: false, message: "Incorrect password." });
        }
    });
});

// ─── API: Verify password (for account switching) ───────────────────
app.post("/verify_password", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Credentials required." });
    }

    db.get("SELECT id, username, password_hash FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) return res.json({ success: false, message: "Server error." });
        if (!row) return res.json({ success: false, message: "Account not found." });

        const match = await bcrypt.compare(password, row.password_hash);
        if (match) {
            res.json({ success: true, userId: row.id, username: row.username, message: "Verified!" });
        } else {
            res.json({ success: false, message: "Incorrect password. Access denied." });
        }
    });
});

// ─── API: Get all registered usernames (for account switcher) ───────
app.get("/get_users", (req, res) => {
    db.all("SELECT id, username FROM users ORDER BY username ASC", [], (err, rows) => {
        if (err) return res.json({ success: false, data: [] });
        res.json({ success: true, data: rows });
    });
});

// ─── API: Store a Name for the Logged-In User ───────────────────────
app.post("/add_name", (req, res) => {
    const { userId, nameEntry } = req.body;

    if (!userId || !nameEntry) {
        return res.json({ success: false, message: "Invalid data." });
    }

    db.run("INSERT INTO user_names (user_id, name_entry) VALUES (?, ?)", [userId, nameEntry], function(err) {
        if (err) return res.json({ success: false, message: "Failed to store name." });
        res.json({ success: true, id: this.lastID, message: "Name securely stored!" });
    });
});

// ─── API: Delete a name entry ───────────────────────────────────────
app.delete("/delete_name/:id", (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;

    db.run("DELETE FROM user_names WHERE id = ? AND user_id = ?", [id, userId], function(err) {
        if (err) return res.json({ success: false, message: "Failed to delete." });
        res.json({ success: true, message: "Deleted successfully." });
    });
});

// ─── API: Get Names for the Logged-In User ──────────────────────────
app.get("/get_names", (req, res) => {
    const userId = req.query.userId;

    if (!userId) {
        return res.json({ success: false, message: "User not logged in.", data: [] });
    }

    db.all("SELECT id, name_entry, created_at FROM user_names WHERE user_id = ? ORDER BY id DESC", [userId], (err, rows) => {
        if (err) return res.json({ success: false, data: [] });
        res.json({ success: true, data: rows });
    });
});

// ─── API: Delete Account permanently (requires password) ────────────
app.post("/delete_account", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Credentials required." });
    }

    db.get("SELECT id, password_hash FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) return res.json({ success: false, message: "Server error." });
        if (!row) return res.json({ success: false, message: "Account not found." });

        const match = await bcrypt.compare(password, row.password_hash);
        if (!match) return res.json({ success: false, message: "Incorrect password. Cannot delete account." });

        db.serialize(() => {
            db.run("DELETE FROM user_names WHERE user_id = ?", [row.id]);
            db.run("DELETE FROM users WHERE id = ?", [row.id], function(err) {
                if (err) return res.json({ success: false, message: "Failed to delete account." });
                res.json({ success: true, message: "Account and all data permanently deleted." });
            });
        });
    });
});

// ─── Start Server ───────────────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
    console.log("╔══════════════════════════════════════╗");
    console.log("║   🚀 Server running on:              ║");
    console.log(`║   http://0.0.0.0:${PORT}             ║`);
    console.log("╚══════════════════════════════════════╝");
});