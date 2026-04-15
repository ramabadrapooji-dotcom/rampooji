const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Health Check for Deployment (Railway/Render)
app.get("/health", (req, res) => {
    res.status(200).send("OK");
});

// Initialize PostgreSQL Pool
const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
    connectionString: connectionString || "postgresql://postgres:password@localhost:5432/postgres",
    ssl: connectionString && connectionString.includes('localhost') ? false : { rejectUnauthorized: false }
});

pool.connect((err, client, release) => {
    if (err) {
        console.error("Database connection error (Please set DATABASE_URL):", err.message);
    } else {
        console.log("✅ Connected to PostgreSQL database");
        release();
        initializeDatabase();
    }
});

async function initializeDatabase() {
    try {
        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create user_names table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_names (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                name_entry TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);
        console.log("✅ Database tables confirmed");
    } catch (err) {
        console.error("Error creating tables:", err.message);
    }
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
        const result = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
        if (result.rows.length > 0) {
            return res.json({ success: false, message: "Username already taken. Try a different one." });
        }

        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);

        const insertResult = await pool.query(
            "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
            [username, passwordHash]
        );

        res.json({
            success: true,
            userId: insertResult.rows[0].id,
            username: username,
            message: "Account created successfully! You are now logged in."
        });
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: "Server error during registration." });
    }
});

// ─── API: Login with existing credentials ───────────────────────────
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Username and password are required." });
    }

    try {
        const result = await pool.query("SELECT id, username, password_hash FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Account not found. Please register first." });
        }

        const row = result.rows[0];
        const match = await bcrypt.compare(password, row.password_hash);
        
        if (match) {
            res.json({ success: true, userId: row.id, username: row.username, message: "Login successful!" });
        } else {
            res.json({ success: false, message: "Incorrect password." });
        }
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: "Server error." });
    }
});

// ─── API: Verify password (for account switching) ───────────────────
app.post("/verify_password", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Credentials required." });
    }

    try {
        const result = await pool.query("SELECT id, username, password_hash FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Account not found." });
        }

        const row = result.rows[0];
        const match = await bcrypt.compare(password, row.password_hash);
        
        if (match) {
            res.json({ success: true, userId: row.id, username: row.username, message: "Verified!" });
        } else {
            res.json({ success: false, message: "Incorrect password. Access denied." });
        }
    } catch (e) {
        console.error(e);
        res.json({ success: false, message: "Server error." });
    }
});

// ─── API: Get all registered usernames (for account switcher) ───────
app.get("/get_users", async (req, res) => {
    try {
        const result = await pool.query("SELECT id, username FROM users ORDER BY username ASC");
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error(err);
        res.json({ success: false, data: [] });
    }
});

// ─── API: Store a Name for the Logged-In User ───────────────────────
app.post("/add_name", async (req, res) => {
    const { userId, nameEntry } = req.body;

    if (!userId || !nameEntry) {
        return res.json({ success: false, message: "Invalid data." });
    }

    try {
        const result = await pool.query(
            "INSERT INTO user_names (user_id, name_entry) VALUES ($1, $2) RETURNING id",
            [userId, nameEntry]
        );
        res.json({ success: true, id: result.rows[0].id, message: "Name securely stored!" });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: "Failed to store name." });
    }
});

// ─── API: Delete a name entry ───────────────────────────────────────
app.delete("/delete_name/:id", async (req, res) => {
    const { id } = req.params;
    const { userId } = req.body;

    try {
        await pool.query("DELETE FROM user_names WHERE id = $1 AND user_id = $2", [id, userId]);
        res.json({ success: true, message: "Deleted successfully." });
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: "Failed to delete." });
    }
});

// ─── API: Get Names for the Logged-In User ──────────────────────────
app.get("/get_names", async (req, res) => {
    const userId = req.query.userId;

    if (!userId) {
        return res.json({ success: false, message: "User not logged in.", data: [] });
    }

    try {
        const result = await pool.query(
            "SELECT id, name_entry, created_at FROM user_names WHERE user_id = $1 ORDER BY id DESC",
            [userId]
        );
        res.json({ success: true, data: result.rows });
    } catch (err) {
        console.error(err);
        res.json({ success: false, data: [] });
    }
});

// ─── API: Delete Account permanently (requires password) ────────────
app.post("/delete_account", async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.json({ success: false, message: "Credentials required." });
    }

    try {
        const result = await pool.query("SELECT id, password_hash FROM users WHERE username = $1", [username]);
        if (result.rows.length === 0) {
            return res.json({ success: false, message: "Account not found." });
        }

        const row = result.rows[0];
        const match = await bcrypt.compare(password, row.password_hash);
        
        if (!match) {
            return res.json({ success: false, message: "Incorrect password. Cannot delete account." });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query("DELETE FROM user_names WHERE user_id = $1", [row.id]);
            await client.query("DELETE FROM users WHERE id = $1", [row.id]);
            await client.query('COMMIT');
            res.json({ success: true, message: "Account and all data permanently deleted." });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error(err);
        res.json({ success: false, message: "Server error. Failed to delete account." });
    }
});

// ─── Start Server ───────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log("╔══════════════════════════════════════╗");
    console.log("║   🚀 Server running on:              ║");
    console.log(`║   http://localhost:${PORT}             ║`);
    console.log("╚══════════════════════════════════════╝");
});