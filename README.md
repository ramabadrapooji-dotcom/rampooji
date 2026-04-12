# Anti-Gravity App - Name Storage & User Management

A secure web application for storing and managing user accounts with bcrypt password hashing and PostgreSQL database.

## Features
✅ User registration & login  
✅ Secure password hashing (bcryptjs)  
✅ Store unlimited names per user  
✅ Delete account & data  
✅ CORS enabled for API access  

## Local Setup

### Requirements
- Node.js 16+
- PostgreSQL 12+
- Git

### Installation
```bash
# 1. Clone repository
git clone https://github.com/ramabadrapooji-dotcom/rampooji.git
cd rampooji

# 2. Install dependencies
npm install

# 3. Create .env file (copy from .env.example)
cp .env.example .env

# 4. Update .env with your PostgreSQL connection
# DATABASE_URL=postgresql://user:password@localhost:5432/myapp

# 5. Start the server
npm start
# Server runs on http://localhost:3000
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/register` | Create new account |
| POST | `/login` | Login with credentials |
| GET | `/get_users` | List all users |
| POST | `/add_name` | Add name entry |
| GET | `/get_names?userId=X` | Get user's names |
| DELETE | `/delete_name/:id` | Delete a name |
| POST | `/delete_account` | Delete account permanently |
| POST | `/verify_password` | Verify credentials |

## Database Schema

### users table
```sql
id (SERIAL PRIMARY KEY)
username (TEXT UNIQUE)
password_hash (TEXT)
created_at (TIMESTAMP)
```

### user_names table
```sql
id (SERIAL PRIMARY KEY)
user_id (INTEGER, FK to users)
name_entry (TEXT)
created_at (TIMESTAMP)
```

## Deployment on Render

1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Configure:
   - **Name**: rampooji
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
6. Add Environment Variable:
   - **Key**: `DATABASE_URL`
   - **Value**: (Use Render PostgreSQL connection string)
7. Deploy!

## Environment Variables

Required:
- `DATABASE_URL` - PostgreSQL connection string
- `PORT` - Server port (default: 3000)

## License
ISC
