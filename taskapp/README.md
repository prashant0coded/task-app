# Taskboard: Express + MongoDB + Socket.IO

Features: register/login (bcrypt + JWT), per-user task CRUD, live updates across tabs and devices, responsive UI.

## Run locally
1. `npm install`
2. Copy `.env.example` to `.env`; set `MONGODB_URI` (MongoDB Atlas free tier) and `JWT_SECRET`.
3. `npm run dev`, then open http://localhost:3000. Open it in two windows to see real-time sync.

## API
| Method | Route | Notes |
|---|---|---|
| POST | /api/auth/register | name, email, password (8+ chars) |
| POST | /api/auth/login | returns JWT |
| GET | /api/auth/me | Bearer token |
| GET / POST | /api/tasks | Bearer token |
| PUT / DELETE | /api/tasks/:id | owner only |

Socket.IO events (server to client): `task:saved`, `task:deleted`, sent only to the owner's private room.

## Deploy
Use **Render** or **Railway** (Web Service, build `npm install`, start `npm start`) and set the two env vars.
Vercel and Netlify run serverless functions, which cannot keep WebSocket connections open, so real-time would not work there.
