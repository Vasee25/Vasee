# Secure Document Management System

A simple, responsive internal-office document management MVP.

## Included
- Secure login/logout
- Admin and Employee roles
- Folder management
- Upload/download/delete documents
- Folder/file access permissions
- Search
- Document version history
- Upload/download audit tracking
- Admin dashboard
- Email notifications
- Responsive UI
- Security headers and login rate limiting

## Requirements
- Node.js 20+
- npm

## Run
1. Copy `.env.example` to `.env`
2. Set a strong `SESSION_SECRET`
3. Run `npm install`
4. Run `npm start`
5. Open `http://localhost:3000`

On first run, the application creates the database and an administrator:
- Email: `admin@example.com`
- Password: `ChangeMe123!`

**Change the admin password immediately after first login.**

Uploaded files are stored under `storage/`. The SQLite database is under `data/`.

## SMTP
Set SMTP_* and MAIL_FROM in `.env` for real email notifications. If SMTP is not configured, notifications are written to the server console.

## Production notes
- Put the application behind HTTPS.
- Use a strong random SESSION_SECRET.
- Restrict access to the office network/VPN as appropriate.
- Move file storage to private object storage for larger deployments.
- Back up both the database and storage directory.
- Replace the bootstrap admin password immediately.
