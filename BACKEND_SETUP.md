# Netlify backend

1. Copy `netlify.toml` and `netlify/functions/` into the root of your GitHub project.
2. Use a hosted PostgreSQL database (Neon, Supabase PostgreSQL, etc.).
3. In Netlify > Site configuration > Environment variables, add:
   - `DATABASE_URL`
   - `JWT_SECRET`
   - `ADMIN_EMAIL`
   - `ADMIN_PASSWORD`
4. Redeploy.
5. Test `https://YOUR-SITE.netlify.app/api/health`.

Important: this backend fixes the current `Request failed` login problem and provides authentication, folders, document listing/search, dashboard, users and audit APIs. The upload/version endpoints still need persistent file-storage integration (S3/Supabase Storage/Netlify Blobs) before production use.
