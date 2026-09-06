# 🚀 Deploying Mailtrace AI on Render

This guide outlines three foolproof ways to deploy **Mailtrace AI** on [Render.com](https://render.com).

---

## 🌟 Method 1: Blueprint Deployment (Fastest & 1-Click)

The repository includes a ready-to-use [`render.yaml`](./render.yaml) blueprint that configures the application automatically.

1. Log in to [Render Dashboard](https://dashboard.render.com).
2. Click **Blueprints** on the top menu (or **New +** > **Blueprint**).
3. Connect your GitHub repository: `libineshr7-cyber/mailtrace.ai`.
4. Render will automatically detect `render.yaml` and configure:
   - **Service Name**: `mailtrace-ai`
   - **Environment**: `Docker` (Multi-stage Node 20 + Python 3.11)
   - **Health Check Path**: `/api/system/health`
   - **Instance Type**: Free
5. Click **Apply**.
6. Render builds the React frontend, packages the FastAPI backend, and deploys it live at `https://mailtrace-ai.onrender.com`.

---

## 🐳 Method 2: Manual Web Service via Docker

If you prefer setting up via the standard Web Service interface:

1. In Render Dashboard, click **New +** > **Web Service**.
2. Select your repository: `libineshr7-cyber/mailtrace.ai`.
3. Configure the settings:
   - **Name**: `mailtrace-ai`
   - **Region**: Oregon (or your preferred region)
   - **Branch**: `main`
   - **Root Directory**: *(leave blank)*
   - **Language / Runtime**: **Docker**
   - **Instance Type**: **Free**
4. Under **Advanced Settings**:
   - **Health Check Path**: `/api/system/health`
5. Click **Deploy Web Service**.

Render will run the multi-stage `Dockerfile`, build the React UI, mount the API, and start Uvicorn.

---

## 🧩 Method 3: Separate Backend & Frontend (Static Site + Web Service)

If you want the frontend on Render's global CDN and the backend on a Python Web Service:

### Step A: Deploy Backend Web Service
1. In Render Dashboard, click **New +** > **Web Service**.
2. Select repository: `libineshr7-cyber/mailtrace.ai`.
3. Configure:
   - **Name**: `mailtrace-api`
   - **Language**: **Python 3**
   - **Branch**: `main`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: Free
4. Click **Deploy Web Service**.
5. Copy your backend URL (e.g. `https://mailtrace-api.onrender.com`).

### Step B: Deploy Frontend Static Site
1. In Render Dashboard, click **New +** > **Static Site**.
2. Select repository: `libineshr7-cyber/mailtrace.ai`.
3. Configure:
   - **Name**: `mailtrace-web`
   - **Branch**: `main`
   - **Root Directory**: `frontend`
   - **Build Command**: `npm install && npm run build`
   - **Publish Directory**: `dist`
4. Under **Environment Variables**, add:
   - `VITE_API_BASE_URL` = `https://mailtrace-api.onrender.com` *(your backend URL from Step A)*
5. Click **Create Static Site**.

---

## 🛡️ Verifying Your Deployment

Once deployed:
1. Open your web URL (e.g., `https://mailtrace-ai.onrender.com`).
2. Go to **Email Analysis** -> Click on any sample email (e.g., *Bank Security Alert*) -> Click **Run Deep Forensic Triage**.
3. Watch the real-time log stream dissect the MIME headers, perform live DNS and threat intel queries, and seal the case in SQLite.
4. Verify the interactive **Threat Graph**, **Infrastructure Map**, and **DFIR Report** tabs.
