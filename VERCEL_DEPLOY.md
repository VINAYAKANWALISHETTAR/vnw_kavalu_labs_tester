# Kavalu Labs Security Engine — Deploy to Vercel
**Developed by Vinayaka N Walishettar**

## Prerequisites
1. Vercel account (free at https://vercel.com)
2. Vercel CLI installed: `npm i -g vercel`
3. Git repository with your code pushed to GitHub/GitLab/Bitbucket

## Deployment Steps

### 1. Install Vercel CLI
```bash
npm install -g vercel
```

### 2. Login to Vercel
```bash
vercel login
```

### 3. Deploy from project directory
```bash
cd web-app-security-tester-main
vercel
```

Follow the prompts:
- Set up and deploy? **Yes**
- Link to existing project? **No** (create new)
- Project name? (enter any name)
- Directory? **./** (current)

### 4. Environment Variables (optional)
If you need environment variables:
```bash
vercel env add SECRET_KEY
```

### 5. Production Deploy
```bash
vercel --prod
```

## Important Limitations on Vercel Serverless

1. **No Selenium/Chrome**: Browser automation won't work in serverless functions
   - Only Reconnaissance and Request-based vulnerability scans work
   - DOM XSS testing is disabled

2. **No long-running background tasks**: Scans run synchronously and must complete within Vercel's timeout (max 10-60 seconds on free tier)

3. **Ephemeral storage**: Files in `/tmp` are deleted after function execution
   - Downloaded reports work but aren't persisted between requests
   - Scan history is in-memory only (lost on cold starts)

4. **Burp Suite**: Requires your own Burp instance with public IP

## Alternative: Full-Featured Hosting

For full functionality (Selenium, persistent storage, long scans), consider:
- **Railway.app** - Easy Docker deploy
- **Render.com** - Free tier with background workers
- **DigitalOcean App Platform** - Full Linux container
- **Heroku** - Simple but paid for background workers

## Local Development

For local testing with full features:
```bash
pip install -r requirements.txt
python app.py
```

For testing the Vercel version locally:
```bash
vercel dev
```
