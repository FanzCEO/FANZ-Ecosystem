# FanzDash DigitalOcean Deployment Guide

## Prerequisites

1. **DigitalOcean Account** with App Platform access
2. **Neon PostgreSQL Database** (or other PostgreSQL provider)
3. **GitHub Repository** with your FanzDash code

## Step 1: Prepare Your Database

### Option A: Neon (Recommended)
1. Sign up at [neon.tech](https://neon.tech)
2. Create a new project
3. Copy the connection string (it should look like):
   ```
   postgresql://username:password@hostname.neon.tech:5432/database_name
   ```

### Option B: DigitalOcean Managed PostgreSQL
1. In DigitalOcean, create a Managed Database (PostgreSQL)
2. Note the connection details

## Step 2: Create App in DigitalOcean App Platform

1. Go to [DigitalOcean App Platform](https://cloud.digitalocean.com/apps)
2. Click "Create App"
3. Connect your GitHub repository
4. Select the repository containing FanzDash
5. Choose the branch (usually `main`)

## Step 3: Configure Build Settings

### Build Command:
```bash
npm run build
```

### Start Command:
```bash
node scripts/start-production.js
```

### Node Version:
Set to `18.x` or `20.x` (latest LTS)

## Step 4: Set Environment Variables

In the App Platform dashboard, add these environment variables:

### Required Variables:
```bash
NODE_ENV=production
DATABASE_URL=postgresql://username:password@hostname:5432/database_name
SESSION_SECRET=your-64-character-secure-random-string-here
PORT=3000
```

### Optional Variables:
```bash
# Redis for session store (if you have Redis)
REDIS_URL=redis://hostname:6379
SESSION_STORE=redis

# OpenAI for AI features
OPENAI_API_KEY=sk-your-openai-key-here

# Build configuration
VITE_API_BASE_URL=/api
```

### Generate a Secure SESSION_SECRET:
Run this command to generate a secure session secret:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Step 5: Configure Health Check

1. In App Platform settings, set Health Check endpoint to: `/api/health`
2. Set Health Check path to: `/api/health`

## Step 6: Deploy

1. Click "Create Resources"
2. Wait for the build and deployment to complete
3. Check the logs for any errors

## Step 7: Verify Deployment

1. Visit your app URL
2. Check that the health endpoint works: `https://your-app.ondigitalocean.app/api/health`
3. Should return: `{"status":"healthy","timestamp":"...","version":"1.0.0"}`

## Troubleshooting

### Common Issues:

#### 1. "App keeps crashing"
- Check environment variables are set correctly
- Ensure DATABASE_URL is valid and database is accessible
- Check logs for specific error messages

#### 2. "Database connection failed"
- Verify DATABASE_URL format
- Ensure database server allows connections from DigitalOcean IPs
- Test connection locally with the same URL

#### 3. "Build fails"
- Ensure all dependencies are in package.json
- Check Node.js version compatibility
- Review build logs for specific errors

#### 4. "502 Bad Gateway"
- App may be starting on wrong port
- Check that PORT environment variable is set to 3000
- Verify health check endpoint is responding

### Debug Steps:

1. **Check Logs:**
   ```bash
   # In DigitalOcean App Platform dashboard
   View Runtime Logs
   ```

2. **Test Locally:**
   ```bash
   # Set environment variables and test
   NODE_ENV=production npm run build
   NODE_ENV=production npm start
   ```

3. **Test Health Check:**
   ```bash
   curl https://your-app.ondigitalocean.app/api/health
   ```

## Production Environment Variables Template

Copy this to your DigitalOcean App Platform environment variables:

```
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://user:pass@hostname:5432/dbname
SESSION_SECRET=generated-64-character-string-here
VITE_API_BASE_URL=/api
```

## Security Notes

1. **Always use HTTPS** in production (DigitalOcean provides this automatically)
2. **Secure your DATABASE_URL** - don't expose it in logs or client code
3. **Use a strong SESSION_SECRET** - generate it with crypto.randomBytes()
4. **Review CORS settings** if you have cross-origin requests

## Support

If deployment fails:

1. Check the environment variables are correctly set
2. Review the build and runtime logs in DigitalOcean
3. Test the health endpoint
4. Ensure your database is accessible from DigitalOcean's network

The app includes extensive logging to help diagnose issues. Look for messages starting with ✅ or ❌ in the logs.