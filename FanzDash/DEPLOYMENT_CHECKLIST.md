# FanzDash Production Deployment Checklist

## Pre-Deployment Checklist

### ✅ Code Preparation
- [x] Fix production server binding (0.0.0.0)
- [x] Add comprehensive error handling
- [x] Create production startup script
- [x] Add environment validation
- [x] Build process working (`npm run build`)
- [x] Production documentation created

### 🔧 Environment Setup
- [ ] DATABASE_URL configured (Neon PostgreSQL)
- [ ] SESSION_SECRET generated (64+ characters)
- [ ] NODE_ENV=production set
- [ ] PORT=3000 configured
- [ ] Optional: REDIS_URL for session store

### 🏗️ Build Warnings to Address
Current build shows these warnings that should be fixed:
- [x] Replace `eval()` calls in video processing (security risk) ✅ FIXED
- [x] Fix duplicate `getModerationSettings` methods in storage.ts ✅ FIXED
- [ ] Consider code splitting for large bundle (2.9MB) - Future optimization

## Quick Environment Test

Generate a secure session secret:
```bash
node -e "console.log('SESSION_SECRET=' + require('crypto').randomBytes(32).toString('hex'))"
```

Test build locally:
```bash
npm run build
```

## DigitalOcean Deployment Steps

### 1. Database Setup
- [ ] Create Neon PostgreSQL database
- [ ] Note connection string
- [ ] Test connection from local machine

### 2. App Platform Configuration
- [ ] Connect GitHub repository
- [ ] Set build command: `npm run build`
- [ ] Set start command: `node scripts/start-production.js`
- [ ] Set Node.js version to 18.x or 20.x

### 3. Environment Variables
Copy these to DigitalOcean App Platform:
```
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://user:pass@hostname.neon.tech:5432/dbname
SESSION_SECRET=your-generated-64-char-string
```

### 4. Health Check
- [ ] Set health check endpoint: `/api/health`
- [ ] Expected response: `{"status":"healthy","timestamp":"...","version":"1.0.0"}`

### 5. Deployment
- [ ] Deploy application
- [ ] Check build logs for errors
- [ ] Check runtime logs for startup messages
- [ ] Test health endpoint
- [ ] Verify app loads correctly

## Post-Deployment Testing

### Health Check
```bash
curl https://your-app.ondigitalocean.app/api/health
```
Should return 200 status with JSON response.

### Application Access
- [ ] App loads at main URL
- [ ] Dashboard interface accessible
- [ ] No console errors in browser
- [ ] API endpoints responding

## Troubleshooting Guide

### Common Issues:

1. **"App keeps crashing"**
   - Check environment variables are set
   - Review runtime logs for errors
   - Ensure DATABASE_URL is valid

2. **"502 Bad Gateway"**
   - App not binding to correct host/port
   - Check server startup logs
   - Verify health endpoint works

3. **"Build fails"**
   - Check Node.js version compatibility
   - Ensure all dependencies in package.json
   - Review build logs

4. **"Database connection failed"**
   - Verify DATABASE_URL format
   - Check database allows external connections
   - Test connection string locally

### Debug Steps:
1. Check DigitalOcean runtime logs
2. Test health endpoint
3. Verify environment variables
4. Check database connectivity

## Security Checklist
- [ ] SESSION_SECRET is cryptographically secure
- [ ] DATABASE_URL not exposed in client code
- [ ] HTTPS enabled (automatic in DigitalOcean)
- [ ] No sensitive data in logs
- [ ] CORS properly configured

## Performance Optimization (Future)
- [ ] Implement code splitting for large bundle
- [ ] Add Redis for session store
- [ ] Configure CDN for static assets
- [ ] Enable gzip compression
- [ ] Monitor performance metrics

## Notes
- The app includes mock database fallback for development
- Production requires valid DATABASE_URL
- Health endpoint works independently of database
- Extensive logging added for debugging