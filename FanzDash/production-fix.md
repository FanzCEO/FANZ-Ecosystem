# FanzDash Production Deployment Issues & Fixes

## Identified Issues

### 1. Missing Environment Variables
The app requires several critical environment variables that are likely missing in production:

- `DATABASE_URL` - Neon PostgreSQL connection string
- `SESSION_SECRET` - Required for session management
- `REDIS_URL` - Redis connection for session store (optional)
- `NODE_ENV=production` - Enables production mode

### 2. Database Connection Handling
The app uses Neon Serverless PostgreSQL but has a mock fallback when DATABASE_URL is invalid:
- In development: Uses mock database
- In production: Requires valid DATABASE_URL or app will use mocks

### 3. Server Configuration
The server binds to host "*******" (redacted) which might be causing binding issues.

## Quick Fixes

### Step 1: Set Environment Variables in DigitalOcean

```bash
# In DigitalOcean App Platform, add these environment variables:
NODE_ENV=production
DATABASE_URL=postgresql://username:password@hostname:5432/database
SESSION_SECRET=your-secure-random-string-here

# Optional Redis for session store:
REDIS_URL=redis://your-redis-url:6379
```

### Step 2: Fix Server Binding Issue

Update `server/index.ts` line 70:

```typescript
// Change from:
host: "*******",

// To:
host: "0.0.0.0",
```

### Step 3: Add Health Check Endpoint

The app already has a health check at `/api/health` - ensure DigitalOcean is using this endpoint.

### Step 4: Database Setup

If you don't have a database yet, you need to:

1. Create a Neon PostgreSQL database
2. Run the database migrations
3. Set the DATABASE_URL environment variable

### Step 5: Build Configuration

Ensure your DigitalOcean build command is:

```bash
npm run build
```

And start command is:

```bash
npm start
```

## Testing the Fix

1. First, test locally with production environment:
   ```bash
   NODE_ENV=production npm start
   ```

2. Check the health endpoint:
   ```bash
   curl http://localhost:3000/api/health
   ```

3. If successful, deploy to DigitalOcean with the environment variables set.

## Additional Debugging

If issues persist, add more logging to `server/index.ts`:

```typescript
// Add before registerRoutes call
console.log('Environment variables check:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('DATABASE_URL exists:', !!process.env.DATABASE_URL);
console.log('SESSION_SECRET exists:', !!process.env.SESSION_SECRET);
console.log('PORT:', process.env.PORT || 3000);

try {
  const server = await registerRoutes(app);
  console.log('Routes registered successfully');
  // ... rest of code
} catch (error) {
  console.error('Failed to register routes:', error);
  process.exit(1);
}
```

## Priority Order

1. **Fix host binding** - Change "*******" to "0.0.0.0"
2. **Set DATABASE_URL** - Create and configure Neon database
3. **Set SESSION_SECRET** - Add secure random string
4. **Test health endpoint** - Verify `/api/health` returns 200
5. **Deploy with proper environment variables**

The most critical issue is likely the host binding configuration preventing the server from accepting connections on DigitalOcean's infrastructure.