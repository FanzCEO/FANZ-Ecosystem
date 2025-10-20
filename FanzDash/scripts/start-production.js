#!/usr/bin/env node

// Production startup script for FanzDash
// Validates environment and starts the server safely

const { spawn } = require('child_process');
const crypto = require('crypto');

console.log('🚀 FanzDash Production Startup');
console.log('================================');

// Environment validation
function validateEnvironment() {
  const errors = [];
  const warnings = [];

  // Check NODE_ENV
  if (process.env.NODE_ENV !== 'production') {
    warnings.push('NODE_ENV is not set to "production"');
  }

  // Check DATABASE_URL
  if (!process.env.DATABASE_URL) {
    errors.push('DATABASE_URL is required');
  } else if (process.env.DATABASE_URL.includes('username:password@localhost')) {
    errors.push('DATABASE_URL appears to be a placeholder. Please set a real database URL.');
  }

  // Check SESSION_SECRET
  if (!process.env.SESSION_SECRET) {
    errors.push('SESSION_SECRET is required');
  } else if (process.env.SESSION_SECRET.length < 32) {
    warnings.push('SESSION_SECRET should be at least 32 characters long');
  } else if (process.env.SESSION_SECRET.includes('change-in-production')) {
    errors.push('SESSION_SECRET appears to be a placeholder. Please set a secure random string.');
  }

  // Check PORT
  const port = parseInt(process.env.PORT || '3000', 10);
  if (isNaN(port) || port < 1 || port > 65535) {
    errors.push('PORT must be a valid port number (1-65535)');
  }

  // Display results
  if (warnings.length > 0) {
    console.log('⚠️  Warnings:');
    warnings.forEach(warning => console.log(`   - ${warning}`));
    console.log('');
  }

  if (errors.length > 0) {
    console.log('❌ Configuration Errors:');
    errors.forEach(error => console.log(`   - ${error}`));
    console.log('');
    console.log('Please fix these errors before starting the server.');
    console.log('See .env.production.example for reference.');
    process.exit(1);
  }

  console.log('✅ Environment validation passed');
  return true;
}

// Generate a secure SESSION_SECRET if needed
function generateSessionSecret() {
  if (!process.env.SESSION_SECRET || 
      process.env.SESSION_SECRET.includes('change-in-production') ||
      process.env.SESSION_SECRET.length < 32) {
    
    const secret = crypto.randomBytes(32).toString('hex');
    console.log('🔐 Generated SESSION_SECRET (add this to your environment):');
    console.log(`SESSION_SECRET=${secret}`);
    console.log('');
  }
}

// Start the server
function startServer() {
  console.log('🚀 Starting FanzDash server...');
  console.log('');

  const server = spawn('node', ['dist/index.js'], {
    stdio: 'inherit',
    env: process.env
  });

  server.on('error', (err) => {
    console.error('❌ Failed to start server:', err);
    process.exit(1);
  });

  server.on('exit', (code) => {
    if (code !== 0) {
      console.error(`❌ Server exited with code ${code}`);
      process.exit(code);
    }
  });

  // Handle graceful shutdown
  process.on('SIGTERM', () => {
    console.log('📴 Received SIGTERM, shutting down gracefully...');
    server.kill('SIGTERM');
  });

  process.on('SIGINT', () => {
    console.log('📴 Received SIGINT, shutting down gracefully...');
    server.kill('SIGINT');
  });
}

// Main execution
try {
  validateEnvironment();
  generateSessionSecret();
  startServer();
} catch (error) {
  console.error('❌ Startup failed:', error);
  process.exit(1);
}