export interface Env {
  NEWSLETTER_SUBSCRIBERS: KVNamespace;
  R2_BUCKET?: R2Bucket; // R2 bucket for newsletter files
  ALLOWED_ORIGIN?: string;
  RESEND_API_KEY?: string; // Resend API key for email notifications
  ADMIN_TOKEN?: string; // Token for protected endpoints
  ENVIRONMENT?: string; // 'production' or 'development'
}

interface NewsletterItem {
  filename: string;
  date: string;
  title: string;
  url: string;
}

// Constants
const MAX_REQUEST_SIZE = 1024; // 1KB max request size
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 5; // 5 requests per minute per IP
const MAX_EMAIL_LENGTH = 320; // RFC 5322 max email length

// Enhanced email validation regex
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Security headers
const securityHeaders = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
};

// Get CORS headers based on request origin
function getCorsHeaders(request: Request, env: Env): Record<string, string> {
  const origin = request.headers.get('Origin');
  const allowedOrigin = env.ALLOWED_ORIGIN || 'https://philippdubach.com';
  
  // Parse allowed origins (comma-separated)
  const allowedOrigins = allowedOrigin.split(',').map(o => o.trim());
  
  // Validate origin against allowed list
  if (origin && allowedOrigins.some(allowed => 
    origin === allowed || 
    origin.endsWith('.philippdubach.com')
  )) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      ...securityHeaders,
    };
  }
  
  // Return minimal headers for non-browser requests or disallowed origins
  return {
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    ...securityHeaders,
  };
}

function handleOptions(request: Request, env: Env): Response {
  return new Response(null, {
    headers: getCorsHeaders(request, env),
  });
}

function jsonResponse(data: unknown, status: number, request: Request, env: Env): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...getCorsHeaders(request, env),
      'Content-Type': 'application/json',
    },
  });
}

// Sanitize email for safe HTML insertion (prevent XSS)
function sanitizeForHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Validate email with comprehensive checks
function isValidEmail(email: string): boolean {
  if (!email || typeof email !== 'string') return false;
  if (email.length > MAX_EMAIL_LENGTH) return false;
  return EMAIL_REGEX.test(email);
}

// Get client IP from request
function getClientIP(request: Request): string {
  // Cloudflare provides CF-Connecting-IP
  const cfIP = request.headers.get('CF-Connecting-IP');
  if (cfIP) return cfIP;
  
  // Fallback to X-Forwarded-For
  const xff = request.headers.get('X-Forwarded-For');
  if (xff) return xff.split(',')[0].trim();
  
  return 'unknown';
}

// Rate limiting using KV
async function checkRateLimit(ip: string, env: Env): Promise<boolean> {
  const key = `rate_limit:${ip}`;
  
  try {
    const current = await env.NEWSLETTER_SUBSCRIBERS.get(key);
    const now = Date.now();
    
    if (!current) {
      // First request, set limit
      await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify({
        count: 1,
        resetAt: now + RATE_LIMIT_WINDOW_MS
      }), { expirationTtl: 120 }); // 2 minute TTL
      return true;
    }
    
    const data = JSON.parse(current) as { count: number; resetAt: number };
    
    if (data.resetAt < now) {
      // Window expired, reset
      await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify({
        count: 1,
        resetAt: now + RATE_LIMIT_WINDOW_MS
      }), { expirationTtl: 120 });
      return true;
    }
    
    if (data.count >= RATE_LIMIT_MAX_REQUESTS) {
      return false; // Rate limit exceeded
    }
    
    // Increment count
    data.count++;
    await env.NEWSLETTER_SUBSCRIBERS.put(key, JSON.stringify(data), { expirationTtl: 120 });
    return true;
  } catch {
    // On error, allow request (fail open for availability)
    return true;
  }
}

// Timing-safe string comparison
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Check admin authentication
function requireAuth(request: Request, env: Env): boolean {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return false;
  
  const token = authHeader.slice(7);
  const expectedToken = env.ADMIN_TOKEN;
  
  if (!expectedToken) return false;
  
  return timingSafeEqual(token, expectedToken);
}

async function handleSubscribe(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    // Check request size
    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > MAX_REQUEST_SIZE) {
      return jsonResponse({ success: false, error: 'Request too large' }, 413, request, env);
    }

    // Rate limiting
    const clientIP = getClientIP(request);
    if (!await checkRateLimit(clientIP, env)) {
      return jsonResponse({ success: false, error: 'Too many requests. Please try again later.' }, 429, request, env);
    }

    const body = await request.json() as { email?: string; honeypot?: string };
    
    // Honeypot check (spam protection)
    if (body.honeypot) {
      return jsonResponse({ success: false, error: 'Invalid request' }, 400, request, env);
    }

    const email = (body.email || '').trim().toLowerCase();

    // Validate email with enhanced validation
    if (!isValidEmail(email)) {
      return jsonResponse({ success: false, error: 'Invalid email address' }, 400, request, env);
    }

    // Check if already subscribed
    const existing = await env.NEWSLETTER_SUBSCRIBERS.get(email);
    if (existing) {
      return jsonResponse({ success: true, message: 'Already subscribed' }, 200, request, env);
    }

    // Store email with timestamp and consent metadata
    const subscriptionData = {
      timestamp: new Date().toISOString(),
      ip: clientIP,
      userAgent: request.headers.get('User-Agent') || 'unknown',
    };
    await env.NEWSLETTER_SUBSCRIBERS.put(email, JSON.stringify(subscriptionData));

    // Send welcome email (non-blocking but log errors)
    ctx.waitUntil(
      sendWelcomeEmail(email, env).then(result => {
        if (!result.success) {
          console.error(`Failed to send welcome email to ${email}: ${result.error}`);
        }
      })
    );

    return jsonResponse({ success: true, message: 'Subscribed successfully' }, 200, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

async function handleUnsubscribe(request: Request, env: Env): Promise<Response> {
  try {
    // Check request size
    const contentLength = request.headers.get('Content-Length');
    if (contentLength && parseInt(contentLength) > MAX_REQUEST_SIZE) {
      return jsonResponse({ success: false, error: 'Request too large' }, 413, request, env);
    }

    const body = await request.json() as { email?: string };
    const email = (body.email || '').trim().toLowerCase();

    if (!isValidEmail(email)) {
      return jsonResponse({ success: false, error: 'Invalid email address' }, 400, request, env);
    }

    // Delete subscription
    await env.NEWSLETTER_SUBSCRIBERS.delete(email);
    
    return jsonResponse({ success: true, message: 'Unsubscribed successfully' }, 200, request, env);
  } catch {
    return jsonResponse({ success: false, error: 'Internal server error' }, 500, request, env);
  }
}

async function handleGetNewsletters(request: Request, env: Env): Promise<Response> {
  try {
    // If R2 bucket is available, list objects directly
    if (env.R2_BUCKET) {
      try {
        const newsletters = await listNewslettersFromR2(env.R2_BUCKET);
        if (newsletters.length > 0) {
          return jsonResponse({ newsletters }, 200, request, env);
        }
      } catch {
        // Fall through to fallback
      }
    }

    // Fallback: try fetching from static URL
    try {
      const response = await fetch('https://static.philippdubach.com/newsletter/');
      if (response.ok) {
        const html = await response.text();
        const newsletters = parseNewsletterDirectory(html);
        if (newsletters.length > 0) {
          return jsonResponse({ newsletters }, 200, request, env);
        }
      }
    } catch {
      // Fall through to fallback
    }

    // Final fallback
    const fallbackNewsletters: NewsletterItem[] = [
      {
        filename: 'newsletter-2025-12.html',
        date: 'December 2025',
        title: 'December 2025 Newsletter',
        url: 'https://static.philippdubach.com/newsletter/newsletter-2025-12.html',
      },
    ];
    return jsonResponse({ newsletters: fallbackNewsletters }, 200, request, env);
  } catch {
    // Return fallback on error
    const fallbackNewsletters: NewsletterItem[] = [
      {
        filename: 'newsletter-2025-12.html',
        date: 'December 2025',
        title: 'December 2025 Newsletter',
        url: 'https://static.philippdubach.com/newsletter/newsletter-2025-12.html',
      },
    ];
    return jsonResponse({ newsletters: fallbackNewsletters }, 200, request, env);
  }
}

async function listNewslettersFromR2(bucket: R2Bucket): Promise<NewsletterItem[]> {
  const newsletters: NewsletterItem[] = [];
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December'
  ];
  
  // List objects with newsletter/ prefix
  const objects = await bucket.list({
    prefix: 'newsletter/',
  });
  
  // Process all objects
  for (const object of objects.objects) {
    const key = object.key;
    
    // Extract filename from key
    const filename = key.split('/').pop() || key;
    
    // Match newsletter-YYYY-MM.html pattern
    const match = filename.match(/newsletter-(\d{4})-(\d{2})\.html/);
    if (!match) continue;
    
    const year = match[1];
    const month = match[2];
    const monthIndex = parseInt(month, 10) - 1;
    
    if (monthIndex < 0 || monthIndex > 11) continue;
    
    const date = `${monthNames[monthIndex]} ${year}`;
    const title = `${monthNames[monthIndex]} ${year} Newsletter`;
    
    newsletters.push({
      filename,
      date,
      title,
      url: `https://static.philippdubach.com/newsletter/${filename}`,
    });
  }
  
  // Sort by date descending (newest first)
  newsletters.sort((a, b) => {
    const aMatch = a.filename.match(/newsletter-(\d{4})-(\d{2})/);
    const bMatch = b.filename.match(/newsletter-(\d{4})-(\d{2})/);
    if (!aMatch || !bMatch) return 0;
    const aKey = aMatch[1] + aMatch[2];
    const bKey = bMatch[1] + bMatch[2];
    return bKey.localeCompare(aKey);
  });
  
  return newsletters;
}

function parseNewsletterDirectory(html: string): NewsletterItem[] {
  const newsletters: NewsletterItem[] = [];
  
  // Parse HTML directory listing
  // Look for links to newsletter-*.html files
  const linkRegex = /<a[^>]+href=["']([^"']*newsletter-(\d{4})-(\d{2})\.html)["'][^>]*>([^<]*)<\/a>/gi;
  let match;
  
  const seen = new Set<string>();
  
  while ((match = linkRegex.exec(html)) !== null) {
    const filename = match[1];
    const year = match[2];
    const month = match[3];
    const linkText = match[4].trim();
    
    // Skip if we've already seen this file
    if (seen.has(filename)) continue;
    seen.add(filename);
    
    // Format date
    const monthNames = [
      'January', 'February', 'March', 'April', 'May', 'June',
      'July', 'August', 'September', 'October', 'November', 'December'
    ];
    const monthIndex = parseInt(month, 10) - 1;
    const date = `${monthNames[monthIndex]} ${year}`;
    
    // Generate title
    const title = linkText || `${monthNames[monthIndex]} ${year} Newsletter`;
    
    newsletters.push({
      filename,
      date,
      title,
      url: `https://static.philippdubach.com/newsletter/${filename}`,
    });
  }
  
  // Sort by date descending (newest first)
  newsletters.sort((a, b) => {
    // Extract year-month from filename for sorting
    const aMatch = a.filename.match(/newsletter-(\d{4})-(\d{2})/);
    const bMatch = b.filename.match(/newsletter-(\d{4})-(\d{2})/);
    if (!aMatch || !bMatch) return 0;
    const aKey = aMatch[1] + aMatch[2];
    const bKey = bMatch[1] + bMatch[2];
    return bKey.localeCompare(aKey);
  });
  
  return newsletters;
}

async function sendWelcomeEmail(subscriberEmail: string, env: Env): Promise<{ success: boolean; error?: string }> {
  // Only send if API key is configured
  if (!env.RESEND_API_KEY) {
    return { success: false, error: 'RESEND_API_KEY not configured' };
  }

  const emailPayload = {
    from: 'Philipp Dubach <noreply@notifications.philippdubach.com>',
    to: [subscriberEmail],
    replyTo: 'info@philippdubach.com',
    bcc: ['info@philippdubach.com'],
    subject: 'Welcome to the Newsletter',
    html: `
      <p>Thanks for subscribing!</p>
      <p>You'll receive the next newsletter in your inbox. In the meantime, you can <a href="https://philippdubach.com/newsletter-archive/">browse the archive</a>.</p>
      <p style="color: #666; font-size: 0.9em; margin-top: 2em;">To unsubscribe, simply reply to this email.</p>
    `,
    text: `Thanks for subscribing!\n\nYou'll receive the next newsletter in your inbox. In the meantime, you can browse the archive: https://philippdubach.com/newsletter-archive/\n\nTo unsubscribe, simply reply to this email.`,
  };
  
  // Add timeout to fetch
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);
  
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(emailPayload),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    const responseText = await response.text();
    
    if (!response.ok) {
      return { success: false, error: `Resend API error ${response.status}: ${responseText}` };
    }
    
    return { success: true };
  } catch (error) {
    clearTimeout(timeoutId);
    const errorMessage = error instanceof Error ? error.message : String(error);
    return { success: false, error: `Fetch error: ${errorMessage}` };
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleOptions(request, env);
    }

    // Route handling
    if (path === '/api/subscribe' && request.method === 'POST') {
      return handleSubscribe(request, env, ctx);
    }

    if (path === '/api/unsubscribe' && request.method === 'POST') {
      return handleUnsubscribe(request, env);
    }

    if (path === '/api/newsletters' && request.method === 'GET') {
      return handleGetNewsletters(request, env);
    }

    // Protected test endpoint - only in development or with auth
    if (path === '/api/test-email' && request.method === 'POST') {
      // Block in production unless authenticated
      if (env.ENVIRONMENT === 'production' && !requireAuth(request, env)) {
        return jsonResponse({ error: 'Unauthorized' }, 401, request, env);
      }
      
      try {
        const body = await request.json() as { email?: string };
        const testEmail = body.email || 'test@example.com';
        
        if (!isValidEmail(testEmail)) {
          return jsonResponse({ success: false, error: 'Invalid email' }, 400, request, env);
        }
        
        const result = await sendWelcomeEmail(testEmail, env);
        if (result.success) {
          return jsonResponse({ success: true, message: 'Test email sent' }, 200, request, env);
        } else {
          return jsonResponse({ success: false, error: result.error }, 500, request, env);
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return jsonResponse({ success: false, error: `Exception: ${errorMessage}` }, 500, request, env);
      }
    }

    // Subscriber count endpoint
    if (path === '/api/subscriber-count' && request.method === 'GET') {
      try {
        // List all keys (excluding rate_limit keys)
        let count = 0;
        let cursor: string | undefined;
        
        do {
          const result = await env.NEWSLETTER_SUBSCRIBERS.list({ cursor, limit: 1000 });
          // Count only subscriber keys (not rate_limit keys)
          count += result.keys.filter(key => !key.name.startsWith('rate_limit:')).length;
          cursor = result.list_complete ? undefined : result.cursor;
        } while (cursor);
        
        // Add 100 baseline and round up to nearest 10
        const displayCount = Math.ceil((count) / 10) * 10;
        
        return jsonResponse({ 
          count,
          display: `${displayCount}+`
        }, 200, request, env);
      } catch {
        return jsonResponse({ count: 0, display: '100+' }, 200, request, env);
      }
    }

    // Health check endpoint
    if (path === '/api/health' && request.method === 'GET') {
      return jsonResponse({ status: 'ok', timestamp: new Date().toISOString() }, 200, request, env);
    }

    // 404 for unknown routes
    return jsonResponse({ error: 'Not found' }, 404, request, env);
  },
};

