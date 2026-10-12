import { randomInt } from 'node:crypto';
import type { NextApiRequest, NextApiResponse } from 'next';
import { withRoleAuth } from '@/lib/authMiddleware';
import type { AdminIdentityWithRoles } from '@/lib/authMiddleware';
import {
  mgmtFetch,
  assignRole,
  getUserRoles,
  addOrgMember,
  listOrgMembers,
  orgScopedAdmin,
} from '@/lib/auth0Management';
import { oneLine } from '@/lib/logSanitize';
import { logAuditEvent } from '@/lib/auditClient';
import {
  ALLOWED_ADMIN_DOMAINS,
  buildAdminEmailSearchQuery,
  isAllowedAdminEmail,
} from '@/lib/adminAuth';

/** In-memory rate limiter: 5 invites per minute per admin. */
const inviteRateMap = new Map<string, number[]>();
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60_000;

function isRateLimited(adminEmail: string): boolean {
  const now = Date.now();
  const timestamps = (inviteRateMap.get(adminEmail) || []).filter(
    (t) => now - t < RATE_WINDOW_MS,
  );
  inviteRateMap.set(adminEmail, timestamps);
  if (timestamps.length >= RATE_LIMIT) return true;
  timestamps.push(now);
  return false;
}

/**
 * GET  /api/admin/users — list admin-domain users with roles
 * POST /api/admin/users — invite a new user (create + assign role + reset password)
 */
async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  if (req.method === 'GET') {
    return handleList(req, res);
  }
  if (req.method === 'POST') {
    return handleInvite(req, res, admin);
  }
  return res.status(405).json({ error: 'Method not allowed' });
}

async function handleList(
  _req: NextApiRequest,
  res: NextApiResponse,
) {
  try {
    // Org-scoped: only this tenant Organization's members. Otherwise the legacy
    // email-domain search (correct while one Organization owns the Auth0 tenant).
    let users: { user_id: string; email: string; name?: string }[];
    if (orgScopedAdmin()) {
      users = await listOrgMembers();
    } else {
      const searchRes = await mgmtFetch(
        `/users?q=${encodeURIComponent(buildAdminEmailSearchQuery())}&search_engine=v3&per_page=100`,
      );
      if (!searchRes.ok) {
        const body = await searchRes.text();
        console.error('[Users API] Management API list failed:', oneLine(body));
        return res.status(502).json({ success: false, error: 'Failed to list users' });
      }
      users = await searchRes.json();
    }

    // Fetch roles for each user via Auth0 Roles API
    const mapped = await Promise.all(
      users.map(async (u) => {
        const roles = await getUserRoles(u.user_id);
        return {
          user_id: u.user_id,
          email: u.email,
          name: u.name || u.email,
          role: roles.includes('admin') ? 'admin' : 'employee',
        };
      }),
    );

    return res.status(200).json({ success: true, users: mapped });
  } catch (error: unknown) {
    const msg = oneLine(error instanceof Error ? error.message : String(error));
    console.error('[Users API] List error:', msg);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

async function handleInvite(
  req: NextApiRequest,
  res: NextApiResponse,
  admin: AdminIdentityWithRoles,
) {
  const { email, role } = req.body || {};

  if (!email || typeof email !== 'string' || !isAllowedAdminEmail(email)) {
    return res.status(400).json({
      success: false,
      error: ALLOWED_ADMIN_DOMAINS.length
        ? `Email must end with one of: ${ALLOWED_ADMIN_DOMAINS.join(', ')}`
        : 'Admin email domains are not configured for this deployment',
    });
  }
  if (!role || !['admin', 'employee'].includes(role)) {
    return res.status(400).json({ success: false, error: 'Role must be "admin" or "employee"' });
  }

  if (isRateLimited(admin.email)) {
    return res.status(429).json({ success: false, error: 'Rate limit exceeded. Max 5 invites per minute.' });
  }

  try {
    // Create user (no app_metadata — roles managed via Roles API)
    const createRes = await mgmtFetch('/users', {
      method: 'POST',
      body: JSON.stringify({
        email,
        connection: 'Username-Password-Authentication',
        password: generateTempPassword(),
      }),
    });

    if (!createRes.ok) {
      const body = await createRes.json().catch(() => ({}));
      const errMsg = (body as Record<string, string>).message || 'Failed to create user';
      console.error('[Users API] Create user failed:', oneLine(errMsg));
      return res.status(createRes.status === 409 ? 409 : 502).json({ success: false, error: errMsg });
    }

    const newUser = await createRes.json();

    // Organization roles can only be assigned after membership exists.
    // This is a no-op for deployments using tenant-level roles.
    await addOrgMember(newUser.user_id);
    await assignRole(newUser.user_id, role);

    // Generate password-reset ticket and send invite email via SES
    let inviteEmailSent = false;
    let inviteEmailError: string | undefined;
    try {
      const ticketRes = await mgmtFetch('/tickets/password-change', {
        method: 'POST',
        body: JSON.stringify({
          user_id: newUser.user_id,
          mark_email_as_verified: true,
        }),
      });

      if (ticketRes.ok) {
        const ticketData = await ticketRes.json();
        const resetUrl = ticketData.ticket as string;

        const { emailNotificationService } = await import(
          '../../../../src/services/emailNotification'
        );
        const result = await emailNotificationService.sendInviteEmail(
          email,
          role,
          resetUrl,
          admin.email,
        );
        inviteEmailSent = result.sent;
        inviteEmailError = result.error;
      } else {
        const body = await ticketRes.text();
        console.error('[Users API] Password ticket creation failed:', oneLine(body));
        inviteEmailError = `Password reset ticket failed (${ticketRes.status})`;
      }
    } catch (err) {
      const msg = oneLine(err instanceof Error ? err.message : String(err));
      console.error('[Users API] Invite email failed:', msg);
      inviteEmailError = msg;
    }

    logAuditEvent({
      adminUserId: admin.userId,
      adminEmail: admin.email,
      action: 'user_invited',
      endpoint: req.url || '',
      method: 'POST',
      responseStatus: 201,
      details: {
        resourceId: newUser.user_id,
        ipAddress: (req.headers['x-forwarded-for'] as string)?.split(',')[0] || req.socket.remoteAddress,
        userAgent: req.headers['user-agent'],
      },
    });

    return res.status(201).json({
      success: true,
      inviteEmailSent,
      ...(inviteEmailError && { inviteEmailError }),
      user: {
        user_id: newUser.user_id,
        email: newUser.email,
        name: newUser.name || newUser.email,
        role,
      },
    });
  } catch (error: unknown) {
    const msg = oneLine(error instanceof Error ? error.message : String(error));
    console.error('[Users API] Invite error:', msg);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
}

function generateTempPassword(): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%';
  let pw = '';
  for (let i = 0; i < 24; i++) {
    pw += chars[randomInt(chars.length)];
  }
  return pw;
}

export default withRoleAuth('admin', handler);
