/**
 * DMCA Takedown Request API
 * 
 * POST /api/dmca - Submit a DMCA takedown request
 * 
 * Requirements:
 * - Required fields: requester_contact, target_url or target_link_id, claim_details
 * - On valid request targeting a link:
 *   - Set link.status='removed', link.deleted_at=now() (soft delete)
 *   - Log to audit trail
 *   - Create DMCA request record
 * - Rate limited to prevent abuse
 */

import { NextRequest, NextResponse } from 'next/server';
import { prisma } from '@/lib/prisma';
import { z } from 'zod';
import { headers } from 'next/headers';

// Validation schema for DMCA request
const dmcaRequestSchema = z.object({
  requester_contact: z.string().email({ message: 'Valid email address required' }),
  requester_name: z.string().min(1).max(200).optional(),
  requester_company: z.string().max(200).optional(),
  target_url: z.string().url().optional(),
  target_link_id: z.string().uuid().optional(),
  work_title: z.string().min(1, 'Title of copyrighted work is required').max(500),
  claim_details: z.string().min(20, 'Please provide detailed claim information (min 20 characters)').max(5000),
  // DMCA compliance fields
  good_faith_statement: z.boolean().refine(val => val === true, {
    message: 'You must confirm good faith belief',
  }),
  accuracy_statement: z.boolean().refine(val => val === true, {
    message: 'You must confirm the accuracy of your information',
  }),
}).refine(data => data.target_url || data.target_link_id, {
  message: 'Either target_url or target_link_id must be provided',
  path: ['target_url'],
});

// Simple in-memory rate limiter (in production, use Redis)
const rateLimitMap = new Map<string, { count: number; resetAt: number }>();
const RATE_LIMIT_MAX = 5; // 5 requests
const RATE_LIMIT_WINDOW = 3600000; // per hour

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  
  if (!record || now > record.resetAt) {
    rateLimitMap.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
    return true;
  }
  
  if (record.count >= RATE_LIMIT_MAX) {
    return false;
  }
  
  record.count++;
  return true;
}

export async function POST(request: NextRequest) {
  try {
    // Get IP for rate limiting and audit
    const headersList = await headers();
    const ip = headersList.get('x-forwarded-for')?.split(',')[0] || 
               headersList.get('x-real-ip') || 
               'unknown';

    // Rate limit check
    if (!checkRateLimit(ip)) {
      return NextResponse.json(
        { 
          error: 'Too many requests', 
          message: 'Please wait before submitting another DMCA request. Maximum 5 requests per hour.' 
        },
        { status: 429 }
      );
    }

    // Parse and validate request body
    const body = await request.json();
    const validation = dmcaRequestSchema.safeParse(body);
    
    if (!validation.success) {
      return NextResponse.json(
        { 
          error: 'Validation failed', 
          details: validation.error.flatten().fieldErrors 
        },
        { status: 400 }
      );
    }

    const data = validation.data;

    // Find target link if URL provided (not direct ID)
    let targetLinkId: string | null = data.target_link_id || null;
    let targetLink: { id: string; series_id: string; url: string; submitted_by: string | null } | null = null;

    if (data.target_url && !targetLinkId) {
      // Normalize URL for lookup
      const normalizedUrl = data.target_url.toLowerCase().trim()
        .replace(/^https?:\/\//, '')
        .replace(/\/+$/, '');

      targetLink = await prisma.chapterLink.findFirst({
        where: {
          url_normalized: normalizedUrl,
          deleted_at: null,
        },
        select: {
          id: true,
          series_id: true,
          url: true,
          submitted_by: true,
        },
      });

      if (targetLink) {
        targetLinkId = targetLink.id;
      }
    } else if (targetLinkId) {
      targetLink = await prisma.chapterLink.findUnique({
        where: { id: targetLinkId },
        select: {
          id: true,
          series_id: true,
          url: true,
          submitted_by: true,
        },
      });
    }

    // Create DMCA request record
    const dmcaRequest = await prisma.dmcaRequest.create({
      data: {
        requester_contact: data.requester_contact,
        requester_name: data.requester_name,
        requester_company: data.requester_company,
        target_url: data.target_url,
        target_link_id: targetLinkId,
        target_series_id: targetLink?.series_id,
        work_title: data.work_title,
        claim_details: data.claim_details,
        status: 'pending',
      },
    });

    // If we found a matching link, immediately remove it (Safe Harbor compliance)
    if (targetLink) {
      await prisma.$transaction(async (tx) => {
        // Soft delete the link
        await tx.chapterLink.update({
          where: { id: targetLink!.id },
          data: {
            status: 'removed',
            deleted_at: new Date(),
          },
        });

        // Create audit log entry (append-only)
        await tx.linkSubmissionAudit.create({
          data: {
            chapter_link_id: targetLink!.id,
            action: 'dmca_remove',
            actor_ip: ip,
            payload: {
              dmca_request_id: dmcaRequest.id,
              requester_contact: data.requester_contact,
              work_title: data.work_title,
              reason: 'DMCA takedown request',
            },
          },
        });
      });

      // Update DMCA request status to processing
      await prisma.dmcaRequest.update({
        where: { id: dmcaRequest.id },
        data: { status: 'processing' },
      });

      console.log(`[DMCA] Link ${targetLink.id} removed via DMCA request ${dmcaRequest.id}`);
    }

    return NextResponse.json({
      success: true,
      message: targetLink 
        ? 'DMCA request received and link has been removed pending review.'
        : 'DMCA request received. Our team will review and take appropriate action.',
      request_id: dmcaRequest.id,
      link_removed: !!targetLink,
    }, { status: 201 });

  } catch (error) {
    console.error('[DMCA] Error processing request:', error);
    return NextResponse.json(
      { error: 'Internal server error', message: 'Failed to process DMCA request' },
      { status: 500 }
    );
  }
}

// GET endpoint to check status of a DMCA request (for submitters)
export async function GET(request: NextRequest) {
  const { searchParams } = new URL(request.url);
  const requestId = searchParams.get('id');
  const email = searchParams.get('email');

  if (!requestId || !email) {
    return NextResponse.json(
      { error: 'Missing required parameters: id and email' },
      { status: 400 }
    );
  }

  try {
    const dmcaRequest = await prisma.dmcaRequest.findFirst({
      where: {
        id: requestId,
        requester_contact: email,
      },
      select: {
        id: true,
        status: true,
        work_title: true,
        target_url: true,
        created_at: true,
        resolved_at: true,
        resolution_note: true,
      },
    });

    if (!dmcaRequest) {
      return NextResponse.json(
        { error: 'Request not found or email does not match' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      request: dmcaRequest,
    });

  } catch (error) {
    console.error('[DMCA] Error fetching request:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
