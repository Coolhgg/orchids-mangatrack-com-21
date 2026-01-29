import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';
import { prisma, DEFAULT_TX_OPTIONS } from '@/lib/prisma';
import { logActivity } from '@/lib/gamification/activity';
import { XP_SERIES_COMPLETED, calculateLevel } from '@/lib/gamification/xp';
import { checkAchievements } from '@/lib/gamification/achievements';
import { checkRateLimit, handleApiError, ApiError, validateOrigin, ErrorCodes, getClientIp, validateContentType, validateJsonSize } from '@/lib/api-utils';

export async function PATCH(req: NextRequest) {
  try {
    validateOrigin(req);
    validateContentType(req);
    await validateJsonSize(req);

    const ip = getClientIp(req);
    if (!await checkRateLimit(`library-bulk-update:${ip}`, 10, 60000)) {
      throw new ApiError('Too many requests. Please wait a moment.', 429, ErrorCodes.RATE_LIMITED);
    }

    const supabase = await createClient();
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) {
      throw new ApiError('Unauthorized', 401, ErrorCodes.UNAUTHORIZED);
    }

    const body = await req.json();
    const { updates } = body;

    if (!Array.isArray(updates) || updates.length === 0) {
      throw new ApiError('Updates must be a non-empty array', 400, ErrorCodes.BAD_REQUEST);
    }

    if (updates.length > 50) {
      throw new ApiError('Cannot update more than 50 entries at once', 400, ErrorCodes.BAD_REQUEST);
    }

    const entryIds = updates.map(u => u.id).filter(Boolean);
    const results = await prisma.$transaction(async (tx) => {
      // PERFORMANCE FIX: Fetch all current entries in one query instead of inside the loop
      const currentEntries = await tx.libraryEntry.findMany({
        where: { 
          id: { in: entryIds },
          user_id: user.id 
        },
      });

      const currentEntriesMap = new Map(currentEntries.map(e => [e.id, e]));
      const updatedEntries = [];
      const now = new Date();

      for (const update of updates) {
        const { id, status, rating, preferred_source } = update;
        if (!id) continue;

        const currentEntry = currentEntriesMap.get(id);
        if (!currentEntry) continue;

        const updateData: any = { updated_at: now };
        if (status) {
          const validStatuses = ['reading', 'completed', 'planning', 'dropped', 'paused'];
          if (validStatuses.includes(status)) {
            updateData.status = status;
          }
        }
        if (rating !== undefined && rating !== null) {
          const ratingNum = Number(rating);
          if (!isNaN(ratingNum) && ratingNum >= 1 && ratingNum <= 10) {
            updateData.user_rating = ratingNum;
          }
        }
        if (preferred_source !== undefined) {
          updateData.preferred_source = preferred_source;
        }

        const updatedEntry = await tx.libraryEntry.update({
          where: { id, user_id: user.id },
          data: updateData,
        });

        updatedEntries.push(updatedEntry);

        // Side effects: XP for completion
        if (status === 'completed' && currentEntry.status !== 'completed') {
          const existingActivity = await tx.activity.findFirst({
            where: {
              user_id: user.id,
              series_id: currentEntry.series_id,
              type: 'series_completed',
            },
          });

          if (!existingActivity) {
            const userProfile = await tx.user.findUnique({
              where: { id: user.id },
              select: { xp: true },
            });

            const newXp = (userProfile?.xp || 0) + XP_SERIES_COMPLETED;
            const newLevel = calculateLevel(newXp);

            await tx.user.update({
              where: { id: user.id },
              data: { xp: newXp, level: newLevel },
            });

            await logActivity(tx, user.id, 'series_completed', {
                seriesId: currentEntry.series_id ?? undefined,
              });

              await checkAchievements(tx, user.id, 'series_completed');
            }
          } else if (status && status !== currentEntry.status) {
            await logActivity(tx, user.id, 'status_updated', {
              seriesId: currentEntry.series_id ?? undefined,
              metadata: { old_status: currentEntry.status, new_status: status },
            });
          }
      }

      return updatedEntries;
    }, { ...DEFAULT_TX_OPTIONS, timeout: 20000 });

    return NextResponse.json({
      success: true,
      count: results.length,
      entries: results
    });
  } catch (error: any) {
    return handleApiError(error);
  }
}
