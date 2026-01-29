import { NextRequest, NextResponse } from "next/server"
import { createClient } from "@/lib/supabase/server"
import { handleApiError, ApiError, ErrorCodes } from "@/lib/api-utils"
import { getMetricsSummary } from "@/lib/metrics"

export async function GET(request: NextRequest) {
  try {
    const supabase = await createClient()
    const { data: { user } } = await supabase.auth.getUser()
    
      if (!user) {
        throw new ApiError("Unauthorized", 401, ErrorCodes.UNAUTHORIZED)
      }

      // SECURITY FIX: Use app_metadata for role checks as it's more secure than user_metadata
      const isAdmin = user.app_metadata?.role === 'admin'
      
      if (!isAdmin) {
        throw new ApiError("Forbidden: Admin privileges required", 403, ErrorCodes.FORBIDDEN)
      }

      const metrics = await getMetricsSummary()

    return NextResponse.json({
      timestamp: new Date().toISOString(),
      window_ms: 60000,
      metrics,
    })
  } catch (error) {
    return handleApiError(error)
  }
}
