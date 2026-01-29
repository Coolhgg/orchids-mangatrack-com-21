import { cache } from 'react'
import { createClient } from './server'
import { User } from '@supabase/supabase-js'

/**
 * Optimized user fetcher that uses React cache() to deduplicate requests 
 * within the same render cycle (server components).
 * This eliminates the 100-300ms latency from redundant getUser() calls
 * when middleware has already verified the session.
 */
export const getCachedUser = cache(async (): Promise<User | null> => {
  try {
    const supabase = await createClient()
    const { data, error } = await supabase.auth.getUser()
    
    if (error || !data.user) {
      return null
    }
    
    return data.user
  } catch (err) {
    console.error('[AuthCache] Unexpected error fetching user:', err)
    return null
  }
})
