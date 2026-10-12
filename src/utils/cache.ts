import { logger } from './logger';
interface CacheItem<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

/**
 * Simple in-memory cache with TTL support
 */
export class SimpleCache<T = any> {
  private cache = new Map<string, CacheItem<T>>();
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(private defaultTtl: number = 300000) { // 5 minutes default
    // Clean up expired items every minute
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 60000);
    this.cleanupInterval.unref();
  }

  /**
   * Set a value in the cache
   */
  set(key: string, value: T, ttl: number = this.defaultTtl): void {
    this.cache.set(key, {
      data: value,
      timestamp: Date.now(),
      ttl
    });
  }

  /**
   * Get a value from the cache
   */
  get(key: string): T | null {
    const item = this.cache.get(key);
    
    if (!item) {
      return null;
    }

    // Check if expired
    if (Date.now() - item.timestamp > item.ttl) {
      this.cache.delete(key);
      return null;
    }

    return item.data;
  }

  /**
   * Check if a key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== null;
  }

  /**
   * Delete a key from the cache
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all cache entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   */
  stats(): {
    size: number;
    expired: number;
    hitRate: number;
    totalKeys: string[];
  } {
    let expired = 0;
    const now = Date.now();
    const totalKeys: string[] = [];

    for (const [key, item] of this.cache.entries()) {
      totalKeys.push(key);
      if (now - item.timestamp > item.ttl) {
        expired++;
      }
    }

    return {
      size: this.cache.size,
      expired,
      hitRate: this.cache.size > 0 ? (this.cache.size - expired) / this.cache.size : 0,
      totalKeys
    };
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, item] of this.cache.entries()) {
      if (now - item.timestamp > item.ttl) {
        this.cache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.info(`🧹 [CACHE] Cleaned up ${cleaned} expired cache entries`);
    }
  }

  /**
   * Destroy the cache and cleanup interval
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.cache.clear();
  }
}

/**
 * Cache middleware for Express routes
 */
export function cacheMiddleware(
  cache: SimpleCache,
  keyGenerator: (req: any) => string,
  ttl?: number
) {
  return (req: any, res: any, next: any) => {
    const key = keyGenerator(req);
    const cached = cache.get(key);

    if (cached) {
      logger.info(`⚡ [CACHE] Cache hit for key: ${key}`);
      return res.json(cached);
    }

    // Override res.json to cache the response
    const originalJson = res.json;
    res.json = function(body: any) {
      if (res.statusCode === 200) {
        cache.set(key, body, ttl);
        logger.info(`💾 [CACHE] Cached response for key: ${key}`);
      }
      return originalJson.call(this, body);
    };

    next();
  };
}

/**
 * Global cache instances
 */
export const userCache = new SimpleCache(300000); // 5 minutes
export const balanceCache = new SimpleCache(60000); // 1 minute
export const messageCache = new SimpleCache(180000); // 3 minutes
export const analyticsCache = new SimpleCache(120000); // 2 minutes

/**
 * Cache key generators
 */
export const cacheKeys = {
  userBalance: (userId: string) => `balance:${userId}`,
  userMessages: (userId: string) => `messages:${userId}`,
  globalAnalytics: () => 'analytics:global',
  userAnalytics: (userId: string) => `analytics:user:${userId}`,
  health: () => 'health:status'
};

export default SimpleCache;