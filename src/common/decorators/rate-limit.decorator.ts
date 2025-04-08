import { SetMetadata } from '@nestjs/common';

export interface RateLimitOptions {
  points: number;     
  duration: number;   
  keyPrefix?: string;
}

export const RATE_LIMIT_KEY = 'rateLimit';


export const RateLimit = (options: RateLimitOptions) => 
  SetMetadata(RATE_LIMIT_KEY, options);


export const THROTTLER_SKIP = 'throttler:skip';
export const SkipThrottle = () => SetMetadata(THROTTLER_SKIP, true);


export const THROTTLER_LIMIT = 'throttler:limit';
export const EnableThrottle = () => SetMetadata(THROTTLER_LIMIT, true);