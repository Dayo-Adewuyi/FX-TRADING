import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerOptions, ThrottlerStorage } from '@nestjs/throttler';
import { Reflector } from '@nestjs/core';
import { RATE_LIMIT_KEY, RateLimitOptions } from '../decorators/rate-limit.decorator';

@Injectable()
export class CustomThrottlerGuard extends ThrottlerGuard {
  constructor(
    private readonly reflector: Reflector,
    private readonly options: ThrottlerOptions,
    private readonly storageService: ThrottlerStorage,
  ) {
    super(options, reflector, storageService);
  }

  getRequestResponse(context: ExecutionContext) {
    const http = context.switchToHttp();
    return {
      req: http.getRequest(),
      res: http.getResponse(),
    };
  }

  protected async handleRequest(
    context: ExecutionContext,
    limit: number,
    ttl: number,
    prefix: string = 'global',
  ): Promise<boolean> {
    const rateLimitOptions = this.reflector.get<RateLimitOptions>(
      RATE_LIMIT_KEY,
      context.getHandler(),
    );

    if (rateLimitOptions) {
      limit = rateLimitOptions.points;
      ttl = rateLimitOptions.duration;
      if (rateLimitOptions.keyPrefix) {
        prefix = rateLimitOptions.keyPrefix;
      }
    }

    const { req, res } = this.getRequestResponse(context);
    
    const ip = 
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
      req.connection.remoteAddress;
      
    const key = `${prefix}:${this.generateKey(context, ip)}`;
    
    const ttls = await this.storageService.getRecord(key);
    const nearLimit = ttls.totalHits > limit * 0.75;
    
    res.header('X-RateLimit-Limit', limit.toString());
    res.header('X-RateLimit-Remaining', Math.max(0, limit - ttls.totalHits).toString());
    res.header('X-RateLimit-Reset', (ttls.expiresIn / 1000).toString());
    
    if (nearLimit) {
      res.header('X-RateLimit-Warning', 'true');
    }
    
    return super.handleRequest(context);
  }
  
  protected generateKey(context: ExecutionContext, suffix: string): string {
    const { req } = this.getRequestResponse(context);
    
    if (req.user && req.user.id) {
      return `${req.user.id}:${suffix}`;
    }
    
    return suffix;
  }
}