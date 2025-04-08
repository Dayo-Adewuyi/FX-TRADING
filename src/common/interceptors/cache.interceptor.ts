import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Inject } from '@nestjs/common';
import { Observable, of } from 'rxjs';
import { tap } from 'rxjs/operators';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class HttpCacheInterceptor implements NestInterceptor {
  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
  ) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();
    
    if (request.method !== 'GET') {
      return next.handle();
    }
    
    if (request.user && !request.enableAuthCache) {
      return next.handle();
    }
    
    const cacheKey = this.generateCacheKey(request);
    
    const cachedResponse = await this.cacheManager.get(cacheKey);
    if (cachedResponse) {
      return of(cachedResponse);
    }
    
    return next.handle().pipe(
      tap(response => {
        const ttl = request.cacheTTL || 60; 
        
        if (response) {
          this.cacheManager.set(cacheKey, response, ttl * 1000);
        }
      }),
    );
  }
  
  private generateCacheKey(request: any): string {
    const { originalUrl, query = {}, user } = request;
    
    const sortedQuery = Object.keys(query)
      .sort()
      .reduce((result, key) => {
        result[key] = query[key];
        return result;
      }, {});
    
    const userPart = user ? `:user:${user.id}` : '';
    
    return `http:${originalUrl}:${JSON.stringify(sortedQuery)}${userPart}`;
  }
}

