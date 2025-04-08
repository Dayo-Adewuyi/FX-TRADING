import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { classToPlain } from 'class-transformer';

export interface Response<T> {
  data: T;
  meta?: Record<string, any>;
}

@Injectable()
export class TransformInterceptor<T> implements NestInterceptor<T, Response<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<Response<T>> {
    const request = context.switchToHttp().getRequest();
    
    return next.handle().pipe(
      map(data => {
        // Handle paginated responses
        if (data && typeof data === 'object' && 'items' in data && 'meta' in data) {
          const { items, meta } = data;
          return {
            data: this.transformData(items),
            meta,
          };
        }
        
        // Handle array responses
        if (Array.isArray(data)) {
          return {
            data: this.transformData(data),
            meta: {
              count: data.length,
            },
          };
        }
        
        // Handle regular responses
        return {
          data: this.transformData(data),
          meta: {
            requestId: request.requestId,
            timestamp: new Date().toISOString(),
          },
        };
      }),
    );
  }
  
  private transformData(data: any): any {
    // Transform entities to plain objects and exclude @Exclude() properties
    if (data === null || data === undefined) {
      return data;
    }
    
    return classToPlain(data);
  }
}

