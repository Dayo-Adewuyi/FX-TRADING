import { Injectable, NestInterceptor, ExecutionContext, CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';

@Injectable()
export class SecurityInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const response = context.switchToHttp().getResponse();
    
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('X-Frame-Options', 'DENY');
    response.setHeader('X-XSS-Protection', '1; mode=block');
    response.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'");
    response.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    response.removeHeader('X-Powered-By');
    response.removeHeader('Server');
    
    return next.handle();
  }
}