import { Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();
    const { method, originalUrl, ip, body } = request;
    
    // Sanitize request body for logging (remove sensitive fields)
    const sanitizedBody = this.sanitizeBody(body);
    
    // Generate a unique request ID
    const requestId = uuidv4();
    request.requestId = requestId;
    response.setHeader('X-Request-ID', requestId);
    
    // Log start of request
    const userAgent = request.headers['user-agent'] || 'unknown';
    const startTime = Date.now();
    
    this.logger.log(
      `[${requestId}] ${method} ${originalUrl} - Started - IP: ${ip} - User-Agent: ${userAgent}`
    );
    
    // If enabled, log the sanitized body
    if (process.env.LOG_REQUEST_BODY === 'true' && Object.keys(sanitizedBody).length > 0) {
      this.logger.debug(
        `[${requestId}] Request Body: ${JSON.stringify(sanitizedBody)}`
      );
    }

    return next.handle().pipe(
      tap({
        next: (data) => {
          const duration = Date.now() - startTime;
          
          // Log end of request
          this.logger.log(
            `[${requestId}] ${method} ${originalUrl} - ${response.statusCode} - ${duration}ms`
          );
          
          // If enabled, log the response data (sanitized)
          if (process.env.LOG_RESPONSE_BODY === 'true' && data) {
            const sanitizedResponse = this.sanitizeResponse(data);
            this.logger.debug(
              `[${requestId}] Response Body: ${JSON.stringify(sanitizedResponse)}`
            );
          }
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          
          // Log error
          this.logger.error(
            `[${requestId}] ${method} ${originalUrl} - Error: ${error.message} - ${duration}ms`,
            error.stack
          );
        }
      })
    );
  }
  
  private sanitizeBody(body: any): any {
    if (!body) return {};
    
    const sensitiveFields = ['password', 'token', 'secret', 'creditCard', 'cvv', 'pin'];
    const sanitized = { ...body };
    
    for (const field of sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }
    
    return sanitized;
  }
  
  private sanitizeResponse(data: any): any {
    if (!data) return {};
    
    // Don't log large responses
    if (typeof data === 'object' && Object.keys(data).length > 100) {
      return { message: '[LARGE RESPONSE BODY]' };
    }
    
    // Don't log binary data or files
    if (Buffer.isBuffer(data) || typeof data === 'string' && data.length > 1000) {
      return { message: '[BINARY DATA]' };
    }
    
    return data;
  }
}

