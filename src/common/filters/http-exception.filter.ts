import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpException,
    Logger,
  } from '@nestjs/common';
  import { Request, Response } from 'express';
  
  @Catch(HttpException)
  export class HttpExceptionFilter implements ExceptionFilter {
    private readonly logger = new Logger(HttpExceptionFilter.name);
  
    catch(exception: HttpException, host: ArgumentsHost) {
      const ctx = host.switchToHttp();
      const response = ctx.getResponse<Response>();
      const request = ctx.getRequest<Request>();
      const status = exception.getStatus();
      const errorResponse = exception.getResponse();
  
      const error = {
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        method: request.method,
        message: errorResponse['message'] || exception.message || 'Internal server error',
        ...(process.env.NODE_ENV === 'development' && { stack: exception.stack }),
      };
  
      if (process.env.NODE_ENV !== 'development') {
        delete error.stack;
      }
  
      this.logger.error(
        `${request.method} ${request.url} ${status}`,
        error.stack,
      );
  
      response.status(status).json(error);
    }
  }
  
  