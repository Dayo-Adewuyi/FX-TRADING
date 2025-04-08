import {
    ExceptionFilter,
    Catch,
    ArgumentsHost,
    HttpStatus,
    Logger,
  } from '@nestjs/common';
  import { Request, Response } from 'express';
  import { TypeORMError } from 'typeorm';
  import { QueryFailedError } from 'typeorm/error/QueryFailedError';
  
  @Catch()
  export class AllExceptionsFilter implements ExceptionFilter {
    private readonly logger = new Logger(AllExceptionsFilter.name);
  
    catch(exception: any, host: ArgumentsHost) {
      const ctx = host.switchToHttp();
      const response = ctx.getResponse<Response>();
      const request = ctx.getRequest<Request>();
      
      let status = HttpStatus.INTERNAL_SERVER_ERROR;
      let message = 'Internal server error';
      let code = 'INTERNAL_SERVER_ERROR';
  
      // Database related errors
      if (exception instanceof QueryFailedError) {
        status = HttpStatus.BAD_REQUEST;
        message = 'Database query failed';
        code = 'QUERY_FAILED';
        
        // Duplicate entry error handling (PostgreSQL)
        if (exception.driverError && exception.driverError.code === '23505') {
          message = 'Duplicate entry detected';
          code = 'DUPLICATE_ENTRY';
        }
      } 
      // Other TypeORM errors
      else if (exception instanceof TypeORMError) {
        status = HttpStatus.BAD_REQUEST;
        message = exception.message;
        code = 'DATABASE_ERROR';
      }
      // JSON parse errors
      else if (exception instanceof SyntaxError && exception.message.includes('JSON')) {
        status = HttpStatus.BAD_REQUEST;
        message = 'Invalid JSON in request body';
        code = 'INVALID_JSON';
      }
      // Rate limit errors
      else if (exception.name === 'ThrottlerException') {
        status = HttpStatus.TOO_MANY_REQUESTS;
        message = 'Too many requests, please try again later';
        code = 'RATE_LIMIT_EXCEEDED';
      }
  
      const errorResponse = {
        statusCode: status,
        timestamp: new Date().toISOString(),
        path: request.url,
        method: request.method,
        message,
        code,
        ...(process.env.NODE_ENV === 'development' && { stack: exception.stack }),
      };
  
      // For security, don't expose stack trace in production
      if (process.env.NODE_ENV !== 'development') {
        delete errorResponse.stack;
      }
  
      // Log the error
      this.logger.error(
        `${request.method} ${request.url} ${status}`,
        exception.stack,
      );
      
      // Redact sensitive error details in production
      if (process.env.NODE_ENV !== 'development' && errorResponse.message.toLowerCase().includes('password')) {
        errorResponse.message = 'An error occurred processing your request';
      }
  
      response.status(status).json(errorResponse);
    }
  }
  
 