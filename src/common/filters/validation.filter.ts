 import { ArgumentsHost, Catch, ExceptionFilter, HttpStatus } from '@nestjs/common';
 import { ValidationError } from 'class-validator';
 import { Response } from 'express';
 
 @Catch(ValidationError)
 export class ValidationFilter implements ExceptionFilter {
   catch(exception: ValidationError[], host: ArgumentsHost) {
     const ctx = host.switchToHttp();
     const response = ctx.getResponse<Response>();
     
     const errorMessages = this.flattenValidationErrors(exception);
     
     response.status(HttpStatus.BAD_REQUEST).json({
       statusCode: HttpStatus.BAD_REQUEST,
       message: 'Validation failed',
       errors: errorMessages,
       timestamp: new Date().toISOString(),
     });
   }
 
   private flattenValidationErrors(errors: ValidationError[]): string[] {
     return errors.reduce<string[]>((acc, error) => {
       if (error.constraints) {
         acc.push(...Object.values(error.constraints));
       }
       if (error.children && error.children.length > 0) {
         acc.push(...this.flattenValidationErrors(error.children));
       }
       return acc;
     }, []);
   }
 }