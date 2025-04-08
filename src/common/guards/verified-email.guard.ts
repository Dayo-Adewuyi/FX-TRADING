
import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';

@Injectable()
export class VerifiedEmailGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const { user } = context.switchToHttp().getRequest();
    
    if (!user) {
      throw new ForbiddenException('User not authenticated');
    }
    
    if (!user.isEmailVerified) {
      throw new ForbiddenException('Email verification required. Please verify your email address to access this resource.');
    }
    
    return true;
  }
}