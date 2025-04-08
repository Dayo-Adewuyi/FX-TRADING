import { ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {
    super();
  }

  canActivate(context: ExecutionContext) {
    // Check if route is public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) {
      return true;
    }

    // Check for valid JWT
    return super.canActivate(context);
  }

  handleRequest(err: any, user: any, info: any) {
    // You can throw custom exceptions here based on auth info
    if (err || !user) {
      throw err || new UnauthorizedException('Invalid token or session expired');
    }

    // Check if user is active
    if (user.status !== 'active') {
      throw new UnauthorizedException('Account is not active');
    }

    return user;
  }
}

