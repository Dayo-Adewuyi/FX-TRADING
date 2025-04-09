import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

import { AuthService } from '../services/auth.service';
import { TokenService } from '../services/token.service';

interface TokenPayload {
  sub: string; 
  email: string;
  role: string;
  iat?: number; 
  exp?: number; 
  jti?: string; 
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: TokenPayload) {
    const token = ExtractJwt.fromAuthHeaderAsBearerToken()(request);

    const isBlacklisted = await this.tokenService.isTokenBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Token has been revoked');
    }

    if (payload.iat) {
      const areTokensInvalidated = await this.tokenService.areUserTokensInvalidated(
        payload.sub,
        payload.iat * 1000
      );
      
      if (areTokensInvalidated) {
        throw new UnauthorizedException('Token has been invalidated');
      }
    }

    const user = await this.authService.validateUserByJwt(payload);
    
    request['token'] = token;
    
    return user;
  }
}