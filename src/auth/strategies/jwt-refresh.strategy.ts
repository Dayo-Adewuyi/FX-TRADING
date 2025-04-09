import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';

import { AuthService } from '../services/auth.service';
import { TokenService } from '../services/token.service';

@Injectable()
export class JwtRefreshStrategy extends PassportStrategy(Strategy, 'jwt-refresh') {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
    private readonly tokenService: TokenService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromBodyField('refreshToken'),
      ignoreExpiration: false,
      secretOrKey: 
        configService.get<string>('JWT_REFRESH_SECRET') || 
        configService.get<string>('JWT_SECRET'),
      passReqToCallback: true,
    });
  }

  async validate(request: Request, payload: any) {
    const token = request.body.refreshToken;

    const isBlacklisted = await this.tokenService.isTokenBlacklisted(token);
    if (isBlacklisted) {
      throw new UnauthorizedException('Refresh token has been revoked');
    }

    if (payload.iat) {
      const areTokensInvalidated = await this.tokenService.areUserTokensInvalidated(
        payload.sub,
        payload.iat * 1000
      );
      
      if (areTokensInvalidated) {
        throw new UnauthorizedException('Refresh token has been invalidated');
      }
    }

    const user = await this.authService.validateUserByJwt(payload);
    
    request['refreshToken'] = token;
    
    return user;
  }
}