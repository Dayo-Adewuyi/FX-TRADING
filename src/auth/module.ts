// src/auth/auth.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RedisModule } from '@liaoliaots/nestjs-redis';

import { User } from '../users/entities/user.entity';
import { AuthController } from './controllers/auth.controller';
import { AuthService } from './services/auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtRefreshStrategy } from './strategies/jwt-refresh.strategy';
import { EmailVerificationService } from './services/email-verification.service';
import { UsersModule } from '../users/users.module';
import { TokenService } from './services/token.service';
import { TokenBlacklist } from './entities/token-blacklist.entity';
import { OtpService } from './services/otp.service';
import { OtpEntity } from './entities/otp.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, TokenBlacklist, OtpEntity]),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          expiresIn: configService.get<string>('JWT_EXPIRATION') || '15m',
          issuer: 'fx-trading-app',
        },
      }),
    }),
    RedisModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        config: {
          host: configService.get('REDIS_HOST', 'localhost'),
          port: configService.get('REDIS_PORT', 6379),
          password: configService.get('REDIS_PASSWORD'),
          keyPrefix: 'auth:',
          db: 0,
        },
      }),
    }),
    UsersModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    JwtRefreshStrategy,
    EmailVerificationService,
    TokenService,
    OtpService,
  ],
  exports: [AuthService, TokenService, OtpService, JwtStrategy],
})
export class AuthModule {}