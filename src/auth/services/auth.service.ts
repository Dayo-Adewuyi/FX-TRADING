import {
    BadRequestException,
    ForbiddenException,
    Injectable,
    NotFoundException,
    UnauthorizedException,
    Logger,
    InternalServerErrorException,
  } from '@nestjs/common';
  import { JwtService } from '@nestjs/jwt';
  import { InjectRepository } from '@nestjs/typeorm';
  import { Repository, DataSource } from 'typeorm';
  import { ConfigService } from '@nestjs/config';
  import * as bcrypt from 'bcrypt';
  import { v4 as uuidv4 } from 'uuid';
  import { Redis } from 'ioredis';
  import { InjectRedis } from '@nestjs-modules/ioredis';   
  import { User, UserStatus, UserRole } from '../../users/entities/user.entity';
  import { RegisterDto } from '../dtos/register.dto';
  import { LoginDto } from '../dtos/login.dto';
  import { EmailVerificationService } from './email-verification.service';
  import { TokenService } from './token.service';
  import { TokenBlacklist } from '../entities/token-blacklist.entity';
  import { SecurityLog, SecurityEventType } from '../entities/security-log.entity';
  import { AuthResponseDto, UserProfileDto } from '../dtos/auth-response.dto';
  
  interface TokenPayload {
    sub: string;
    email: string;
    role: string;
    iat?: number;
    exp?: number; 
    jti?: string; 
  }
  
  @Injectable()
  export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly SALT_ROUNDS = 12;
    private readonly ACCESS_TOKEN_EXPIRATION = '15m';
    private readonly REFRESH_TOKEN_EXPIRATION = '7d';
    private readonly LOGIN_ATTEMPTS_KEY = 'login:attempts:';
    private readonly LOGIN_ATTEMPTS_LIMIT = 5;
    private readonly LOGIN_ATTEMPTS_WINDOW = 60 * 15; 
    private readonly PASSWORD_RESET_EXPIRATION = 60 * 60; 
  
    constructor(
      @InjectRepository(User)
      private readonly userRepository: Repository<User>,
      @InjectRepository(TokenBlacklist)
      private readonly tokenBlacklistRepository: Repository<TokenBlacklist>,
      @InjectRepository(SecurityLog)
      private readonly securityLogRepository: Repository<SecurityLog>,
      private readonly jwtService: JwtService,
      private readonly configService: ConfigService,
      private readonly emailVerificationService: EmailVerificationService,
      private readonly tokenService: TokenService,
      private readonly dataSource: DataSource,
      @InjectRedis() private readonly redis: Redis,
    ) {}
  
    /**
     * Register a new user
     * 
     * @param registerDto User registration data
     * @returns Newly created user
     */
    async register(registerDto: RegisterDto): Promise<UserProfileDto> {
      const { email, password, firstName, lastName } = registerDto;
  
      const existingUser = await this.userRepository.findOne({
        where: { email },
      });
  
      if (existingUser) {
        throw new BadRequestException('Email is already in use');
      }
  
      const queryRunner = this.dataSource.createQueryRunner();
      await queryRunner.connect();
      await queryRunner.startTransaction();
  
      try {
        const hashedPassword = await this.hashPassword(password);
  
        const verificationToken = uuidv4();
  
        const user = new User();
        user.email = email.toLowerCase().trim();
        user.password = hashedPassword;
        user.firstName = firstName.trim();
        user.lastName = lastName.trim();
        user.verificationToken = verificationToken;
        user.isEmailVerified = false;
        user.status = UserStatus.PENDING;
        user.role = UserRole.USER;
  
        const savedUser = await queryRunner.manager.save(user);
  
        const securityLog = new SecurityLog();
        securityLog.userId = savedUser.id;
        securityLog.eventType = SecurityEventType.EMAIL_VERIFICATION_SENT;
        await queryRunner.manager.save(securityLog);
  
        await queryRunner.commitTransaction();
  
        await this.emailVerificationService.sendVerificationEmail(savedUser);
  
        return this.mapUserToProfileDto(savedUser);
      } catch (error) {
        await queryRunner.rollbackTransaction();
        this.logger.error(`Failed to register user: ${error.message}`, error.stack);
        
        if (error instanceof BadRequestException) {
          throw error;
        }
        
        throw new InternalServerErrorException('Error during user registration');
      } finally {
        await queryRunner.release();
      }
    }
  
    /**
     * Authenticate a user and generate access and refresh tokens
     * 
     * @param loginDto Login credentials
     * @param ipAddress User's IP address for security logging
     * @param userAgent User's browser/device info for security logging
     * @returns Authentication response with tokens and user info
     */
    async login(
      loginDto: LoginDto, 
      ipAddress?: string, 
      userAgent?: string
    ): Promise<AuthResponseDto> {
      const { email, password } = loginDto;
      const normalizedEmail = email.toLowerCase().trim();
  
      await this.checkLoginAttempts(normalizedEmail, ipAddress);
  
      const user = await this.userRepository.findOne({
        where: { email: normalizedEmail },
      });
  
      if (!user) {
        await this.incrementLoginAttempts(normalizedEmail, ipAddress);
        throw new UnauthorizedException('Invalid credentials');
      }
  
      if (user.status !== UserStatus.ACTIVE) {
        if (user.status === UserStatus.PENDING) {
          throw new ForbiddenException('Please verify your email address to activate your account');
        } else {
          throw new ForbiddenException('Your account is not active. Please contact support.');
        }
      }
  
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        await this.incrementLoginAttempts(normalizedEmail, ipAddress);
        
        await this.logSecurityEvent(
          SecurityEventType.LOGIN_FAILURE,
          user.id,
          ipAddress,
          userAgent,
          { reason: 'Invalid password' }
        );
        
        throw new UnauthorizedException('Invalid credentials');
      }
  
      await this.resetLoginAttempts(normalizedEmail, ipAddress);
  
      const { accessToken, refreshToken, expiresIn } = await this.generateTokens(user);
  
      user.lastLogin = new Date();
      await this.userRepository.save(user);
  
      await this.logSecurityEvent(
        SecurityEventType.LOGIN_SUCCESS,
        user.id,
        ipAddress,
        userAgent
      );
  
      return {
        accessToken,
        refreshToken,
        expiresIn,
        tokenType: 'Bearer',
        user: this.mapUserToProfileDto(user),
      };
    }
  
    /**
     * Refresh an access token using a valid refresh token
     * 
     * @param refreshToken Current refresh token
     * @param ipAddress User's IP address for security logging
     * @returns New access and refresh tokens
     */
    async refreshToken(refreshToken: string, ipAddress?: string): Promise<AuthResponseDto> {
      try {
        const decoded = await this.jwtService.verifyAsync(refreshToken, {
          secret: this.configService.get<string>('JWT_REFRESH_SECRET') || this.configService.get<string>('JWT_SECRET'),
        });
  
        const isBlacklisted = await this.tokenService.isTokenBlacklisted(refreshToken);
        if (isBlacklisted) {
          throw new UnauthorizedException('Invalid refresh token');
        }
  
        const user = await this.userRepository.findOne({
          where: { id: decoded.sub },
        });
  
        if (!user) {
          throw new UnauthorizedException('User not found');
        }
  
        if (user.status !== UserStatus.ACTIVE) {
          throw new ForbiddenException('Account is not active');
        }
  
        await this.tokenService.blacklistToken(refreshToken, user.id);
  
        const tokens = await this.generateTokens(user);
  
        return {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresIn: tokens.expiresIn,
          tokenType: 'Bearer',
          user: this.mapUserToProfileDto(user),
        };
      } catch (error) {
        this.logger.error(`Failed to refresh token: ${error.message}`, error.stack);
        
        if (error instanceof UnauthorizedException || error instanceof ForbiddenException) {
          throw error;
        }
        
        throw new UnauthorizedException('Invalid or expired refresh token');
      }
    }
  
    /**
     * Initiate password reset process
     * 
     * @param email User's email address
     * @returns Success message
     */
    async forgotPassword(email: string): Promise<{ message: string }> {
      const normalizedEmail = email.toLowerCase().trim();
      
      const user = await this.userRepository.findOne({
        where: { email: normalizedEmail },
      });
  
      if (!user) {
        return { message: 'If your email is registered, you will receive a password reset link.' };
      }
  
      const resetToken = uuidv4();
      const hashedResetToken = await bcrypt.hash(resetToken, this.SALT_ROUNDS);
      
      const key = `password:reset:${user.id}`;
      await this.redis.set(key, hashedResetToken, 'EX', this.PASSWORD_RESET_EXPIRATION);
      
      await this.logSecurityEvent(
        SecurityEventType.PASSWORD_RESET_REQUESTED,
        user.id,
        null,
        null,
        { method: 'email' }
      );
  
      await this.emailVerificationService.sendPasswordResetEmail(user, resetToken);
  
      return { message: 'If your email is registered, you will receive a password reset link.' };
    }
  
    /**
     * Complete password reset with token
     * 
     * @param token Password reset token
     * @param newPassword New password
     * @returns Success message
     */
    async resetPassword(token: string, newPassword: string): Promise<{ message: string }> {
      try {
        const decoded = await this.jwtService.verifyAsync(token, {
          secret: this.configService.get<string>('JWT_RESET_SECRET') || this.configService.get<string>('JWT_SECRET'),
        });
  
        const userId = decoded.sub;
        
        const user = await this.userRepository.findOne({
          where: { id: userId },
        });
  
        if (!user) {
          throw new NotFoundException('User not found');
        }
  
        const key = `password:reset:${userId}`;
        const storedToken = await this.redis.get(key);
        
        if (!storedToken) {
          throw new BadRequestException('Password reset token has expired or is invalid');
        }
  
        const hashedPassword = await this.hashPassword(newPassword);
  
        user.password = hashedPassword;
        await this.userRepository.save(user);
  
        await this.redis.del(key);
  
        await this.logSecurityEvent(
          SecurityEventType.PASSWORD_RESET_COMPLETED,
          user.id
        );
  
        await this.tokenService.invalidateAllUserTokens(userId);
  
        return { message: 'Password has been reset successfully. Please log in with your new password.' };
      } catch (error) {
        this.logger.error(`Failed to reset password: ${error.message}`, error.stack);
        
        if (error instanceof NotFoundException || error instanceof BadRequestException) {
          throw error;
        }
        
        throw new BadRequestException('Invalid or expired password reset token');
      }
    }
  
    /**
     * Change user's password (requires current password)
     * 
     * @param userId User ID
     * @param currentPassword Current password for verification
     * @param newPassword New password
     * @returns Success message
     */
    async changePassword(
      userId: string,
      currentPassword: string,
      newPassword: string,
    ): Promise<{ message: string }> {
      const user = await this.userRepository.findOne({
        where: { id: userId },
      });
  
      if (!user) {
        throw new NotFoundException('User not found');
      }
  
      const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
      if (!isPasswordValid) {
        throw new UnauthorizedException('Current password is incorrect');
      }
  
      if (currentPassword === newPassword) {
        throw new BadRequestException('New password must be different from current password');
      }
  
      const hashedPassword = await this.hashPassword(newPassword);
  
      user.password = hashedPassword;
      await this.userRepository.save(user);
  
      await this.logSecurityEvent(
        SecurityEventType.PASSWORD_CHANGED,
        user.id
      );
  
      await this.tokenService.invalidateAllUserTokens(userId);
  
      return { message: 'Password changed successfully' };
    }
  
    /**
     * Get user profile data
     * 
     * @param userId User ID
     * @returns User profile data
     */
    async getUserProfile(userId: string): Promise<UserProfileDto> {
      const user = await this.userRepository.findOne({
        where: { id: userId },
      });
  
      if (!user) {
        throw new NotFoundException('User not found');
      }
  
      return this.mapUserToProfileDto(user);
    }
  
    /**
     * Validate user by JWT payload for auth guards
     * 
     * @param payload JWT token payload
     * @returns User object if valid
     */
    async validateUserByJwt(payload: TokenPayload): Promise<User> {
      const { sub } = payload;
      
      const user = await this.userRepository.findOne({
        where: { id: sub },
      });
  
      if (!user || user.status !== UserStatus.ACTIVE) {
        throw new UnauthorizedException('Invalid token');
      }
  
      return user;
    }
  
    /**
     * Hash a password with bcrypt
     * 
     * @param password Plain text password
     * @returns Hashed password
     */
    private async hashPassword(password: string): Promise<string> {
      return bcrypt.hash(password, this.SALT_ROUNDS);
    }
  
    /**
     * Generate access and refresh tokens for a user
     * 
     * @param user User object
     * @returns Access and refresh tokens with expiration
     */
    private async generateTokens(user: User): Promise<{
      accessToken: string;
      refreshToken: string;
      expiresIn: number;
    }> {
      const payload: TokenPayload = {
        sub: user.id,
        email: user.email,
        role: user.role,
        jti: uuidv4(), 
      };
  
      const expiresInSeconds = parseInt(
        this.ACCESS_TOKEN_EXPIRATION.replace('m', ''),
        10
      ) * 60;
  
      const accessToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.ACCESS_TOKEN_EXPIRATION,
        secret: this.configService.get<string>('JWT_SECRET'),
      });
  
      const refreshToken = await this.jwtService.signAsync(payload, {
        expiresIn: this.REFRESH_TOKEN_EXPIRATION,
        secret: 
          this.configService.get<string>('JWT_REFRESH_SECRET') ||
          this.configService.get<string>('JWT_SECRET'),
      });
  
      user.refreshToken = await bcrypt.hash(refreshToken, 10);
      await this.userRepository.save(user);
  
      return {
        accessToken,
        refreshToken,
        expiresIn: expiresInSeconds,
      };
    }
  
    /**
     * Map User entity to UserProfileDto for safe response
     * 
     * @param user User entity
     * @returns User profile DTO
     */
    private mapUserToProfileDto(user: User): UserProfileDto {
      const profileDto = new UserProfileDto();
      profileDto.id = user.id;
      profileDto.email = user.email;
      profileDto.firstName = user.firstName;
      profileDto.lastName = user.lastName;
      profileDto.isEmailVerified = user.isEmailVerified;
      profileDto.role = user.role;
      profileDto.lastLogin = user.lastLogin;
      profileDto.createdAt = user.createdAt;
      
      return profileDto;
    }
  
    /**
     * Check if too many login attempts have been made
     * 
     * @param email User email
     * @param ipAddress User IP address
     */
    private async checkLoginAttempts(email: string, ipAddress?: string): Promise<void> {
      const emailKey = `${this.LOGIN_ATTEMPTS_KEY}${email}`;
      const emailAttempts = await this.redis.get(emailKey);
      
      if (emailAttempts && parseInt(emailAttempts, 10) >= this.LOGIN_ATTEMPTS_LIMIT) {
        throw new ForbiddenException(
          'Too many login attempts. Please try again later or reset your password.'
        );
      }
  
      if (ipAddress) {
        const ipKey = `${this.LOGIN_ATTEMPTS_KEY}ip:${ipAddress}`;
        const ipAttempts = await this.redis.get(ipKey);
        
        if (ipAttempts && parseInt(ipAttempts, 10) >= this.LOGIN_ATTEMPTS_LIMIT * 3) {
          throw new ForbiddenException(
            'Too many login attempts from this IP address. Please try again later.'
          );
        }
      }
    }
  
    /**
     * Increment login attempts counter
     * 
     * @param email User email
     * @param ipAddress User IP address
     */
    private async incrementLoginAttempts(email: string, ipAddress?: string): Promise<void> {
      const emailKey = `${this.LOGIN_ATTEMPTS_KEY}${email}`;
      await this.redis.incr(emailKey);
      await this.redis.expire(emailKey, this.LOGIN_ATTEMPTS_WINDOW);
  
      if (ipAddress) {
        const ipKey = `${this.LOGIN_ATTEMPTS_KEY}ip:${ipAddress}`;
        await this.redis.incr(ipKey);
        await this.redis.expire(ipKey, this.LOGIN_ATTEMPTS_WINDOW);
      }
    }
  
    /**
     * Reset login attempts counter
     * 
     * @param email User email
     * @param ipAddress User IP address
     */
    private async resetLoginAttempts(email: string, ipAddress?: string): Promise<void> {
      const emailKey = `${this.LOGIN_ATTEMPTS_KEY}${email}`;
      await this.redis.del(emailKey);
  
      if (ipAddress) {
        const ipKey = `${this.LOGIN_ATTEMPTS_KEY}ip:${ipAddress}`;
        await this.redis.del(ipKey);
      }
    }
  
    /**
     * Log security events for audit trail
     * 
     * @param eventType Type of security event
     * @param userId User ID
     * @param ipAddress User IP address
     * @param userAgent User agent string
     * @param metadata Additional event metadata
     */
    private async logSecurityEvent(
      eventType: SecurityEventType,
      userId: string,
      ipAddress?: string,
      userAgent?: string,
      metadata?: Record<string, any>,
    ): Promise<void> {
      try {
        const securityLog = new SecurityLog();
        securityLog.userId = userId;
        securityLog.eventType = eventType;
        securityLog.ipAddress = ipAddress;
        securityLog.userAgent = userAgent;
        securityLog.metadata = metadata;
  
        await this.securityLogRepository.save(securityLog);
      } catch (error) {
        this.logger.error(`Failed to log security event: ${error.message}`, error.stack);
      }
    }
  }