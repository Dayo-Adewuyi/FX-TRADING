import {
    Injectable,
    Logger,
    NotFoundException,
    BadRequestException,
    InternalServerErrorException,
  } from '@nestjs/common';
  import { InjectRepository } from '@nestjs/typeorm';
  import { Repository } from 'typeorm';
  import { JwtService } from '@nestjs/jwt';
  import { ConfigService } from '@nestjs/config';
  import { MailerService } from '@nestjs-modules/mailer';
  import { v4 as uuidv4 } from 'uuid';
  
  import { User, UserStatus } from '../../users/entities/user.entity';
  import { SecurityLog, SecurityEventType } from '../entities/security-log.entity';
  
  @Injectable()
  export class EmailVerificationService {
    private readonly logger = new Logger(EmailVerificationService.name);
    private readonly EMAIL_VERIFICATION_EXPIRATION = '7d'; 
  
    constructor(
      @InjectRepository(User)
      private readonly userRepository: Repository<User>,
      @InjectRepository(SecurityLog)
      private readonly securityLogRepository: Repository<SecurityLog>,
      private readonly jwtService: JwtService,
      private readonly configService: ConfigService,
      private readonly mailerService: MailerService,
    ) {}
  
    /**
     * Generate and send verification email to user
     * 
     * @param user User to send verification email to
     * @returns Success status
     */
    async sendVerificationEmail(user: User): Promise<{ success: boolean; message: string }> {
      try {
        const verificationToken = await this.generateVerificationToken(user);
  
        const appUrl = this.configService.get<string>('APP_URL', 'http://localhost:3000');
        const verificationUrl = `${appUrl}/auth/verify-email?token=${verificationToken}`;
  
        await this.mailerService.sendMail({
          to: user.email,
          subject: 'Verify Your Email Address - FX Trading App',
          template: 'email-verification',
          context: {
            firstName: user.firstName,
            verificationUrl,
            supportEmail: this.configService.get<string>('SUPPORT_EMAIL', 'support@fxtrading.com'),
            appName: this.configService.get<string>('APP_NAME', 'FX Trading App'),
            expirationDays: 7,
          },
        });
  
        await this.logSecurityEvent(
          SecurityEventType.EMAIL_VERIFICATION_SENT,
          user.id
        );
  
        return {
          success: true,
          message: 'Verification email sent successfully',
        };
      } catch (error) {
        this.logger.error(`Failed to send verification email: ${error.message}`, error.stack);
        throw new InternalServerErrorException('Failed to send verification email');
      }
    }
  
    /**
     * Send password reset email
     * 
     * @param user User to send password reset email to
     * @param resetToken Password reset token
     * @returns Success status
     */
    async sendPasswordResetEmail(
      user: User,
      resetToken: string
    ): Promise<{ success: boolean; message: string }> {
      try {
        const token = await this.jwtService.signAsync(
          {
            sub: user.id,
            email: user.email,
            type: 'password-reset',
            jti: resetToken,
          },
          {
            expiresIn: '1h',
            secret: this.configService.get<string>('JWT_RESET_SECRET') || this.configService.get<string>('JWT_SECRET'),
          }
        );
  
        const appUrl = this.configService.get<string>('APP_URL', 'http://localhost:3000');
        const resetUrl = `${appUrl}/auth/reset-password?token=${token}`;
  
        await this.mailerService.sendMail({
          to: user.email,
          subject: 'Reset Your Password - FX Trading App',
          template: 'password-reset',
          context: {
            firstName: user.firstName,
            resetUrl,
            supportEmail: this.configService.get<string>('SUPPORT_EMAIL', 'support@fxtrading.com'),
            appName: this.configService.get<string>('APP_NAME', 'FX Trading App'),
            expirationHours: 1,
          },
        });
  
        return {
          success: true,
          message: 'Password reset email sent successfully',
        };
      } catch (error) {
        this.logger.error(`Failed to send password reset email: ${error.message}`, error.stack);
        throw new InternalServerErrorException('Failed to send password reset email');
      }
    }
  
    /**
     * Verify email with token
     * 
     * @param token Email verification token
     * @returns Success message
     */
    async verifyEmail(token: string): Promise<{ message: string }> {
      try {
        const decoded = await this.jwtService.verifyAsync(token, {
          secret: this.configService.get<string>('JWT_VERIFICATION_SECRET') || this.configService.get<string>('JWT_SECRET'),
        });
  
        const userId = decoded.sub;
  
        const user = await this.userRepository.findOne({
          where: { id: userId },
        });
  
        if (!user) {
          throw new NotFoundException('User not found');
        }
  
        if (user.isEmailVerified) {
          return { message: 'Email is already verified' };
        }
  
        user.isEmailVerified = true;
        user.verificationToken = null;
        
        if (user.status === UserStatus.PENDING) {
          user.status = UserStatus.ACTIVE;
        }
        
        await this.userRepository.save(user);
  
        await this.logSecurityEvent(
          SecurityEventType.EMAIL_VERIFIED,
          user.id
        );
  
        return { message: 'Email verified successfully' };
      } catch (error) {
        this.logger.error(`Failed to verify email: ${error.message}`, error.stack);
        
        if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
          throw new BadRequestException('Invalid or expired verification token');
        }
        
        throw new InternalServerErrorException('Failed to verify email');
      }
    }
  
    /**
     * Generate email verification token
     * 
     * @param user User to generate token for
     * @returns JWT verification token
     */
    private async generateVerificationToken(user: User): Promise<string> {
      if (!user.verificationToken) {
        user.verificationToken = uuidv4();
        await this.userRepository.save(user);
      }
  
      return this.jwtService.signAsync(
        {
          sub: user.id,
          email: user.email,
          type: 'email-verification',
          jti: user.verificationToken,
        },
        {
          expiresIn: this.EMAIL_VERIFICATION_EXPIRATION,
          secret: this.configService.get<string>('JWT_VERIFICATION_SECRET') || this.configService.get<string>('JWT_SECRET'),
        }
      );
    }
  
    /**
     * Log security events for audit trail
     * 
     * @param eventType Type of security event
     * @param userId User ID
     * @param metadata Additional event metadata
     */
    private async logSecurityEvent(
      eventType: SecurityEventType,
      userId: string,
      metadata?: Record<string, any>,
    ): Promise<void> {
      try {
        const securityLog = new SecurityLog();
        securityLog.userId = userId;
        securityLog.eventType = eventType;
        securityLog.metadata = metadata;
  
        await this.securityLogRepository.save(securityLog);
      } catch (error) {
        this.logger.error(`Failed to log security event: ${error.message}`, error.stack);
      }
    }
  }