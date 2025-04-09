import {
    BadRequestException,
    Injectable,
    Logger,
    NotFoundException,
    UnauthorizedException,
  } from '@nestjs/common';
  import { InjectRepository } from '@nestjs/typeorm';
  import { Repository, LessThan } from 'typeorm';
  import { MailerService } from '@nestjs-modules/mailer';
  import { ConfigService } from '@nestjs/config';
  import { Redis } from 'ioredis';
  import { InjectRedis } from '@nestjs-modules/ioredis';   
  
  import { OtpEntity } from '../entities/otp.entity';
  import { OtpAction } from '../dtos/request-otp.dto';
  import { SecurityLog, SecurityEventType } from '../entities/security-log.entity';
  import { User } from '../../users/entities/user.entity';
  
  @Injectable()
  export class OtpService {
    private readonly logger = new Logger(OtpService.name);
    private readonly OTP_LENGTH = 6;
    private readonly OTP_EXPIRY_MINUTES = 10;
    private readonly MAX_OTP_ATTEMPTS = 3;
    private readonly OTP_RATE_LIMIT_KEY = 'otp:ratelimit:';
    private readonly OTP_RATE_LIMIT_WINDOW = 60 * 15;
    private readonly OTP_RATE_LIMIT_MAX = 5; 
  
    constructor(
      @InjectRepository(OtpEntity)
      private readonly otpRepository: Repository<OtpEntity>,
      @InjectRepository(SecurityLog)
      private readonly securityLogRepository: Repository<SecurityLog>,
      @InjectRepository(User)
      private readonly userRepository: Repository<User>,
      private readonly mailerService: MailerService,
      private readonly configService: ConfigService,
      @InjectRedis() private readonly redis: Redis,
    ) {
      setInterval(() => this.cleanupExpiredOtps(), 60 * 60 * 1000); 
    }
  
    /**
     * Generate and send an OTP for a specific action
     * 
     * @param userId User ID
     * @param action Action requiring OTP verification
     * @param email User's email address
     * @returns Success message
     */
    async generateAndSendOtp(
      userId: string,
      action: OtpAction,
      email: string,
    ): Promise<{ message: string }> {
      await this.checkRateLimit(userId, action);
  
      await this.otpRepository.delete({
        userId,
        action,
        isVerified: false,
      });
  
      const otp = this.generateOtp();
  
      const expiresAt = new Date();
      expiresAt.setMinutes(expiresAt.getMinutes() + this.OTP_EXPIRY_MINUTES);
  
      const otpEntity = new OtpEntity();
      otpEntity.userId = userId;
      otpEntity.action = action;
      otpEntity.otp = otp;
      otpEntity.expiresAt = expiresAt;
      otpEntity.attempts = 0;
      otpEntity.isVerified = false;
  
      await this.otpRepository.save(otpEntity);
  
      await this.sendOtpEmail(email, otp, action);
  
      await this.logSecurityEvent(
        SecurityEventType.OTP_REQUESTED,
        userId,
        null,
        null,
        { action },
      );
  
      await this.incrementRateLimit(userId, action);
  
      return {
        message: `OTP sent to your email. It will expire in ${this.OTP_EXPIRY_MINUTES} minutes.`,
      };
    }
  
    /**
     * Verify an OTP for a specific action
     * 
     * @param userId User ID
     * @param action Action requiring OTP verification
     * @param otpCode OTP code to verify
     * @returns Success status
     */
    async verifyOtp(
      userId: string,
      action: OtpAction,
      otpCode: string,
    ): Promise<{ verified: boolean; message: string }> {
      const otpEntity = await this.otpRepository.findOne({
        where: {
          userId,
          action,
          isVerified: false,
        },
        order: {
          createdAt: 'DESC',
        },
      });
  
      if (!otpEntity) {
        throw new NotFoundException('No active OTP found. Please request a new OTP.');
      }
  
      if (new Date() > otpEntity.expiresAt) {
        await this.otpRepository.update(otpEntity.id, { isVerified: false });
        
        await this.logSecurityEvent(
          SecurityEventType.OTP_VERIFICATION_FAILED,
          userId,
          null,
          null,
          { action, reason: 'expired' },
        );
        
        throw new BadRequestException('OTP has expired. Please request a new OTP.');
      }
  
      if (otpEntity.attempts >= this.MAX_OTP_ATTEMPTS) {
        await this.otpRepository.update(otpEntity.id, { isVerified: false });
        
        await this.logSecurityEvent(
          SecurityEventType.OTP_VERIFICATION_FAILED,
          userId,
          null,
          null,
          { action, reason: 'max_attempts_reached' },
        );
        
        throw new UnauthorizedException('Too many incorrect attempts. Please request a new OTP.');
      }
  
      if (otpEntity.otp !== otpCode) {
        otpEntity.attempts += 1;
        await this.otpRepository.save(otpEntity);
        
        await this.logSecurityEvent(
          SecurityEventType.OTP_VERIFICATION_FAILED,
          userId,
          null,
          null,
          { action, attempts: otpEntity.attempts },
        );
        
        const remainingAttempts = this.MAX_OTP_ATTEMPTS - otpEntity.attempts;
        throw new UnauthorizedException(
          `Invalid OTP. You have ${remainingAttempts} attempt${
            remainingAttempts === 1 ? '' : 's'
          } remaining.`
        );
      }
  
      otpEntity.isVerified = true;
      await this.otpRepository.save(otpEntity);
  
      await this.logSecurityEvent(
        SecurityEventType.OTP_VERIFIED,
        userId,
        null,
        null,
        { action },
      );
  
      return {
        verified: true,
        message: 'OTP verified successfully.',
      };
    }
  
    /**
     * Check if an action has been verified with OTP
     * 
     * @param userId User ID
     * @param action Action to check
     * @returns True if action is verified
     */
    async isActionVerified(userId: string, action: OtpAction): Promise<boolean> {
      const verifiedOtp = await this.otpRepository.findOne({
        where: {
          userId,
          action,
          isVerified: true,
          expiresAt: LessThan(new Date()),
        },
        order: {
          createdAt: 'DESC',
        },
      });
  
      return !!verifiedOtp;
    }
  
    /**
     * Generate a random OTP code
     * 
     * @returns OTP code
     */
    private generateOtp(): string {
      const digits = '0123456789';
      let otp = '';
      
      for (let i = 0; i < this.OTP_LENGTH; i++) {
        otp += digits[Math.floor(Math.random() * 10)];
      }
      
      return otp;
    }
  
    /**
     * Send OTP via email
     * 
     * @param email Recipient email
     * @param otp OTP code
     * @param action Action requiring OTP
     */
    private async sendOtpEmail(
      email: string,
      otp: string,
      action: OtpAction,
    ): Promise<void> {
      try {
        const user = await this.userRepository.findOne({
          where: { email },
        });
  
        const actionLabel = this.getActionLabel(action);
  
        await this.mailerService.sendMail({
          to: email,
          subject: `Your One-Time Password for ${actionLabel} - FX Trading App`,
          template: 'otp',
          context: {
            firstName: user ? user.firstName : 'Valued Customer',
            otp,
            actionLabel,
            expiryMinutes: this.OTP_EXPIRY_MINUTES,
            supportEmail: this.configService.get<string>('SUPPORT_EMAIL', 'support@fxtrading.com'),
            appName: this.configService.get<string>('APP_NAME', 'FX Trading App'),
          },
        });
      } catch (error) {
        this.logger.error(`Failed to send OTP email: ${error.message}`, error.stack);
        throw new Error('Failed to send OTP email');
      }
    }
  
    /**
     * Get user-friendly label for OTP action
     * 
     * @param action OTP action
     * @returns Human-readable action label
     */
    private getActionLabel(action: OtpAction): string {
      const actionLabels = {
        [OtpAction.FUND_WALLET]: 'Wallet Funding',
        [OtpAction.WITHDRAW]: 'Withdrawal',
        [OtpAction.TRADE]: 'Currency Trading',
        [OtpAction.UPDATE_PROFILE]: 'Profile Update',
        [OtpAction.CHANGE_SECURITY_SETTINGS]: 'Security Settings Change',
      };
  
      return actionLabels[action] || 'Account Action';
    }
  
    /**
     * Check rate limiting for OTP requests
     * 
     * @param userId User ID
     * @param action OTP action
     */
    private async checkRateLimit(userId: string, action: OtpAction): Promise<void> {
      const key = `${this.OTP_RATE_LIMIT_KEY}${userId}:${action}`;
      const count = await this.redis.get(key);
      
      if (count && parseInt(count, 10) >= this.OTP_RATE_LIMIT_MAX) {
        throw new BadRequestException(
          `Too many OTP requests. Please wait before requesting another OTP.`
        );
      }
    }
  
    /**
     * Increment the rate limit counter
     * 
     * @param userId User ID
     * @param action OTP action
     */
    private async incrementRateLimit(userId: string, action: OtpAction): Promise<void> {
      const key = `${this.OTP_RATE_LIMIT_KEY}${userId}:${action}`;
      await this.redis.incr(key);
      await this.redis.expire(key, this.OTP_RATE_LIMIT_WINDOW);
    }
  
    /**
     * Clean up expired OTPs from the database
     */
    private async cleanupExpiredOtps(): Promise<void> {
      try {
        await this.otpRepository.delete({
          expiresAt: LessThan(new Date()),
          isVerified: false,
        });
      } catch (error) {
        this.logger.error(`Failed to clean up expired OTPs: ${error.message}`, error.stack);
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