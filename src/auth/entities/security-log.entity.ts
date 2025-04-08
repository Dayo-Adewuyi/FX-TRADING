import { 
    Column, 
    CreateDateColumn, 
    Entity, 
    Index, 
    PrimaryGeneratedColumn 
  } from 'typeorm';
  
  export enum SecurityEventType {
    LOGIN_SUCCESS = 'login_success',
    LOGIN_FAILURE = 'login_failure',
    LOGOUT = 'logout',
    PASSWORD_CHANGED = 'password_changed',
    PASSWORD_RESET_REQUESTED = 'password_reset_requested',
    PASSWORD_RESET_COMPLETED = 'password_reset_completed',
    EMAIL_VERIFICATION_SENT = 'email_verification_sent',
    EMAIL_VERIFIED = 'email_verified',
    OTP_REQUESTED = 'otp_requested',
    OTP_VERIFIED = 'otp_verified',
    OTP_VERIFICATION_FAILED = 'otp_verification_failed',
    PROFILE_UPDATED = 'profile_updated',
    ACCOUNT_LOCKED = 'account_locked',
    SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  }
  
  @Entity('security_logs')
  export class SecurityLog {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'varchar', length: 36, nullable: true })
    @Index()
    userId: string;
  
    @Column({ type: 'enum', enum: SecurityEventType })
    @Index()
    eventType: SecurityEventType;
  
    @Column({ type: 'varchar', length: 45, nullable: true })
    @Index()
    ipAddress: string;
  
    @Column({ type: 'varchar', length: 255, nullable: true })
    userAgent: string;
  
    @Column({ type: 'jsonb', nullable: true })
    metadata: Record<string, any>;
  
    @CreateDateColumn()
    @Index()
    createdAt: Date;
  }