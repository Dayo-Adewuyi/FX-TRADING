import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    ManyToOne,
    JoinColumn,
    Index,
  } from 'typeorm';
  import { User } from './user.entity';
  
  export enum ActivityType {
    LOGIN = 'login',
    LOGOUT = 'logout',
    PASSWORD_CHANGE = 'password_change',
    PROFILE_UPDATE = 'profile_update',
    KYC_SUBMIT = 'kyc_submit',
    KYC_APPROVED = 'kyc_approved',
    KYC_REJECTED = 'kyc_rejected',
    TWO_FACTOR_ENABLED = 'two_factor_enabled',
    TWO_FACTOR_DISABLED = 'two_factor_disabled',
    ACCOUNT_LOCKED = 'account_locked',
    ACCOUNT_UNLOCKED = 'account_unlocked',
    WALLET_CREATED = 'wallet_created',
    FUNDS_ADDED = 'funds_added',
    CURRENCY_CONVERTED = 'currency_converted',
    ACCOUNT_CREATED = 'account_created',
    ACCOUNT_DELETED = 'account_deleted',
    ACCOUNT_DEACTIVATED = 'account_deactivated',
    PASSWORD_RESET_REQUESTED = 'password_reset_requested',
  }
  
  @Entity('user_activities')
  export class UserActivity {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'uuid' })
    @Index()
    userId: string;
  
    @Column({ type: 'enum', enum: ActivityType })
    @Index()
    activityType: ActivityType;
  
    @Column({ length: 45, nullable: true })
    ipAddress?: string;
  
    @Column({ nullable: true })
    userAgent?: string;
  
    @Column({ type: 'jsonb', nullable: true })
    metadata?: Record<string, any>;
  
    @CreateDateColumn()
    @Index()
    createdAt: Date;
  
    // Relationships
    @ManyToOne(() => User, user => user.activities)
    @JoinColumn({ name: 'userId' })
    user: User;
  }
  
  