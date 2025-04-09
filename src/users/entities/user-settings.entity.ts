import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    UpdateDateColumn,
    OneToOne,
    JoinColumn,
  } from 'typeorm';
  import { User } from './user.entity';
  
  export enum NotificationType {
    EMAIL = 'email',
    PUSH = 'push',
    SMS = 'sms',
  }
  
  export enum Theme {
    LIGHT = 'light',
    DARK = 'dark',
    SYSTEM = 'system',
  }
  
  export enum Currency {
    NGN = 'NGN',
    USD = 'USD',
    EUR = 'EUR',
    GBP = 'GBP',
  }
  
  @Entity('user_settings')
  export class UserSettings {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'uuid' })
    userId: string;
  
    @Column({ type: 'enum', enum: Theme, default: Theme.SYSTEM })
    theme: Theme;
  
    @Column({ type: 'enum', enum: Currency, default: Currency.NGN })
    preferredCurrency: Currency;
  
    @Column({ type: 'boolean', default: true })
    emailNotifications: boolean;
  
    @Column({ type: 'boolean', default: false })
    smsNotifications: boolean;
  
    @Column({ type: 'boolean', default: true })
    pushNotifications: boolean;
  
    @Column({ type: 'boolean', default: true })
    marketingEmails: boolean;
  
    @Column({ type: 'boolean', default: true })
    activityAlerts: boolean;
  
    @Column({ type: 'boolean', default: true })
    loginAlerts: boolean;
  
    @Column({ type: 'boolean', default: true })
    transactionAlerts: boolean;
  
    @Column({ type: 'jsonb', default: {} })
    notificationPreferences: Record<string, boolean>;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @UpdateDateColumn()
    updatedAt: Date;
  
    @OneToOne(() => User, user => user.settings)
    @JoinColumn({ name: 'userId' })
    user: User;
  }