import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    UpdateDateColumn,
    OneToOne,
    OneToMany,
    Index,
    Check,
    BeforeInsert,
    BeforeUpdate,
  } from 'typeorm';
  import { Exclude } from 'class-transformer';
  import * as bcrypt from 'bcrypt';
  
  import { UserProfile } from './user-profile.entity';
  import { KycDocument } from './kyc-document.entity';
  import { UserActivity } from './user-activity.entity';
  import { UserSettings } from './user-settings.entity';
  import { Wallet } from '../../wallets/entities/wallet.entity';
  import { Transaction } from '../../wallets/entities/transaction.entity';
  
  export enum UserRole {
    ADMIN = 'admin',
    MANAGER = 'manager',
    USER = 'user',
  }
  
  export enum UserStatus {
    PENDING = 'pending',
    ACTIVE = 'active',
    SUSPENDED = 'suspended',
    LOCKED = 'locked',
    DEACTIVATED = 'deactivated',
  }
  
  export enum KycStatus {
    NOT_SUBMITTED = 'not_submitted',
    PENDING = 'pending',
    APPROVED = 'approved',
    REJECTED = 'rejected',
  }
  
  @Entity('users')
  @Check(`"email" ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$'`)
  export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ length: 100 })
    firstName: string;
  
    @Column({ length: 100 })
    lastName: string;
  
    @Column()
    @Index({ unique: true })
    email: string;
  
    @Column()
    @Exclude({ toPlainOnly: true })
    password: string;
  
    @Column({ nullable: true })
    @Exclude({ toPlainOnly: true })
    verificationToken?: string;
  
    @Column({ type: 'boolean', default: false })
    isEmailVerified: boolean;
  
    @Column({ type: 'enum', enum: UserRole, default: UserRole.USER })
    role: UserRole;
  
    @Column({ type: 'enum', enum: UserStatus, default: UserStatus.PENDING })
    status: UserStatus;
  
    @Column({ type: 'enum', enum: KycStatus, default: KycStatus.NOT_SUBMITTED })
    kycStatus: KycStatus;
  
    @Column({ nullable: true })
    @Exclude({ toPlainOnly: true })
    refreshToken?: string;
  
    @Column({ nullable: true })
    phoneNumber?: string;
  
    @Column({ type: 'boolean', default: false })
    isPhoneVerified: boolean;
  
    @Column({ type: 'boolean', default: false })
    twoFactorEnabled: boolean;
  
    @Column({ nullable: true })
    @Exclude({ toPlainOnly: true })
    twoFactorSecret?: string;
  
    @Column({ type: 'int', default: 0 })
    @Exclude({ toPlainOnly: true })
    loginAttempts: number;
  
    @Column({ nullable: true })
    @Exclude({ toPlainOnly: true })
    lockUntil?: Date;
  
    @Column({ nullable: true })
    lastLogin?: Date;
  
    @Column({ default: 0 })
    @Exclude({ toPlainOnly: true })
    tokenVersion: number;
  
    @Column({ nullable: true })
    passwordChangedAt?: Date;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @UpdateDateColumn()
    updatedAt: Date;
  
    // Relationships
    @OneToOne(() => UserProfile, profile => profile.user)
    profile: UserProfile;
  
    @OneToMany(() => KycDocument, document => document.user)
    kycDocuments: KycDocument[];
  
    @OneToMany(() => UserActivity, activity => activity.user)
    activities: UserActivity[];
  
    @OneToOne(() => UserSettings, settings => settings.user)
    settings: UserSettings;
  
    @OneToMany(() => Wallet, wallet => wallet.user)
    wallets: Wallet[];
  
    @OneToMany(() => Transaction, transaction => transaction.user)
    transactions: Transaction[];
  
    @BeforeInsert()
    @BeforeUpdate()
    async hashPassword() {
      if (this.password && (this.isNewPassword || this.password.length < 60)) {
        const salt = await bcrypt.genSalt(12);
        this.password = await bcrypt.hash(this.password, salt);
      }
    }
  
    async comparePassword(candidatePassword: string): Promise<boolean> {
      return bcrypt.compare(candidatePassword, this.password);
    }
  
    isAccountLocked(): boolean {
      return this.lockUntil && new Date(this.lockUntil) > new Date();
    }
  
    incrementLoginAttempts() {
      if (this.lockUntil && new Date(this.lockUntil) < new Date()) {
        this.loginAttempts = 1;
        this.lockUntil = null;
      } else {
        this.loginAttempts += 1;
      }
      return this.loginAttempts;
    }
  
    resetLoginAttempts() {
      this.loginAttempts = 0;
      this.lockUntil = null;
    }
  
    lockAccount(hours = 1) {
      const lockUntil = new Date();
      lockUntil.setHours(lockUntil.getHours() + hours);
      this.lockUntil = lockUntil;
    }
  
    get isNewPassword(): boolean {
      return this.previousPassword !== this.password;
    }
  
    private previousPassword: string;
  }