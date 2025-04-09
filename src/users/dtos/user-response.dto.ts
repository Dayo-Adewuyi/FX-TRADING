import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose, Type } from 'class-transformer';
import { UserRole, UserStatus, KycStatus } from '../entities/user.entity';
import { Theme, Currency } from '../entities/user-settings.entity';

export class UserResponseDto {
  @ApiProperty()
  @Expose()
  id: string;

  @ApiProperty()
  @Expose()
  firstName: string;

  @ApiProperty()
  @Expose()
  lastName: string;

  @ApiProperty()
  @Expose()
  email: string;

  @ApiProperty({ enum: UserRole })
  @Expose()
  role: UserRole;

  @ApiProperty({ enum: UserStatus })
  @Expose()
  status: UserStatus;

  @ApiProperty({ enum: KycStatus })
  @Expose()
  kycStatus: KycStatus;

  @ApiProperty()
  @Expose()
  phoneNumber?: string;

  @ApiProperty()
  @Expose()
  isEmailVerified: boolean;

  @ApiProperty()
  @Expose()
  isPhoneVerified: boolean;

  @ApiProperty()
  @Expose()
  twoFactorEnabled: boolean;

  @ApiProperty()
  @Expose()
  lastLogin?: Date;

  @ApiProperty()
  @Expose()
  createdAt: Date;

  @ApiProperty()
  @Expose()
  updatedAt: Date;

  @ApiProperty({ type: () => UserProfileResponseDto })
  @Expose()
  @Type(() => UserProfileResponseDto)
  profile?: UserProfileResponseDto;

  @ApiProperty({ type: () => UserSettingsResponseDto })
  @Expose()
  @Type(() => UserSettingsResponseDto)
  settings?: UserSettingsResponseDto;

  @Exclude()
  password: string;

  @Exclude()
  verificationToken?: string;

  @Exclude()
  refreshToken?: string;

  @Exclude()
  twoFactorSecret?: string;

  @Exclude()
  loginAttempts: number;

  @Exclude()
  lockUntil?: Date;

  @Exclude()
  tokenVersion: number;
}

export class UserProfileResponseDto {
  @ApiProperty()
  @Expose()
  id: string;

  @ApiProperty()
  @Expose()
  address?: string;

  @ApiProperty()
  @Expose()
  city?: string;

  @ApiProperty()
  @Expose()
  state?: string;

  @ApiProperty()
  @Expose()
  country?: string;

  @ApiProperty()
  @Expose()
  postalCode?: string;

  @ApiProperty()
  @Expose()
  dateOfBirth?: Date;

  @ApiProperty()
  @Expose()
  nationality?: string;

  @ApiProperty()
  @Expose()
  occupation?: string;

  @ApiProperty()
  @Expose()
  employer?: string;

  @ApiProperty()
  @Expose()
  bio?: string;

  @ApiProperty()
  @Expose()
  avatarUrl?: string;

  @ApiProperty()
  @Expose()
  createdAt: Date;

  @ApiProperty()
  @Expose()
  updatedAt: Date;
}

export class UserSettingsResponseDto {
  @ApiProperty()
  @Expose()
  id: string;

  @ApiProperty({ enum: Theme })
  @Expose()
  theme: Theme;

  @ApiProperty({ enum: Currency })
  @Expose()
  preferredCurrency: Currency;

  @ApiProperty()
  @Expose()
  emailNotifications: boolean;

  @ApiProperty()
  @Expose()
  smsNotifications: boolean;

  @ApiProperty()
  @Expose()
  pushNotifications: boolean;

  @ApiProperty()
  @Expose()
  marketingEmails: boolean;

  @ApiProperty()
  @Expose()
  activityAlerts: boolean;

  @ApiProperty()
  @Expose()
  loginAlerts: boolean;

  @ApiProperty()
  @Expose()
  transactionAlerts: boolean;

  @ApiProperty()
  @Expose()
  notificationPreferences: Record<string, boolean>;

  @ApiProperty()
  @Expose()
  createdAt: Date;

  @ApiProperty()
  @Expose()
  updatedAt: Date;
}

