import { ApiProperty } from '@nestjs/swagger';
import {
  IsOptional,
  IsEnum,
  IsBoolean,
  IsString,
  Length,
} from 'class-validator';
import { UserRole, UserStatus, KycStatus } from '../entities/user.entity';
import { UpdateUserDto } from './update-user.dto';

export class AdminUpdateUserDto extends UpdateUserDto {
  @ApiProperty({ enum: UserRole, example: UserRole.USER, required: false })
  @IsOptional()
  @IsEnum(UserRole, { message: 'Invalid user role' })
  role?: UserRole;

  @ApiProperty({ enum: UserStatus, example: UserStatus.ACTIVE, required: false })
  @IsOptional()
  @IsEnum(UserStatus, { message: 'Invalid user status' })
  status?: UserStatus;

  @ApiProperty({ enum: KycStatus, example: KycStatus.APPROVED, required: false })
  @IsOptional()
  @IsEnum(KycStatus, { message: 'Invalid KYC status' })
  kycStatus?: KycStatus;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Account lock status must be a boolean' })
  unlockAccount?: boolean;

  @ApiProperty({ example: 'Admin notes about this user', required: false })
  @IsOptional()
  @IsString({ message: 'Admin notes must be a string' })
  @Length(0, 1000, { message: 'Admin notes cannot exceed 1000 characters' })
  adminNotes?: string;
}

