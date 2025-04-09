import { ApiProperty } from '@nestjs/swagger';
import {
  IsOptional,
  IsString,
  Length,
  IsEmail,
  IsPhoneNumber,
  IsEnum,
  IsBoolean,
} from 'class-validator';
import { UserStatus, UserRole } from '../entities/user.entity';

export class UpdateUserDto {
  @ApiProperty({ example: 'John', required: false })
  @IsOptional()
  @IsString({ message: 'First name must be a string' })
  @Length(2, 100, { message: 'First name must be between 2 and 100 characters' })
  firstName?: string;

  @ApiProperty({ example: 'Doe', required: false })
  @IsOptional()
  @IsString({ message: 'Last name must be a string' })
  @Length(2, 100, { message: 'Last name must be between 2 and 100 characters' })
  lastName?: string;

  @ApiProperty({ example: 'john.doe@example.com', required: false })
  @IsOptional()
  @IsEmail({}, { message: 'Invalid email format' })
  email?: string;

  @ApiProperty({ example: '+2348012345678', required: false })
  @IsOptional()
  @IsPhoneNumber(null, { message: 'Invalid phone number format' })
  phoneNumber?: string;

  @ApiProperty({ enum: UserStatus, example: UserStatus.ACTIVE, required: false })
  @IsOptional()
  @IsEnum(UserStatus, { message: 'Invalid user status' })
  status?: UserStatus;

  @ApiProperty({ enum: UserRole, example: UserRole.USER, required: false })
  @IsOptional()
  @IsEnum(UserRole, { message: 'Invalid user role' })
  role?: UserRole;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Email verification status must be a boolean' })
  isEmailVerified?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Phone verification status must be a boolean' })
  isPhoneVerified?: boolean;
}

