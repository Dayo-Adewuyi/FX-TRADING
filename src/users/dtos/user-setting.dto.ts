
import { ApiProperty } from '@nestjs/swagger';
import {
  IsEnum,
  IsOptional,
  IsBoolean,
  IsObject,
} from 'class-validator';
import { Theme, Currency } from '../entities/user-settings.entity';

export class UpdateUserSettingsDto {
  @ApiProperty({ enum: Theme, example: Theme.DARK, required: false })
  @IsOptional()
  @IsEnum(Theme, { message: 'Invalid theme' })
  theme?: Theme;

  @ApiProperty({ enum: Currency, example: Currency.USD, required: false })
  @IsOptional()
  @IsEnum(Currency, { message: 'Invalid preferred currency' })
  preferredCurrency?: Currency;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Email notifications setting must be a boolean' })
  emailNotifications?: boolean;

  @ApiProperty({ example: false, required: false })
  @IsOptional()
  @IsBoolean({ message: 'SMS notifications setting must be a boolean' })
  smsNotifications?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Push notifications setting must be a boolean' })
  pushNotifications?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Marketing emails setting must be a boolean' })
  marketingEmails?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Activity alerts setting must be a boolean' })
  activityAlerts?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Login alerts setting must be a boolean' })
  loginAlerts?: boolean;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean({ message: 'Transaction alerts setting must be a boolean' })
  transactionAlerts?: boolean;

  @ApiProperty({ 
    example: { 'newTrade': true, 'rateAlert': false }, 
    required: false 
  })
  @IsOptional()
  @IsObject({ message: 'Notification preferences must be an object' })
  notificationPreferences?: Record<string, boolean>;
}

