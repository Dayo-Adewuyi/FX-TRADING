import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty } from 'class-validator';

export enum OtpAction {
  FUND_WALLET = 'fund_wallet',
  WITHDRAW = 'withdraw',
  TRADE = 'trade',
  UPDATE_PROFILE = 'update_profile',
  CHANGE_SECURITY_SETTINGS = 'change_security_settings',
}

export class RequestOtpDto {
  @ApiProperty({ 
    enum: OtpAction,
    description: 'The action requiring OTP verification',
    example: OtpAction.TRADE 
  })
  @IsNotEmpty({ message: 'Action is required' })
  @IsEnum(OtpAction, { message: 'Invalid action' })
  action: OtpAction;
}

