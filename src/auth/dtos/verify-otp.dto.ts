import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsNumberString, Length } from 'class-validator';
import { OtpAction } from './request-otp.dto';

export class VerifyOtpDto {
  @ApiProperty({ 
    enum: OtpAction,
    description: 'The action requiring OTP verification',
    example: OtpAction.TRADE 
  })
  @IsNotEmpty({ message: 'Action is required' })
  @IsEnum(OtpAction, { message: 'Invalid action' })
  action: OtpAction;

  @ApiProperty({ 
    example: '123456',
    description: 'Six-digit one-time password' 
  })
  @IsNotEmpty({ message: 'OTP is required' })
  @IsNumberString({}, { message: 'OTP must contain only numbers' })
  @Length(6, 6, { message: 'OTP must be exactly 6 digits' })
  otp: string;
}

