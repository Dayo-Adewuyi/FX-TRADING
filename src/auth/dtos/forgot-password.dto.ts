import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
  @ApiProperty({ 
    example: 'john.doe@example.com',
    description: 'Email address to send password reset link' 
  })
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;
}

