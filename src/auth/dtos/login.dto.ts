import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @ApiProperty({ 
    example: 'john.doe@example.com',
    description: 'User email address' 
  })
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  email: string;

  @ApiProperty({ 
    example: 'StrongP@ssw0rd',
    description: 'User password' 
  })
  @IsNotEmpty({ message: 'Password is required' })
  @IsString({ message: 'Password must be a string' })
  password: string;
}
