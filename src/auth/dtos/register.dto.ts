
import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  Length,
  Matches,
  MaxLength,
} from 'class-validator';

export class RegisterDto {
  @ApiProperty({ 
    example: 'John',
    description: 'User first name' 
  })
  @IsNotEmpty({ message: 'First name is required' })
  @IsString({ message: 'First name must be a string' })
  @MaxLength(100, { message: 'First name cannot exceed 100 characters' })
  firstName: string;

  @ApiProperty({ 
    example: 'Doe',
    description: 'User last name' 
  })
  @IsNotEmpty({ message: 'Last name is required' })
  @IsString({ message: 'Last name must be a string' })
  @MaxLength(100, { message: 'Last name cannot exceed 100 characters' })
  lastName: string;

  @ApiProperty({ 
    example: 'john.doe@example.com',
    description: 'User email address' 
  })
  @IsNotEmpty({ message: 'Email is required' })
  @IsEmail({}, { message: 'Invalid email format' })
  @MaxLength(255, { message: 'Email cannot exceed 255 characters' })
  email: string;

  @ApiProperty({
    example: 'StrongP@ssw0rd',
    description: 'User password must include uppercase, lowercase, number, and special character',
  })
  @IsNotEmpty({ message: 'Password is required' })
  @Length(8, 100, { message: 'Password must be between 8 and 100 characters' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/,
    {
      message:
        'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character',
    },
  )
  password: string;
}

