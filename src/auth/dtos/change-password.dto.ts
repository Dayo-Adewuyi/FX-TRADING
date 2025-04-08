import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class ChangePasswordDto {
  @ApiProperty({ 
    example: 'OldP@ssw0rd',
    description: 'Current password' 
  })
  @IsNotEmpty({ message: 'Current password is required' })
  @IsString({ message: 'Current password must be a string' })
  currentPassword: string;

  @ApiProperty({
    example: 'NewStrongP@ssw0rd',
    description: 'New password must include uppercase, lowercase, number, and special character',
  })
  @IsNotEmpty({ message: 'New password is required' })
  @Length(8, 100, { message: 'Password must be between 8 and 100 characters' })
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]).{8,}$/,
    {
      message:
        'Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character',
    },
  )
  newPassword: string;
}

