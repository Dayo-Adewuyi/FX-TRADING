import { ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';

export class UserProfileDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  firstName: string;

  @ApiProperty()
  lastName: string;

  @ApiProperty()
  email: string;

  @ApiProperty()
  isEmailVerified: boolean;

  @ApiProperty()
  role: string;

  @ApiProperty()
  lastLogin: Date;

  @ApiProperty()
  createdAt: Date;
}

export class AuthResponseDto {
  @ApiProperty({
    description: 'JWT access token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accessToken: string;

  @ApiProperty({
    description: 'Expiration time in seconds',
    example: 900, 
  })
  expiresIn: number;

  @ApiProperty({
    description: 'Token type',
    example: 'Bearer',
  })
  tokenType: string = 'Bearer';

  @ApiProperty({
    type: UserProfileDto,
    description: 'User profile information',
  })
  user: UserProfileDto;

  @Exclude()
  refreshToken?: string;
}