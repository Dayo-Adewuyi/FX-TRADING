
import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    description: 'Refresh token (required if not using cookies)',
    required: false
  })
  @IsOptional()
  @IsString({ message: 'Refresh token must be a string' })
  refreshToken?: string;
}

