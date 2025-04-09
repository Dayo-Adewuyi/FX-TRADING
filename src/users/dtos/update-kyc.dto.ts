import { ApiProperty } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
} from 'class-validator';
import { DocumentStatus } from '../entities/kyc-document.entity';

export class UpdateKycStatusDto {
  @ApiProperty({ enum: DocumentStatus })
  @IsNotEmpty({ message: 'Status is required' })
  @IsEnum(DocumentStatus, { message: 'Invalid document status' })
  status: DocumentStatus;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsString({ message: 'Rejection reason must be a string' })
  @MaxLength(500, { message: 'Rejection reason cannot exceed 500 characters' })
  rejectionReason?: string;
}

