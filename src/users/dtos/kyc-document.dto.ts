import { ApiProperty } from '@nestjs/swagger';
import {
  IsEnum,
  IsNotEmpty,
  IsString,
  IsOptional,
  IsDateString,
  MaxLength,
} from 'class-validator';
import { DocumentType } from '../entities/kyc-document.entity';

export class CreateKycDocumentDto {
  @ApiProperty({ enum: DocumentType, example: DocumentType.PASSPORT })
  @IsNotEmpty({ message: 'Document type is required' })
  @IsEnum(DocumentType, { message: 'Invalid document type' })
  documentType: DocumentType;

  @ApiProperty({ example: 'A1234567' })
  @IsNotEmpty({ message: 'Document number is required' })
  @IsString({ message: 'Document number must be a string' })
  @MaxLength(255, { message: 'Document number cannot exceed 255 characters' })
  documentNumber: string;

  @ApiProperty({ example: '2030-01-01', required: false })
  @IsOptional()
  @IsDateString({}, { message: 'Expiry date must be a valid ISO date' })
  expiryDate?: string;

  @ApiProperty({ example: 'base64-encoded-document-data' })
  @IsNotEmpty({ message: 'Document data is required' })
  @IsString({ message: 'Document data must be a string' })
  documentData: string; // Base64-encoded document data
}
