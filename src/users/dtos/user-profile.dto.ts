import { ApiProperty } from '@nestjs/swagger';
import {
  IsOptional,
  IsString,
  Length,
  IsDateString,
  IsISO31661Alpha2,
  MaxLength,
} from 'class-validator';

export class UserProfileDto {
  @ApiProperty({ example: '123 Main St', required: false })
  @IsOptional()
  @IsString({ message: 'Address must be a string' })
  @MaxLength(255, { message: 'Address cannot exceed 255 characters' })
  address?: string;

  @ApiProperty({ example: 'New York', required: false })
  @IsOptional()
  @IsString({ message: 'City must be a string' })
  @MaxLength(100, { message: 'City cannot exceed 100 characters' })
  city?: string;

  @ApiProperty({ example: 'NY', required: false })
  @IsOptional()
  @IsString({ message: 'State must be a string' })
  @MaxLength(100, { message: 'State cannot exceed 100 characters' })
  state?: string;

  @ApiProperty({ example: 'US', required: false })
  @IsOptional()
  @IsISO31661Alpha2({ message: 'Country must be a valid ISO 3166-1 alpha-2 code' })
  country?: string;

  @ApiProperty({ example: '10001', required: false })
  @IsOptional()
  @IsString({ message: 'Postal code must be a string' })
  @MaxLength(20, { message: 'Postal code cannot exceed 20 characters' })
  postalCode?: string;

  @ApiProperty({ example: '1990-01-01', required: false })
  @IsOptional()
  @IsDateString({}, { message: 'Date of birth must be a valid ISO date' })
  dateOfBirth?: string;

  @ApiProperty({ example: 'American', required: false })
  @IsOptional()
  @IsString({ message: 'Nationality must be a string' })
  @MaxLength(100, { message: 'Nationality cannot exceed 100 characters' })
  nationality?: string;

  @ApiProperty({ example: 'Software Engineer', required: false })
  @IsOptional()
  @IsString({ message: 'Occupation must be a string' })
  @MaxLength(100, { message: 'Occupation cannot exceed 100 characters' })
  occupation?: string;

  @ApiProperty({ example: 'Acme Inc', required: false })
  @IsOptional()
  @IsString({ message: 'Employer must be a string' })
  @MaxLength(100, { message: 'Employer cannot exceed 100 characters' })
  employer?: string;

  @ApiProperty({ example: 'I am a software engineer...', required: false })
  @IsOptional()
  @IsString({ message: 'Bio must be a string' })
  @MaxLength(1000, { message: 'Bio cannot exceed 1000 characters' })
  bio?: string;
}

