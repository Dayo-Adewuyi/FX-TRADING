import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class PaginationMetaDto {
  @ApiProperty()
  totalItems: number;

  @ApiProperty()
  itemCount: number;

  @ApiProperty()
  itemsPerPage: number;

  @ApiProperty()
  totalPages: number;

  @ApiProperty()
  currentPage: number;
}

export class PaginatedResponseDto<T> {
  @ApiProperty({ isArray: true })
  @Type(options => {
    return (options.newObject as PaginatedResponseDto<any>).itemType;
  })
  items: T[];

  @ApiProperty()
  meta: PaginationMetaDto;

  constructor(itemType: new () => T) {
    this.itemType = itemType;
  }

  private itemType: new () => T;
}

