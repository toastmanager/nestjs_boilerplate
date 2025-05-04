import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class AuthToken {
  @ApiProperty()
  @IsString()
  access: string;

  @ApiProperty()
  @IsString()
  refresh: string;
}
