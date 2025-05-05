import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty } from 'class-validator';

export class RefreshDto {
  @ApiProperty()
  @IsNotEmpty()
  refresh_token: string;
}
