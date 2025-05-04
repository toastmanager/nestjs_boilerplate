import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString } from 'class-validator';

export class UpdateUserDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  username: string;
}
