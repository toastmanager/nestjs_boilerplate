import { ApiProperty } from '@nestjs/swagger';
import { IsDate, IsInt, IsNotEmpty, IsString } from 'class-validator';

export class UserDto {
  @ApiProperty({
    type: 'integer',
  })
  @IsInt()
  id: number;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty()
  @IsDate()
  createdAt: Date;
}
