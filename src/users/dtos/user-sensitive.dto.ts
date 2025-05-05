import { ApiProperty } from '@nestjs/swagger';
import { UserDto } from './user.dto';
import { IsEmail } from 'class-validator';

export class UserSensitiveDto extends UserDto {
  @ApiProperty()
  @IsEmail()
  email: string;
}
