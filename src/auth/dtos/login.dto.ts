import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class LoginDto {
  @ApiProperty()
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsString()
  @IsStrongPassword({
    minLowercase: 0,
    minUppercase: 0,
    minSymbols: 0,
    minNumbers: 0,
  })
  password: string;
}
