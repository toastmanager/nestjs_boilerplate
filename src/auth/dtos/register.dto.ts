import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
} from 'class-validator';
import { STRONG_PASSWORD_OPTIONS } from '../auth.constants';

export class RegisterDto {
  @ApiProperty({
    example: 'example@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'username',
  })
  @IsString()
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    example: 'password123',
  })
  @IsString()
  @IsStrongPassword(STRONG_PASSWORD_OPTIONS)
  password: string;
}
