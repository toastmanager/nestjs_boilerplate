import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
} from 'class-validator';
import { STRONG_PASSWORD_OPTIONS } from '../auth.constants';

export class PasswordResetDto {
  @ApiProperty({
    example: 'example@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  @IsStrongPassword(STRONG_PASSWORD_OPTIONS)
  newPassword: string;

  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  token: string;
}
