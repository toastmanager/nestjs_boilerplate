import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsNotEmpty,
  IsString,
  IsStrongPassword,
} from 'class-validator';

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
  @IsStrongPassword({
    minLowercase: 0,
    minUppercase: 0,
    minSymbols: 0,
    minNumbers: 0,
  })
  password: string;
}
