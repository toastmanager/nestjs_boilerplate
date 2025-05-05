import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, IsStrongPassword } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'example@example.com',
  })
  @IsEmail()
  email: string;

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
