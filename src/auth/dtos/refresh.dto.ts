import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class RefreshDto {
  @ApiPropertyOptional()
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  refresh_token: string;

  @ApiPropertyOptional({
    description: `Specifies where the refresh token should be sourced from.
     - 'cookie' (Default): Read from the HTTP refresh token cookie (typical for web clients).
     - 'body': Read from the 'refreshToken' field in the JSON request body (typical for mobile/non-browser clients).`,
    default: 'cookie',
    example: 'json',
  })
  @IsString()
  @IsOptional()
  mode: string = 'cookie';
}
