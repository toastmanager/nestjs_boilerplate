import { Configuration, Value } from '@itgorillaz/configify';
import { IsNotEmpty, IsString } from 'class-validator';

@Configuration()
export class AuthConfig {
  @IsString()
  @IsNotEmpty()
  @Value('JWT_SECRET')
  jwtSecret: string;

  @IsString()
  @IsNotEmpty()
  @Value('JWT_ACCESS_TOKEN_EXPIRES_IN')
  jwtAccessTokenExpiresIn: string;

  @IsString()
  @IsNotEmpty()
  @Value('JWT_REFRESH_TOKEN_EXPIRES_IN')
  jwtRefreshTokenExpiresIn: string;
}
