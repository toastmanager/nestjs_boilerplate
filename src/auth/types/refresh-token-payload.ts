import { IsNotEmpty, IsString } from 'class-validator';
import { RefreshTokenPayloadBase } from './refresh-token-payload-base';

export class RefreshTokenPayload extends RefreshTokenPayloadBase {
  @IsString()
  @IsNotEmpty()
  sub: string;

  @IsString()
  @IsNotEmpty()
  jti: string;
}
