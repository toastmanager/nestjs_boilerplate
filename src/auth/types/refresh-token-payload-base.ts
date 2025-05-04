import { IsBoolean, IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { TokenType } from './token-type';

/**
 * The `id` is added to the payload as a `sub` string at the stage of token creation.
 */
export class RefreshTokenPayloadBase {
  @IsBoolean()
  isActive: boolean;

  @IsString()
  @IsNotEmpty()
  username: string;

  @IsEnum(TokenType)
  type: TokenType = TokenType.refresh;
}
