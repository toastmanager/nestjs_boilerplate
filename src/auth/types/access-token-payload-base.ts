import {
  IsBoolean,
  IsDate,
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsString,
} from 'class-validator';
import { TokenType } from './token-type';

/**
 * The `id` is added to the payload as a `sub` string at the stage of token creation.
 */
export class AccessTokenPayloadBase {
  @IsBoolean()
  isActive: boolean;

  @IsString()
  @IsNotEmpty()
  username: string;

  @IsEmail()
  email: string;

  @IsDate()
  createdAt: Date;

  @IsDate()
  updatedAt: Date;

  @IsEnum(TokenType)
  type: TokenType = TokenType.access;
}
