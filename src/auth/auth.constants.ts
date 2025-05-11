import { IsStrongPasswordOptions } from 'class-validator';

export const SALT_ROUNDS = 15;
export const REFRESH_TOKEN_COOKIE_KEY = 'refresh_token';
export const EMAIL_VERIFICATION_TOKEN_EXPIRATION_SECONDS = 60 * 60;
export const PASSWORD_RESET_TOKEN_EXPIRATION_SECONDS = 60 * 10;
export const STRONG_PASSWORD_OPTIONS: IsStrongPasswordOptions = {
  minLowercase: 0,
  minUppercase: 0,
  minSymbols: 0,
  minNumbers: 0,
};
