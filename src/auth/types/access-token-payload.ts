import { AccessTokenPayloadBase } from './access-token-payload-base';

export class AccessTokenPayload extends AccessTokenPayloadBase {
  sub: string;
  iat: number;
  exp: number;
}
