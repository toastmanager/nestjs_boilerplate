import { Request } from 'express';
import { AccessTokenPayloadBase } from './access-token-payload-base';

export type RequestWithUser = Request & {
  user: AccessTokenPayloadBase;
};
