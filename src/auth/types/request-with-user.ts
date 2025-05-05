import { Request } from 'express';
import { AccessTokenPayload } from './access-token-payload';

export type RequestWithUser = Request & {
  user: AccessTokenPayload;
};
