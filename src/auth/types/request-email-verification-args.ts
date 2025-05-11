import { Prisma } from 'generated/prisma';

export type RequestEmailVerificationArgs = {
  where: Prisma.UserWhereUniqueInput;
  ip?: string;
  userAgent?: string;
  expirationTime?: number;
};
