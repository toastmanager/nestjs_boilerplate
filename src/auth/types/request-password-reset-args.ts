import { Prisma } from 'generated/prisma';

export type RequestPasswordResetArgs = {
  where: Prisma.UserWhereUniqueInput;
  ip?: string;
  userAgent?: string;
  expirationTime?: number;
};
