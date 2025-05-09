import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma } from 'generated/prisma/client';

@Injectable()
export class EmailVerificationRepo {
  constructor(private readonly prisma: PrismaService) {}

  async create(args: Prisma.EmailVerificationTokenCreateArgs) {
    const emailVerificationToken =
      await this.prisma.emailVerificationToken.create(args);
    return emailVerificationToken;
  }

  async findMany(args?: Prisma.EmailVerificationTokenFindManyArgs) {
    const emailVerificationTokens =
      await this.prisma.emailVerificationToken.findMany(args);
    return emailVerificationTokens;
  }

  async findFirst(args?: Prisma.EmailVerificationTokenFindFirstArgs) {
    const emailVerificationToken =
      await this.prisma.emailVerificationToken.findFirst(args);
    return emailVerificationToken;
  }

  async findUnique(args: Prisma.EmailVerificationTokenFindUniqueArgs) {
    const emailVerificationToken =
      await this.prisma.emailVerificationToken.findUnique(args);
    return emailVerificationToken;
  }

  async update(args: Prisma.EmailVerificationTokenUpdateArgs) {
    const emailVerificationToken =
      await this.prisma.emailVerificationToken.update(args);
    return emailVerificationToken;
  }

  async remove(args: Prisma.EmailVerificationTokenDeleteArgs) {
    const emailVerificationToken =
      await this.prisma.emailVerificationToken.delete(args);
    return emailVerificationToken;
  }
}
