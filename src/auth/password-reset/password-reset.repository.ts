import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma } from 'generated/prisma/client';

@Injectable()
export class PasswordResetRepo {
  constructor(private readonly prisma: PrismaService) {}

  async create(args: Prisma.PasswordResetTokenCreateArgs) {
    const passwordResetToken =
      await this.prisma.passwordResetToken.create(args);
    return passwordResetToken;
  }

  async findMany(args?: Prisma.PasswordResetTokenFindManyArgs) {
    const passwordResetTokens =
      await this.prisma.passwordResetToken.findMany(args);
    return passwordResetTokens;
  }

  async findFirst(args?: Prisma.PasswordResetTokenFindFirstArgs) {
    const passwordResetToken =
      await this.prisma.passwordResetToken.findFirst(args);
    return passwordResetToken;
  }

  async findUnique(args: Prisma.PasswordResetTokenFindUniqueArgs) {
    const passwordResetToken =
      await this.prisma.passwordResetToken.findUnique(args);
    return passwordResetToken;
  }

  async update(args: Prisma.PasswordResetTokenUpdateArgs) {
    const passwordResetToken =
      await this.prisma.passwordResetToken.update(args);
    return passwordResetToken;
  }

  async remove(args: Prisma.PasswordResetTokenDeleteArgs) {
    const passwordResetToken =
      await this.prisma.passwordResetToken.delete(args);
    return passwordResetToken;
  }
}
