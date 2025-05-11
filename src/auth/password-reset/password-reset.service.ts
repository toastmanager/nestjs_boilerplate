import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma } from 'generated/prisma/client';
import { UsersService } from 'src/users/users.service';
import { PASSWORD_RESET_TOKEN_EXPIRATION_SECONDS } from '../auth.constants';
import { AuthMailerService } from '../auth-mailer.service';
import * as crypto from 'crypto';

@Injectable()
export class PasswordResetService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authMailerService: AuthMailerService,
    private readonly usersService: UsersService,
  ) {}

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

  async requestPasswordReset(args: {
    where: Prisma.UserWhereUniqueInput;
    ip?: string;
    userAgent?: string;
    expirationTime?: number;
  }): Promise<void> {
    try {
      const { where } = args;
      const user = await this.usersService.findUnique({
        where,
        select: { email: true },
      });
      const resetToken = await this.generatePasswordResetToken(args);
      await this.authMailerService.sendPasswordResetEmail({
        email: user.email,
        resetToken,
      });
    } catch (_) {
      // Ignore to prevent mail leak
    }
  }

  async generatePasswordResetToken(args: {
    where: Prisma.UserWhereUniqueInput;
    ip?: string;
    userAgent?: string;
    expirationTime?: number;
  }): Promise<string> {
    const { where, ip, userAgent, expirationTime } = args;

    const user = await this.usersService.findUnique({
      where,
    });

    if (!user) {
      throw new NotFoundException('User with this credentials does not exist');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = this.hashPasswordResetToken(token);
    const expiresIn = expirationTime ?? PASSWORD_RESET_TOKEN_EXPIRATION_SECONDS;

    await this.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        ip: ip,
        userAgent,
        tokenHash,
        expiresAt: new Date(Date.now() + expiresIn),
      },
    });

    return token;
  }

  hashPasswordResetToken(token: string) {
    return crypto.createHash('sha256').update(token).digest('hex');
  }
}
