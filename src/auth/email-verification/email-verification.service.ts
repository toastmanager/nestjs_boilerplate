import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { EmailVerificationToken, Prisma } from 'generated/prisma/client';
import { AuthMailerService } from '../auth-mailer.service';
import { UsersService } from 'src/users/users.service';
import { EMAIL_VERIFICATION_TOKEN_EXPIRATION_MILLISECONDS } from '../auth.constants';
import * as crypto from 'crypto';
import { RequestEmailVerificationArgs } from '../types/request-email-verification-args';

@Injectable()
export class EmailVerificationTokenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly authMailerService: AuthMailerService,
    private readonly usersService: UsersService,
  ) {}

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

  async requestEmailVerification(args: RequestEmailVerificationArgs) {
    const { where } = args;
    const user = await this.usersService.findUnique({
      where,
      select: { email: true },
    });

    const verificationToken = await this.generateEmailVerificationToken(args);

    await this.authMailerService.sendVerificationEmail({
      email: user.email,
      verificationToken,
    });
  }

  async generateEmailVerificationToken(args: {
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
      throw new NotFoundException('User with this email does not exist');
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expiresIn =
      expirationTime ?? EMAIL_VERIFICATION_TOKEN_EXPIRATION_MILLISECONDS;

    await this.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        ip,
        userAgent,
        token,
        expiresAt: new Date(Date.now() + expiresIn),
      },
    });

    return token;
  }

  isValidToken(args: { token?: EmailVerificationToken }) {
    const { token } = args;
    return token && token.expiresAt >= new Date() && !token.isRevoked;
  }
}
