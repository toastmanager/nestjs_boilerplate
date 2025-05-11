import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { Prisma } from 'generated/prisma';

@Injectable()
export class RefreshTokensService {
  constructor(private readonly prisma: PrismaService) {}

  async create(args: Prisma.RefreshTokenCreateArgs) {
    const refreshToken = await this.prisma.refreshToken.create(args);
    return refreshToken;
  }

  async findMany(args?: Prisma.RefreshTokenFindManyArgs) {
    const refreshTokens = await this.prisma.refreshToken.findMany(args);
    return refreshTokens;
  }

  async findFirst(args?: Prisma.RefreshTokenFindFirstArgs) {
    const refreshToken = await this.prisma.refreshToken.findFirst(args);
    return refreshToken;
  }

  async findUnique(args: Prisma.RefreshTokenFindUniqueArgs) {
    const refreshToken = await this.prisma.refreshToken.findUnique(args);
    return refreshToken;
  }

  async update(args: Prisma.RefreshTokenUpdateArgs) {
    const refreshToken = await this.prisma.refreshToken.update(args);
    return refreshToken;
  }

  async remove(args: Prisma.RefreshTokenDeleteArgs) {
    const refreshToken = await this.prisma.refreshToken.delete(args);
    return refreshToken;
  }

  async revoke(args: Prisma.RefreshTokenFindUniqueArgs) {
    const refreshToken = await this.update({
      ...args,
      data: {
        isRevoked: true,
      },
    });

    return refreshToken;
  }

  /**
   * revokes next tokens of given refresh token
   */
  async revokeNextTokens(jti: string): Promise<void> {
    const token = await this.prisma.refreshToken.findUnique({
      where: {
        jti: jti,
      },
    });
    if (!token) {
      return;
    }
    await this.revoke({
      where: {
        jti: jti,
      },
    });
    if (token.nextJti) {
      await this.revokeNextTokens(token.nextJti);
    }
  }

  async revokeAllUserTokens(userId: number) {
    const revokedTokens = await this.prisma.refreshToken.updateMany({
      where: {
        user: {
          id: userId,
        },
        isRevoked: false,
      },
      data: {
        isRevoked: true,
      },
    });

    return revokedTokens;
  }
}
