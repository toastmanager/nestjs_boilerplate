import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './dtos/login.dto';
import { Prisma, User } from 'generated/prisma';
import { AuthToken } from './dtos/auth-token.dto';
import { RegisterDto } from './dtos/register.dto';
import { AccessTokenPayloadBase } from 'src/auth/types/access-token-payload-base';
import {
  EMAIL_VERIFICATION_TOKEN_EXPIRATION_SECONDS,
  PASSWORD_RESET_TOKEN_EXPIRATION_SECONDS,
  SALT_ROUNDS,
} from './auth.constants';
import { RefreshTokenPayloadBase } from './types/refresh-token-payload-base';
import { AuthConfig } from './auth.config';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { RefreshTokensService } from 'src/auth/refresh-tokens/refresh-tokens.service';
import { RefreshTokenPayload } from './types/refresh-token-payload';
import { TokenType } from './types/token-type';
import { EmailVerificationRepo } from './email-verification/email-verification.repository';
import { PasswordResetRepo } from './password-reset/password-reset.repository';
import { AuthMailerService } from './auth-mailer.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly authMailerService: AuthMailerService,
    private readonly emailVerificationRepo: EmailVerificationRepo,
    private readonly passwordResetRepo: PasswordResetRepo,
    private readonly refreshTokensService: RefreshTokensService,
    private readonly authConfig: AuthConfig,
    private readonly jwtService: JwtService,
  ) {}

  createAccessTokenPayload(user: User): AccessTokenPayloadBase {
    return {
      type: TokenType.access,
      username: user.username,
      email: user.email,
      isActive: user.isActive,
      updatedAt: user.updatedAt,
      createdAt: user.createdAt,
    };
  }

  createRefreshTokenPayload(user: User): RefreshTokenPayloadBase {
    return {
      type: TokenType.refresh,
      username: user.username,
      isActive: user.isActive,
    };
  }

  async login(args: {
    loginDto: LoginDto;
    ip?: string;
    userAgent?: string;
  }): Promise<AuthToken> {
    const { loginDto, userAgent, ip } = args;
    const user = await this.usersService.findUnique({
      where: {
        email: loginDto.email.toLowerCase(),
      },
      omit: {
        passwordHash: false,
      },
    });

    if (!user) {
      throw new NotFoundException('User with this credentials is not found');
    }

    if (
      !(await this.comparePasswordToHash(loginDto.password, user.passwordHash))
    ) {
      throw new UnauthorizedException('Incorrect credentials');
    }

    return {
      access_token: await this.createAccessToken({ user }),
      refresh_token: await this.createRefreshToken({ user, ip, userAgent }),
    };
  }

  async register(args: {
    registerDto: RegisterDto;
    ip?: string;
    userAgent?: string;
  }): Promise<AuthToken> {
    const { registerDto, ip, userAgent } = args;

    await this.usersService.checkUserExistence({
      where: {
        email: registerDto.email,
      },
    });

    const passwordHash = await this.hashPassword(registerDto.password);
    const user = await this.usersService.create({
      data: {
        email: registerDto.email.toLowerCase(),
        username: registerDto.username,
        passwordHash: passwordHash,
      },
    });

    return {
      access_token: await this.createAccessToken({ user }),
      refresh_token: await this.createRefreshToken({ user, ip, userAgent }),
    };
  }

  async createRefreshToken(args: {
    user: User;
    ip?: string;
    userAgent?: string;
    previousTokenJti?: string;
  }): Promise<string> {
    const { user, ip, userAgent, previousTokenJti } = args;

    const dbToken = await this.refreshTokensService.create({
      data: {
        user: {
          connect: {
            id: user.id,
          },
        },
        ipAddress: ip,
        userAgent: userAgent,
        ...(!previousTokenJti
          ? {}
          : {
              previous: {
                connect: {
                  jti: previousTokenJti,
                },
              },
            }),
      },
    });
    const payload = this.createRefreshTokenPayload(user);
    const token = await this.jwtService.signAsync(payload, {
      jwtid: dbToken.jti,
      subject: user.id.toString(),
      expiresIn: this.authConfig.jwtRefreshTokenExpiresIn,
    });
    return token;
  }

  async createAccessToken(args: { user: User }): Promise<string> {
    const { user } = args;
    const payload = this.createAccessTokenPayload(user);
    const token = await this.jwtService.signAsync(payload, {
      subject: user.id.toString(),
    });
    return token;
  }

  async refresh(args: {
    refreshToken: string;
    ip?: string;
    userAgent?: string;
  }): Promise<AuthToken> {
    const { refreshToken, ip, userAgent } = args;
    const payload = await this.verifyToken<RefreshTokenPayload>(refreshToken);
    await this.validateAndHandleRefreshTokenPayload(payload);
    await this.refreshTokensService.revoke({
      where: {
        jti: payload.jti,
      },
    });

    const user = await this.usersService.findUnique({
      where: {
        id: +payload.sub,
      },
    });
    if (!user) {
      throw new NotFoundException(`User with id ${+payload.sub} not found`);
    }

    return {
      access_token: await this.createAccessToken({ user }),
      refresh_token: await this.createRefreshToken({
        user,
        ip,
        userAgent,
        previousTokenJti: payload.jti,
      }),
    };
  }

  ensureCorrectRefreshTokenType(payload: RefreshTokenPayload): void {
    if (payload.type !== TokenType.refresh) {
      throw new BadRequestException(
        'Invalid token type provided. Expected a refresh token.',
      );
    }
  }

  async requestEmailVerification(args: {
    where: Prisma.UserWhereUniqueInput;
    ip?: string;
    userAgent?: string;
    expirationTime?: number;
  }) {
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
      expirationTime ?? EMAIL_VERIFICATION_TOKEN_EXPIRATION_SECONDS;

    await this.emailVerificationRepo.create({
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

  async verifyEmail(args: {
    where: Prisma.UserWhereUniqueInput;
    token: string;
  }): Promise<void> {
    const { where, token } = args;
    const dbVerificationToken = await this.emailVerificationRepo.findFirst({
      where: {
        token: token,
        user: where,
      },
    });

    const isTokenInvalid =
      !dbVerificationToken ||
      dbVerificationToken.expiresAt < new Date() ||
      dbVerificationToken.isRevoked;

    if (isTokenInvalid) {
      throw new BadRequestException('Invalid or expired token');
    }

    await this.usersService.update({
      where: where,
      data: {
        isVerified: true,
      },
    });

    await this.emailVerificationRepo.update({
      data: {
        isRevoked: true,
      },
      where: {
        id: dbVerificationToken.id,
      },
    });

    return;
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

    await this.passwordResetRepo.create({
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

  async resetPassword(args: {
    where: Prisma.UserWhereUniqueInput;
    token: string;
    newPassword: string;
  }) {
    const { where, token, newPassword } = args;
    const tokenHash = this.hashPasswordResetToken(token);
    const dbVerificationToken = await this.passwordResetRepo.findFirst({
      where: {
        tokenHash: tokenHash,
        user: where,
      },
    });

    const isTokenInvalid =
      !dbVerificationToken ||
      dbVerificationToken.expiresAt < new Date() ||
      dbVerificationToken.isRevoked;

    if (isTokenInvalid) {
      throw new BadRequestException('Invalid or expired token');
    }

    const newPasswordHash = await this.hashPassword(newPassword);
    await this.usersService.update({
      where: where,
      data: {
        passwordHash: newPasswordHash,
      },
    });

    await this.passwordResetRepo.update({
      data: {
        isRevoked: true,
      },
      where: {
        id: dbVerificationToken.id,
      },
    });

    return;
  }

  /**
   * checks if refresh token payload is valid
   * - raises errors if not
   * - revokes next related tokens if token is revoked
   */
  async validateAndHandleRefreshTokenPayload(
    payload: RefreshTokenPayload,
  ): Promise<void> {
    this.ensureCorrectRefreshTokenType(payload);

    const dbToken = await this.refreshTokensService.findUnique({
      where: {
        jti: payload.jti,
      },
    });

    if (!dbToken) {
      throw new NotFoundException(
        'Refresh token with this jti not found in database',
      );
    }

    if (dbToken.isRevoked) {
      await this.refreshTokensService.revokeNextTokens(dbToken.jti);

      throw new UnauthorizedException(
        'The provided Refresh Token was used earlier. All refresh tokens created after it have been revoked',
      );
    }
  }

  async logout(args: { refreshToken: string }): Promise<void> {
    const { refreshToken } = args;
    const payload = await this.verifyToken<RefreshTokenPayload>(refreshToken);
    this.ensureCorrectRefreshTokenType(payload);
    await this.refreshTokensService.revoke({
      where: {
        jti: payload.jti,
      },
    });
  }

  /**
   * returns token payload
   * throws `UnauthorizedException` if payload is invalid
   */
  async verifyToken<T extends object = any>(token: string): Promise<T> {
    try {
      const payload = await this.jwtService.verifyAsync(token);
      return payload;
    } catch (error) {
      throw new UnauthorizedException(error.message);
    }
  }

  async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(SALT_ROUNDS);
    const passwordHash = await bcrypt.hash(password, salt);
    return passwordHash;
  }

  async comparePasswordToHash(
    rawPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    const isEqual = await bcrypt.compare(rawPassword, hashedPassword);
    return isEqual;
  }
}
