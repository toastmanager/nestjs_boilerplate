import {
  Body,
  Controller,
  HttpStatus,
  Post,
  Request,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dtos/login.dto';
import { RegisterDto } from './dtos/register.dto';
import { RequestWithUser } from './types/request-with-user';
import { RefreshTokensService } from 'src/auth/refresh-tokens/refresh-tokens.service';
import {
  ApiBadRequestResponse,
  ApiBearerAuth,
  ApiNoContentResponse,
  ApiNotFoundResponse,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthToken } from './dtos/auth-token.dto';
import { LogoutDto } from './dtos/logout.dto';
import { RefreshDto } from './dtos/refresh.dto';
import { CookieOptions, Request as ExpressRequest, Response } from 'express';
import { AuthConfig } from './auth.config';
import { REFRESH_TOKEN_COOKIE_KEY } from './auth.constants';
import { PasswordResetDto } from './dtos/password-reset.dto';
import { VerifyEmailDto } from './dtos/verify-email.dto';
import { RequestPasswordResetDto } from './dtos/request-password-reset.dto';
import * as ms from 'ms';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly authConfig: AuthConfig,
    private readonly refreshTokensService: RefreshTokensService,
  ) {}

  @Post('login')
  @ApiNotFoundResponse()
  @ApiBadRequestResponse()
  @ApiOkResponse({
    type: AuthToken,
  })
  async login(
    @Request() req: ExpressRequest,
    @Res({
      passthrough: true,
    })
    res: Response,
    @Body() loginDto: LoginDto,
  ): Promise<AuthToken> {
    const { ip, headers } = req;
    const authToken = await this.authService.login({
      loginDto,
      ip,
      userAgent: headers['user-agent'],
    });
    await this.setRefreshTokenCookie(res, authToken.refresh_token);
    return authToken;
  }

  @Post('register')
  @ApiBadRequestResponse()
  @ApiOkResponse({
    type: AuthToken,
  })
  async register(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Body() registerDto: RegisterDto,
  ): Promise<AuthToken> {
    const authToken = await this.authService.register({ registerDto });
    await this.setRefreshTokenCookie(res, authToken.refresh_token);
    return authToken;
  }

  @Post('logout')
  @ApiNoContentResponse()
  @ApiBadRequestResponse()
  @ApiUnauthorizedResponse()
  logout(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Body() logoutDto: LogoutDto,
  ): void {
    this.authService.logout({ refreshToken: logoutDto.refresh_token });
    this.clearRefreshTokenCookie(res);
    res.status(HttpStatus.NO_CONTENT);
  }

  /**
   * Invalidates all active refresh tokens for the currently authenticated user.
   */
  @Post('logout-all')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiNoContentResponse()
  @ApiUnauthorizedResponse()
  logoutAll(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Request() req: RequestWithUser,
  ): void {
    const { user: payload } = req;
    this.refreshTokensService.revokeAllUserTokens(+payload.sub);
    this.clearRefreshTokenCookie(res);
    res.status(HttpStatus.NO_CONTENT);
  }

  @Post('refresh')
  @ApiOkResponse({
    type: AuthToken,
  })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  async refresh(
    @Request() req: RequestWithUser,
    @Res({ passthrough: true }) res: Response,
    @Body() refreshDto: RefreshDto,
  ): Promise<AuthToken> {
    if (refreshDto.mode === 'cookie') {
      const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_KEY];
      const authToken = await this.authService.refresh({
        refreshToken,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      await this.setRefreshTokenCookie(res, authToken.refresh_token);
      return authToken;
    } else {
      const authToken = await this.authService.refresh({
        refreshToken: refreshDto.refresh_token,
        ip: req.ip,
        userAgent: req.headers['user-agent'],
      });
      await this.setRefreshTokenCookie(res, authToken.refresh_token);
      return authToken;
    }
  }

  @Post('password/request-reset')
  @ApiBadRequestResponse()
  @ApiNoContentResponse()
  async requestPasswordReset(
    @Request() req: ExpressRequest,
    @Body() requestPasswordResetDto: RequestPasswordResetDto,
    @Res({
      passthrough: true,
    })
    res: Response,
  ) {
    const { ip, headers } = req;
    this.authService.requestPasswordReset({
      where: {
        email: requestPasswordResetDto.email,
      },
      ip: ip,
      userAgent: headers['user-agent'],
    });
    res.status(HttpStatus.NO_CONTENT);
    return;
  }

  @Post('password/reset')
  @ApiBadRequestResponse()
  @ApiNoContentResponse()
  async resetPassword(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Body() passwordResetDto: PasswordResetDto,
  ): Promise<void> {
    await this.authService.resetPassword({
      where: {
        email: passwordResetDto.email,
      },
      newPassword: passwordResetDto.newPassword,
      token: passwordResetDto.token,
    });
    res.status(HttpStatus.NO_CONTENT);
    return;
  }

  @Post('email/request-verification')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiUnauthorizedResponse()
  @ApiNoContentResponse()
  async requestEmailVerification(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Request() req: RequestWithUser,
  ) {
    const { user, ip, headers } = req;
    this.authService.requestEmailVerification({
      where: {
        id: +user.sub,
      },
      ip,
      userAgent: headers['user-agent'],
    });
    res.status(HttpStatus.NO_CONTENT);
    return;
  }

  @Post('email/verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiNoContentResponse()
  @ApiUnauthorizedResponse()
  @ApiBadRequestResponse()
  async verifyEmail(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Request() req: RequestWithUser,
    @Body() verifyEmailDto: VerifyEmailDto,
  ) {
    const { user: payload } = req;
    await this.authService.verifyEmail({
      where: {
        id: +payload.sub,
      },
      token: verifyEmailDto.token,
    });
    res.status(HttpStatus.NO_CONTENT);
    return;
  }

  private readonly refreshTokenCookieOptions: CookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: ms(this.authConfig.jwtRefreshTokenExpiresIn as ms.StringValue),
  };

  private async setRefreshTokenCookie(
    response: Response,
    refreshToken: string,
  ): Promise<void> {
    response.cookie(
      REFRESH_TOKEN_COOKIE_KEY,
      refreshToken,
      this.refreshTokenCookieOptions,
    );
  }

  private clearRefreshTokenCookie(response: Response): void {
    response.clearCookie(
      REFRESH_TOKEN_COOKIE_KEY,
      this.refreshTokenCookieOptions,
    );
  }
}
