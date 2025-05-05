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
import { RefreshTokensService } from 'src/refresh-tokens/refresh-tokens.service';
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
import { CookieOptions, Response } from 'express';
import { AuthConfig } from './auth.config';
import { REFRESH_TOKEN_COOKIE_KEY } from './auth.constants';
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
  @ApiOkResponse({
    type: AuthToken,
  })
  async login(
    @Res({
      passthrough: true,
    })
    res: Response,
    @Body() loginDto: LoginDto,
  ): Promise<AuthToken> {
    const authToken = await this.authService.login(loginDto);
    await this.setRefreshTokenCookie(res, authToken.refresh_token);
    return authToken;
  }

  @Post('register')
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
    const authToken = await this.authService.register(registerDto);
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
    this.authService.logout(logoutDto.refresh_token);
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
    if (refreshDto.mode == 'cookie') {
      const refreshToken = req.cookies[REFRESH_TOKEN_COOKIE_KEY];
      const authToken = await this.authService.refresh(refreshToken);
      await this.setRefreshTokenCookie(res, authToken.refresh_token);
      return authToken;
    } else {
      const authToken = await this.authService.refresh(
        refreshDto.refresh_token,
      );
      await this.setRefreshTokenCookie(res, authToken.refresh_token);
      return authToken;
    }
  }

  // @Post('password/request-reset')
  // requestPasswordReset() {}

  // @Post('password/reset')
  // resetPassword() {}

  // @Post('email/request-verification')
  // requestEmailVerification() {}

  // @Post('email/verify')
  // verifyEmail() {}

  private refreshTokenCookieOptions: CookieOptions = {
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
