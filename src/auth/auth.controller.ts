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
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly refreshTokensService: RefreshTokensService,
  ) {}

  @Post('login')
  @ApiNotFoundResponse()
  @ApiOkResponse({
    type: AuthToken,
  })
  login(@Body() loginDto: LoginDto): Promise<AuthToken> {
    return this.authService.login(loginDto);
  }

  @Post('register')
  @ApiOkResponse({
    type: AuthToken,
  })
  register(@Body() registerDto: RegisterDto): Promise<AuthToken> {
    return this.authService.register(registerDto);
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
    res.status(HttpStatus.NO_CONTENT);
  }

  @Post('refresh')
  @ApiOkResponse({
    type: AuthToken,
  })
  @ApiBadRequestResponse()
  @ApiNotFoundResponse()
  refresh(@Body() refreshDto: RefreshDto): Promise<AuthToken> {
    return this.authService.refresh(refreshDto.refresh_token);
  }

  // @Post('password/request-reset')
  // requestPasswordReset() {}

  // @Post('password/reset')
  // resetPassword() {}

  // @Post('email/request-verification')
  // requestEmailVerification() {}

  // @Post('email/verify')
  // verifyEmail() {}
}
