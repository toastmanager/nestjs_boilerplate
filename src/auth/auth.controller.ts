import { Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('login')
  login() {}

  @Post('register')
  register() {}

  @Post('logout')
  logout() {}

  /**
   * Invalidates all active refresh tokens for the currently authenticated user.
   */
  @Post('logout-all')
  logoutAll() {}

  @Post('refresh')
  refresh() {}

  @Post('password/request-reset')
  requestPasswordReset() {}

  @Post('password/reset')
  resetPassword() {}

  @Post('email/request-verification')
  requestEmailVerification() {}

  @Post('email/verify')
  verifyEmail() {}
}
