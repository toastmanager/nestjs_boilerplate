import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { AuthConfig } from './auth.config';
import { RefreshTokensModule } from 'src/auth/refresh-tokens/refresh-tokens.module';
import { JwtStrategy } from './strategies/jwt.strategy';
import { PasswordResetModule } from './password-reset/password-reset.module';
import { EmailVerificationModule } from './email-verification/email-verification.module';
import { AuthMailerService } from './auth-mailer.service';
import { MailerModule } from 'src/mailer/mailer.module';

@Module({
  imports: [
    UsersModule,
    RefreshTokensModule,
    JwtModule.registerAsync({
      inject: [AuthConfig],
      useFactory: async (authConfig: AuthConfig) => ({
        secret: authConfig.jwtSecret,
        signOptions: { expiresIn: authConfig.jwtAccessTokenExpiresIn },
      }),
    }),
    MailerModule,
    EmailVerificationModule,
    PasswordResetModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, AuthMailerService, JwtStrategy],
})
export class AuthModule {}
