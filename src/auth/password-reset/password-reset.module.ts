import { Module } from '@nestjs/common';
import { PasswordResetTokenService } from './password-reset.service';

@Module({
  providers: [PasswordResetTokenService],
  exports: [PasswordResetTokenService],
})
export class PasswordResetModule {}
