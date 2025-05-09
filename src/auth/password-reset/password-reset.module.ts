import { Module } from '@nestjs/common';
import { PasswordResetRepo } from './password-reset.repository';

@Module({
  providers: [PasswordResetRepo],
  exports: [PasswordResetRepo],
})
export class PasswordResetModule {}
