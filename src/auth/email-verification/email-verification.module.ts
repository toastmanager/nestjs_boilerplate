import { Module } from '@nestjs/common';
import { EmailVerificationTokenService } from './email-verification.service';

@Module({
  providers: [EmailVerificationTokenService],
  exports: [EmailVerificationTokenService],
})
export class EmailVerificationModule {}
