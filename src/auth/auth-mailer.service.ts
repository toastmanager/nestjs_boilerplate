import { Injectable } from '@nestjs/common';
import { AppConfig } from 'src/app.config';
import { MailerService } from 'src/mailer/mailer.service';

@Injectable()
export class AuthMailerService {
  constructor(
    private readonly mailerService: MailerService,
    private readonly appConfig: AppConfig,
  ) {}

  async sendPasswordResetEmail(args: {
    email: string;
    resetToken: string;
  }): Promise<void> {
    const { email, resetToken } = args;
    const resetUrl = `${this.appConfig.frontendUrl}/reset-password?token=${resetToken}`;
    await this.mailerService.sendMail({
      to: email,
      subject: 'Reset your password',
      html: `<p>Click <a href="${resetUrl}">here</a> to reset your password.</p>`,
    });
  }

  async sendVerificationEmail(args: {
    email: string;
    verificationToken: string;
  }): Promise<void> {
    const { email, verificationToken } = args;
    const verifyUrl = `${this.appConfig.frontendUrl}/verify-email?token=${verificationToken}`;
    await this.mailerService.sendMail({
      to: email,
      subject: 'Verify your email',
      html: `<p>Click <a href="${verifyUrl}">here</a> to verify your email address.</p>`,
    });
  }
}
