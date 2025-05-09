import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { MailerConfig } from './mailer.config';
import * as nodemailer from 'nodemailer';

@Injectable()
export class MailerService implements OnModuleInit {
  private readonly transporter: nodemailer.Transporter;
  private readonly logger = new Logger(MailerService.name);

  constructor(private readonly mailerConfig: MailerConfig) {
    this.transporter = nodemailer.createTransport({
      host: this.mailerConfig.host,
      port: this.mailerConfig.port,
      secure: this.mailerConfig.port === 465,
      auth: {
        user: this.mailerConfig.user,
        pass: this.mailerConfig.pass,
      },
    });
  }

  async onModuleInit() {
    try {
      await this.transporter.verify();
      this.logger.log('SMTP server is ready to take messages');
    } catch (err) {
      this.logger.error('SMTP server verification failed', err);
    }
  }

  async sendMail(
    options: nodemailer.SendMailOptions,
  ): Promise<nodemailer.SentMessageInfo> {
    const info = this.transporter.sendMail({
      ...options,
      from: options.from || this.mailerConfig.from,
    });
    return info;
  }
}
