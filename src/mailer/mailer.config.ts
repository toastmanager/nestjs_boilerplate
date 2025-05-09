import { Configuration, Value } from '@itgorillaz/configify';
import { Transform } from 'class-transformer';
import { IsInt, IsNotEmpty, IsOptional, IsString } from 'class-validator';

@Configuration()
export class MailerConfig {
  @IsString()
  @IsNotEmpty()
  @Value('SMTP_HOST')
  host: string;

  @Transform(({ value }) => +value)
  @Value('SMTP_PORT')
  port: number;

  @IsString()
  @IsOptional()
  @Value('SMTP_USER')
  user?: string;

  @IsString()
  @IsOptional()
  @Value('SMTP_PASS')
  pass?: string;
}
