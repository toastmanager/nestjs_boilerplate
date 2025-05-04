import { Configuration, Value } from '@itgorillaz/configify';
import { IsNotEmpty, IsString } from 'class-validator';

@Configuration()
export class StorageConfig {
  @IsString()
  @IsNotEmpty()
  @Value('S3_ACCESS_KEY_ID')
  accessKeyId: string;

  @IsString()
  @IsNotEmpty()
  @Value('S3_SECRET_ACCESS_KEY')
  secretAccessKey: string;

  @IsString()
  @IsNotEmpty()
  @Value('S3_ENDPOINT')
  endpoint: string;

  @IsString()
  @IsNotEmpty()
  @Value('S3_FORCE_PATH_STYLE')
  isForcePathStyle: boolean;

  @IsString()
  @IsNotEmpty()
  @Value('S3_REGION')
  region: string;
}
