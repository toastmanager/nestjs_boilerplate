import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe, VersioningType } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

const APP_ROUTE_PREFIX = '';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app
    .enableVersioning({
      type: VersioningType.URI,
    })
    .useGlobalPipes(
      new ValidationPipe({
        whitelist: true,
        transform: true,
      }),
    )
    .setGlobalPrefix(APP_ROUTE_PREFIX)
    .enableCors({
      credentials: true,
      origin: true,
    });

  const config = new DocumentBuilder()
    .setTitle('Boilerplate API')
    .addBearerAuth()
    .build();
  const documentFactory = () => SwaggerModule.createDocument(app, config);
  SwaggerModule.setup(
    `${APP_ROUTE_PREFIX}/:version/docs`,
    app,
    documentFactory,
    {
      jsonDocumentUrl: 'swagger/json',
    },
  );

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
