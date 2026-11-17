import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  // ruleid: nestjs-validation-pipe-without-whitelist
  app.useGlobalPipes(new ValidationPipe({ transform: true }));
  // ruleid: nestjs-cors-credentials-any-origin
  app.enableCors({ origin: true, credentials: true });
  const config = new DocumentBuilder().setTitle('api').build();
  const document = SwaggerModule.createDocument(app, config);
  // ruleid: nestjs-swagger-unconditional
  SwaggerModule.setup('docs', app, document);
  await app.listen(3000);
}
bootstrap();
