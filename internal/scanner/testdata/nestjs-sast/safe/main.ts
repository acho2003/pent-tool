import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { SwaggerModule } from '@nestjs/swagger';
import { JwtModule } from '@nestjs/jwt';
import { TypeOrmModule } from '@nestjs/typeorm';

async function bootstrap(AppModule: any, document: any, config: any) {
  const app = await NestFactory.create(AppModule);
  // ok: nestjs-validation-pipe-without-whitelist
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
  // ok: nestjs-cors-credentials-any-origin
  app.enableCors({ origin: ['https://app.example.test'], credentials: true });
  // ok: nestjs-cors-credentials-any-origin
  app.enableCors({ origin: true });
  if (process.env.NODE_ENV !== 'production') {
    // ok: nestjs-swagger-unconditional
    SwaggerModule.setup('docs', app, document);
  }
  return [
    // ok: nestjs-typeorm-synchronize-enabled
    TypeOrmModule.forRoot({ type: 'postgres', synchronize: false }),
    // ok: nestjs-jwt-hardcoded-secret
    JwtModule.register({ secret: process.env.JWT_SECRET }),
    // ok: nestjs-jwt-ignore-expiration
    { ignoreExpiration: false, secretOrKey: config.get('JWT_SECRET') },
  ];
}
