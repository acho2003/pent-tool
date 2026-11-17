import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    // ruleid: nestjs-typeorm-synchronize-enabled
    TypeOrmModule.forRoot({ type: 'postgres', url: process.env.DATABASE_URL, synchronize: true }),
    // ruleid: nestjs-jwt-hardcoded-secret
    JwtModule.register({ secret: 'dev-signing-secret', signOptions: { expiresIn: '1h' } }),
  ],
})
export class AppModule {}
